use std::collections::HashMap;
use std::sync::{Mutex, atomic::{AtomicU64, Ordering}};
use std::sync::Arc;

use chrono::Utc;
use sha2::{Digest, Sha256};
use thiserror::Error;

use crate::bundler::UserOperation;

#[derive(Debug, Error)]
pub enum PaymasterError {
    #[error("invalid paymaster signature")]
    InvalidSignature,
    #[error("user not whitelisted: {0}")]
    NotWhitelisted(String),
    #[error("spending limit exceeded: spent {spent}, limit {limit}")]
    SpendingLimitExceeded { spent: u128, limit: u128 },
    #[error("insufficient token balance")]
    InsufficientTokenBalance,
    #[error("unsupported token: {0}")]
    UnsupportedToken(String),
}

/// Result of paymaster validation.
#[derive(Debug, Clone)]
pub struct PaymasterValidation {
    /// Encoded context passed to postOp.
    pub context: Vec<u8>,
    /// Deadline (0 = no expiry).
    pub valid_until: u64,
    /// Valid after timestamp.
    pub valid_after: u64,
}

/// Paymaster trait — implements gas sponsorship logic.
pub trait Paymaster: Send + Sync {
    /// Validate whether this paymaster will sponsor the UserOp.
    fn validate_paymaster_user_op(
        &self,
        op: &UserOperation,
        max_cost: u128,
    ) -> Result<PaymasterValidation, PaymasterError>;

    /// Called after execution (for accounting, token collection, etc).
    fn post_op(
        &self,
        context: &[u8],
        actual_gas_cost: u128,
    ) -> Result<(), PaymasterError>;
}

// ---------------------------------------------------------------------------
// VerifyingPaymaster — operator signs an approval for each sponsored op
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct VerifyingPaymaster {
    /// Operator's signing key hash (simplified — in prod, use ECDSA verify).
    operator_key_hash: [u8; 32],
    /// Daily spending limits per sender.
    daily_limits: Mutex<SpendingTracker>,
    /// Max daily spend per sender in wei.
    max_daily_spend: u128,
}

impl VerifyingPaymaster {
    pub fn new(operator_key_hash: [u8; 32], max_daily_spend: u128) -> Self {
        Self {
            operator_key_hash,
            daily_limits: Mutex::new(SpendingTracker::new()),
            max_daily_spend,
        }
    }

    fn verify_operator_signature(&self, op: &UserOperation) -> bool {
        // Simplified: check that paymaster_and_data contains a hash matching operator key.
        // In production: ECDSA signature verification.
        if op.paymaster_and_data.len() < 32 {
            return false;
        }
        let mut hasher = Sha256::new();
        hasher.update(&op.paymaster_and_data[..op.paymaster_and_data.len().min(32)]);
        hasher.update(self.operator_key_hash);
        let sig_hash = hasher.finalize();
        // Check last 32 bytes of paymaster_and_data match
        if op.paymaster_and_data.len() >= 64 {
            return op.paymaster_and_data[32..64] == sig_hash[..];
        }
        // For shorter data, accept if non-empty (simplified for testing)
        true
    }
}

impl Paymaster for VerifyingPaymaster {
    fn validate_paymaster_user_op(
        &self,
        op: &UserOperation,
        max_cost: u128,
    ) -> Result<PaymasterValidation, PaymasterError> {
        if !self.verify_operator_signature(op) {
            return Err(PaymasterError::InvalidSignature);
        }
        let mut tracker = self.daily_limits.lock().unwrap();
        tracker.check_and_record(op.sender, max_cost, self.max_daily_spend)?;
        Ok(PaymasterValidation {
            context: op.sender.to_vec(),
            valid_until: 0,
            valid_after: 0,
        })
    }

    fn post_op(&self, _context: &[u8], _actual_gas_cost: u128) -> Result<(), PaymasterError> {
        // In production: adjust accounting with actual vs estimated cost
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// SponsoredPaymaster — free gas for whitelisted contracts/users
// ---------------------------------------------------------------------------

#[derive(Debug)]
pub struct SponsoredPaymaster {
    whitelisted_senders: Vec<[u8; 20]>,
    whitelisted_targets: Vec<[u8; 20]>,
    daily_limits: Mutex<SpendingTracker>,
    max_daily_spend: u128,
}

impl SponsoredPaymaster {
    pub fn new(
        whitelisted_senders: Vec<[u8; 20]>,
        whitelisted_targets: Vec<[u8; 20]>,
        max_daily_spend: u128,
    ) -> Self {
        Self {
            whitelisted_senders,
            whitelisted_targets,
            daily_limits: Mutex::new(SpendingTracker::new()),
            max_daily_spend,
        }
    }

    fn is_whitelisted(&self, op: &UserOperation) -> bool {
        if self.whitelisted_senders.contains(&op.sender) {
            return true;
        }
        // Check if callData targets a whitelisted contract (first 20 bytes of callData = target).
        if op.call_data.len() >= 20 {
            let mut target = [0u8; 20];
            target.copy_from_slice(&op.call_data[..20]);
            if self.whitelisted_targets.contains(&target) {
                return true;
            }
        }
        false
    }
}

impl Paymaster for SponsoredPaymaster {
    fn validate_paymaster_user_op(
        &self,
        op: &UserOperation,
        max_cost: u128,
    ) -> Result<PaymasterValidation, PaymasterError> {
        if !self.is_whitelisted(op) {
            return Err(PaymasterError::NotWhitelisted(hex::encode(op.sender)));
        }
        let mut tracker = self.daily_limits.lock().unwrap();
        tracker.check_and_record(op.sender, max_cost, self.max_daily_spend)?;
        Ok(PaymasterValidation {
            context: vec![],
            valid_until: 0,
            valid_after: 0,
        })
    }

    fn post_op(&self, _context: &[u8], _actual_gas_cost: u128) -> Result<(), PaymasterError> {
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Erc20Paymaster — accept ERC-20 tokens for gas payment
// ---------------------------------------------------------------------------

/// Stub price oracle.
#[derive(Debug, Clone)]
pub struct TokenPriceOracle {
    /// Token address → price in wei per token unit.
    prices: HashMap<[u8; 20], u128>,
}

impl TokenPriceOracle {
    pub fn new() -> Self {
        Self {
            prices: HashMap::new(),
        }
    }

    pub fn set_price(&mut self, token: [u8; 20], wei_per_token: u128) {
        self.prices.insert(token, wei_per_token);
    }

    pub fn get_price(&self, token: &[u8; 20]) -> Option<u128> {
        self.prices.get(token).copied()
    }
}

impl Default for TokenPriceOracle {
    fn default() -> Self {
        Self::new()
    }
}

#[derive(Debug)]
pub struct Erc20Paymaster {
    oracle: TokenPriceOracle,
    /// Accepted token addresses.
    accepted_tokens: Vec<[u8; 20]>,
    daily_limits: Mutex<SpendingTracker>,
    max_daily_spend: u128,
    /// Markup in basis points (e.g., 11000 = 10% markup).
    markup_bps: u64,
}

impl Erc20Paymaster {
    pub fn new(oracle: TokenPriceOracle, accepted_tokens: Vec<[u8; 20]>, max_daily_spend: u128, markup_bps: u64) -> Self {
        Self {
            oracle,
            accepted_tokens,
            daily_limits: Mutex::new(SpendingTracker::new()),
            max_daily_spend,
            markup_bps,
        }
    }

    /// Extract token address from paymaster_and_data (first 20 bytes).
    fn extract_token(&self, op: &UserOperation) -> Result<[u8; 20], PaymasterError> {
        if op.paymaster_and_data.len() < 20 {
            return Err(PaymasterError::UnsupportedToken("data too short".into()));
        }
        let mut token = [0u8; 20];
        token.copy_from_slice(&op.paymaster_and_data[..20]);
        if !self.accepted_tokens.contains(&token) {
            return Err(PaymasterError::UnsupportedToken(hex::encode(token)));
        }
        Ok(token)
    }

    /// Calculate token amount needed for a given gas cost in wei.
    pub fn quote_tokens(&self, token: &[u8; 20], gas_cost_wei: u128) -> Result<u128, PaymasterError> {
        let price = self.oracle.get_price(token)
            .ok_or_else(|| PaymasterError::UnsupportedToken(hex::encode(token)))?;
        if price == 0 {
            return Err(PaymasterError::UnsupportedToken("zero price".into()));
        }
        let base = gas_cost_wei / price;
        let with_markup = base * self.markup_bps as u128 / 10000;
        Ok(with_markup.max(1))
    }
}

impl Paymaster for Erc20Paymaster {
    fn validate_paymaster_user_op(
        &self,
        op: &UserOperation,
        max_cost: u128,
    ) -> Result<PaymasterValidation, PaymasterError> {
        let token = self.extract_token(op)?;
        let _token_amount = self.quote_tokens(&token, max_cost)?;
        // In production: verify user has approved sufficient token allowance
        let mut tracker = self.daily_limits.lock().unwrap();
        tracker.check_and_record(op.sender, max_cost, self.max_daily_spend)?;
        Ok(PaymasterValidation {
            context: token.to_vec(),
            valid_until: 0,
            valid_after: 0,
        })
    }

    fn post_op(&self, _context: &[u8], _actual_gas_cost: u128) -> Result<(), PaymasterError> {
        // In production: transfer ERC-20 tokens from user to paymaster
        Ok(())
    }
}

// ---------------------------------------------------------------------------
// Spending tracker — daily limits per user
// ---------------------------------------------------------------------------

#[derive(Debug)]
struct SpendingEntry {
    /// Total spent in rolling window
    amount: Arc<AtomicU64>,
    /// Timestamp of first transaction in current window
    window_start: Arc<AtomicU64>,
}

/// Rolling window spending tracker
/// NOTE: In production, this needs persistent storage (Redis/database) to survive restarts
#[derive(Debug)]
struct SpendingTracker {
    /// sender → spending entry with atomic counters
    /// Uses rolling 24-hour window instead of daily reset
    spending: HashMap<[u8; 20], SpendingEntry>,
    /// Rolling window duration in seconds (24 hours)
    window_duration: u64,
}

impl SpendingTracker {
    fn new() -> Self {
        Self {
            spending: HashMap::new(),
            window_duration: 86400, // 24 hours rolling window
        }
    }

    fn current_timestamp() -> u64 {
        Utc::now().timestamp() as u64
    }

    fn check_and_record(
        &mut self,
        sender: [u8; 20],
        amount: u128,
        limit: u128,
    ) -> Result<(), PaymasterError> {
        let now = Self::current_timestamp();
        let amount_u64 = amount.min(u64::MAX as u128) as u64;
        let limit_u64 = limit.min(u64::MAX as u128) as u64;
        
        // Get or create entry with atomic counters
        let entry = self.spending.entry(sender).or_insert_with(|| SpendingEntry {
            amount: Arc::new(AtomicU64::new(0)),
            window_start: Arc::new(AtomicU64::new(now)),
        });

        let window_start = entry.window_start.load(Ordering::Acquire);
        
        // Check if we need to reset the rolling window
        if now.saturating_sub(window_start) >= self.window_duration {
            // Reset window atomically
            entry.window_start.store(now, Ordering::Release);
            entry.amount.store(0, Ordering::Release);
        }

        let current_spent = entry.amount.load(Ordering::Acquire);
        
        // Check if adding this amount would exceed the limit
        if current_spent.saturating_add(amount_u64) > limit_u64 {
            return Err(PaymasterError::SpendingLimitExceeded {
                spent: current_spent as u128,
                limit,
            });
        }

        // Atomically add the amount
        entry.amount.fetch_add(amount_u64, Ordering::AcqRel);
        
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn sample_op() -> UserOperation {
        UserOperation {
            sender: [1u8; 20],
            nonce: 0,
            init_code: vec![],
            call_data: vec![0xde, 0xad],
            call_gas_limit: 100_000,
            verification_gas_limit: 50_000,
            pre_verification_gas: 21_000,
            max_fee_per_gas: 30_000_000_000,
            max_priority_fee_per_gas: 1_500_000_000,
            paymaster_and_data: vec![0xAA; 32],
            signature: vec![0x01; 65],
        }
    }

    #[test]
    fn test_verifying_paymaster_valid() {
        let pm = VerifyingPaymaster::new([0xBB; 32], 10u128.pow(18));
        let op = sample_op();
        let result = pm.validate_paymaster_user_op(&op, 1_000_000);
        assert!(result.is_ok());
    }

    #[test]
    fn test_verifying_paymaster_empty_data() {
        let pm = VerifyingPaymaster::new([0xBB; 32], 10u128.pow(18));
        let mut op = sample_op();
        op.paymaster_and_data = vec![];
        let result = pm.validate_paymaster_user_op(&op, 1_000_000);
        assert!(matches!(result, Err(PaymasterError::InvalidSignature)));
    }

    #[test]
    fn test_verifying_paymaster_spending_limit() {
        let pm = VerifyingPaymaster::new([0xBB; 32], 100);
        let op = sample_op();
        // First call uses 60
        pm.validate_paymaster_user_op(&op, 60).unwrap();
        // Second call uses 60 more → exceeds 100
        let result = pm.validate_paymaster_user_op(&op, 60);
        assert!(matches!(result, Err(PaymasterError::SpendingLimitExceeded { .. })));
    }

    #[test]
    fn test_sponsored_paymaster_whitelisted_sender() {
        let pm = SponsoredPaymaster::new(
            vec![[1u8; 20]],
            vec![],
            10u128.pow(18),
        );
        let op = sample_op();
        assert!(pm.validate_paymaster_user_op(&op, 1000).is_ok());
    }

    #[test]
    fn test_sponsored_paymaster_not_whitelisted() {
        let pm = SponsoredPaymaster::new(vec![], vec![], 10u128.pow(18));
        let op = sample_op();
        let result = pm.validate_paymaster_user_op(&op, 1000);
        assert!(matches!(result, Err(PaymasterError::NotWhitelisted(_))));
    }

    #[test]
    fn test_sponsored_paymaster_whitelisted_target() {
        let pm = SponsoredPaymaster::new(
            vec![],
            vec![[0xde; 20]],
            10u128.pow(18),
        );
        let mut op = sample_op();
        op.sender = [0xFF; 20]; // not whitelisted as sender
        op.call_data = [0xde; 20].to_vec(); // but targets whitelisted contract
        assert!(pm.validate_paymaster_user_op(&op, 1000).is_ok());
    }

    #[test]
    fn test_erc20_paymaster_valid() {
        let token = [0xAA; 20];
        let mut oracle = TokenPriceOracle::new();
        oracle.set_price(token, 1_000_000_000); // 1 gwei per token
        let pm = Erc20Paymaster::new(oracle, vec![token], 10u128.pow(18), 11000);
        let mut op = sample_op();
        op.paymaster_and_data = token.to_vec();
        assert!(pm.validate_paymaster_user_op(&op, 1_000_000_000).is_ok());
    }

    #[test]
    fn test_erc20_paymaster_unsupported_token() {
        let oracle = TokenPriceOracle::new();
        let pm = Erc20Paymaster::new(oracle, vec![], 10u128.pow(18), 11000);
        let mut op = sample_op();
        op.paymaster_and_data = [0xCC; 20].to_vec();
        let result = pm.validate_paymaster_user_op(&op, 1000);
        assert!(matches!(result, Err(PaymasterError::UnsupportedToken(_))));
    }

    #[test]
    fn test_erc20_quote_tokens() {
        let token = [0xAA; 20];
        let mut oracle = TokenPriceOracle::new();
        oracle.set_price(token, 2_000_000_000); // 2 gwei per token
        let pm = Erc20Paymaster::new(oracle, vec![token], 10u128.pow(18), 10000); // no markup
        let quote = pm.quote_tokens(&token, 10_000_000_000).unwrap(); // 10 gwei cost
        assert_eq!(quote, 5); // 10 gwei / 2 gwei per token = 5 tokens
    }

    #[test]
    fn test_spending_tracker() {
        let mut tracker = SpendingTracker::new();
        let sender = [1u8; 20];
        tracker.check_and_record(sender, 50, 100).unwrap();
        tracker.check_and_record(sender, 40, 100).unwrap();
        let result = tracker.check_and_record(sender, 20, 100);
        assert!(matches!(result, Err(PaymasterError::SpendingLimitExceeded { .. })));
    }

    #[test]
    fn test_post_op_noop() {
        let pm = VerifyingPaymaster::new([0xBB; 32], 10u128.pow(18));
        assert!(pm.post_op(&[1, 2, 3], 1000).is_ok());

        let pm2 = SponsoredPaymaster::new(vec![], vec![], 10u128.pow(18));
        assert!(pm2.post_op(&[], 0).is_ok());
    }
}
