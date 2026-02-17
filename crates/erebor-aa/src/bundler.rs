use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use std::sync::atomic::{AtomicUsize, Ordering};
use std::time::{Duration, Instant};

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;

/// ERC-4337 UserOperation matching the spec.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UserOperation {
    pub sender: [u8; 20],
    pub nonce: u64,
    pub init_code: Vec<u8>,
    pub call_data: Vec<u8>,
    pub call_gas_limit: u64,
    pub verification_gas_limit: u64,
    pub pre_verification_gas: u64,
    pub max_fee_per_gas: u128,
    pub max_priority_fee_per_gas: u128,
    pub paymaster_and_data: Vec<u8>,
    pub signature: Vec<u8>,
}

impl UserOperation {
    /// Compute a hash of the UserOperation (simplified — real impl uses abi.encode + keccak).
    pub fn hash(&self, entry_point: &[u8; 20], chain_id: u64) -> [u8; 32] {
        let mut hasher = Sha256::new();
        hasher.update(self.sender);
        hasher.update(self.nonce.to_be_bytes());
        hasher.update(&self.init_code);
        hasher.update(&self.call_data);
        hasher.update(self.call_gas_limit.to_be_bytes());
        hasher.update(self.verification_gas_limit.to_be_bytes());
        hasher.update(self.pre_verification_gas.to_be_bytes());
        hasher.update(self.max_fee_per_gas.to_be_bytes());
        hasher.update(self.max_priority_fee_per_gas.to_be_bytes());
        hasher.update(&self.paymaster_and_data);
        hasher.update(entry_point);
        hasher.update(chain_id.to_be_bytes());
        let result = hasher.finalize();
        let mut out = [0u8; 32];
        out.copy_from_slice(&result);
        out
    }

    /// Total gas this op can consume.
    pub fn total_gas(&self) -> u64 {
        self.call_gas_limit
            .saturating_add(self.verification_gas_limit)
            .saturating_add(self.pre_verification_gas)
    }

    /// Maximum cost in wei.
    pub fn max_cost(&self) -> u128 {
        self.total_gas() as u128 * self.max_fee_per_gas
    }
}

#[derive(Debug, Error)]
pub enum BundlerError {
    #[error("invalid signature")]
    InvalidSignature,
    #[error("nonce too low: expected >= {expected}, got {got}")]
    NonceTooLow { expected: u64, got: u64 },
    #[error("gas limit exceeded: {0} > max {1}")]
    GasLimitExceeded(u64, u64),
    #[error("mempool full")]
    MempoolFull,
    #[error("user op not found")]
    NotFound,
    #[error("bundle submission failed: {0}")]
    SubmissionFailed(String),
    #[error("gas price too high: {price}, max allowed: {max}")]
    GasPriceTooHigh { price: u128, max: u128 },
    #[error("sender rate limited")]
    SenderRateLimited,
}

/// Per-sender rate limiting for gas griefing protection
#[derive(Debug)]
struct SenderRateLimit {
    /// Number of ops submitted in current window
    count: u32,
    /// Window start time
    window_start: Instant,
}

/// Rate limiter for UserOp submissions per sender
#[derive(Debug)]
pub struct UserOpRateLimiter {
    /// sender -> rate limit entry
    limits: Arc<Mutex<HashMap<[u8; 20], SenderRateLimit>>>,
    /// Max ops per sender per window
    max_ops_per_window: u32,
    /// Rate limit window duration
    window_duration: Duration,
}

impl UserOpRateLimiter {
    pub fn new(max_ops_per_window: u32, window_duration: Duration) -> Self {
        Self {
            limits: Arc::new(Mutex::new(HashMap::new())),
            max_ops_per_window,
            window_duration,
        }
    }

    pub fn check_rate_limit(&self, sender: [u8; 20]) -> Result<(), BundlerError> {
        let mut limits = self.limits.lock().unwrap();
        let now = Instant::now();
        
        let entry = limits.entry(sender).or_insert(SenderRateLimit {
            count: 0,
            window_start: now,
        });

        // Reset window if expired
        if now.duration_since(entry.window_start) >= self.window_duration {
            entry.count = 0;
            entry.window_start = now;
        }

        // Check limit
        if entry.count >= self.max_ops_per_window {
            return Err(BundlerError::SenderRateLimited);
        }

        entry.count += 1;
        Ok(())
    }
}

/// Validates a UserOperation with gas griefing protection.
pub fn validate_user_op(
    op: &UserOperation,
    expected_min_nonce: u64,
    max_gas_limit: u64,
    rate_limiter: Option<&UserOpRateLimiter>,
) -> Result<(), BundlerError> {
    // Maximum gas limit per UserOp (10M gas to prevent griefing)
    const MAX_TOTAL_GAS: u64 = 10_000_000;
    
    if op.nonce < expected_min_nonce {
        return Err(BundlerError::NonceTooLow {
            expected: expected_min_nonce,
            got: op.nonce,
        });
    }

    let total = op.total_gas();
    
    // Enforce absolute maximum gas limit
    if total > MAX_TOTAL_GAS {
        return Err(BundlerError::GasLimitExceeded(total, MAX_TOTAL_GAS));
    }
    
    // Enforce configurable gas limit
    if total > max_gas_limit {
        return Err(BundlerError::GasLimitExceeded(total, max_gas_limit));
    }

    // Validate gas price is reasonable (max 1000 gwei to prevent griefing)
    const MAX_GAS_PRICE: u128 = 1000 * 1_000_000_000; // 1000 gwei
    if op.max_fee_per_gas > MAX_GAS_PRICE {
        return Err(BundlerError::GasPriceTooHigh { 
            price: op.max_fee_per_gas, 
            max: MAX_GAS_PRICE 
        });
    }

    // Per-sender rate limiting
    if let Some(limiter) = rate_limiter {
        limiter.check_rate_limit(op.sender)?;
    }

    if op.signature.is_empty() {
        return Err(BundlerError::InvalidSignature);
    }
    
    Ok(())
}

/// In-memory mempool for pending UserOperations.
#[derive(Debug)]
pub struct UserOpMempool {
    ops: Mutex<HashMap<[u8; 32], UserOperation>>,
    max_size: usize,
    /// Maximum memory usage in bytes (default 64MB)
    max_memory_bytes: usize,
    /// Current memory usage tracking
    current_memory_bytes: Arc<std::sync::atomic::AtomicUsize>,
    entry_point: [u8; 20],
    chain_id: u64,
    rate_limiter: UserOpRateLimiter,
}

impl UserOpMempool {
    pub fn new(entry_point: [u8; 20], chain_id: u64, max_size: usize) -> Self {
        Self {
            ops: Mutex::new(HashMap::new()),
            max_size,
            max_memory_bytes: 64 * 1024 * 1024, // 64MB default limit
            current_memory_bytes: Arc::new(AtomicUsize::new(0)),
            entry_point,
            chain_id,
            // Default: 10 ops per sender per 5 minutes
            rate_limiter: UserOpRateLimiter::new(10, Duration::from_secs(300)),
        }
    }

    /// Estimate the memory size of a UserOperation
    fn estimate_op_size(op: &UserOperation) -> usize {
        // Estimate based on variable-length fields
        std::mem::size_of::<UserOperation>()
            + op.init_code.len()
            + op.call_data.len()
            + op.paymaster_and_data.len()
            + op.signature.len()
    }

    /// Add a UserOp. Returns its hash.
    pub fn add(&self, op: UserOperation) -> Result<[u8; 32], BundlerError> {
        let hash = op.hash(&self.entry_point, self.chain_id);
        let op_size = Self::estimate_op_size(&op);
        
        let mut ops = self.ops.lock().unwrap();
        
        // Check count-based limit
        if ops.len() >= self.max_size {
            return Err(BundlerError::MempoolFull);
        }
        
        // Check memory-based limit
        let current_memory = self.current_memory_bytes.load(Ordering::Acquire);
        if current_memory + op_size > self.max_memory_bytes {
            return Err(BundlerError::MempoolFull);
        }
        
        ops.insert(hash, op);
        self.current_memory_bytes.fetch_add(op_size, Ordering::AcqRel);
        Ok(hash)
    }

    /// Remove a UserOp by hash.
    pub fn remove(&self, hash: &[u8; 32]) -> Result<UserOperation, BundlerError> {
        let mut ops = self.ops.lock().unwrap();
        let op = ops.remove(hash).ok_or(BundlerError::NotFound)?;
        
        // Update memory tracking
        let op_size = Self::estimate_op_size(&op);
        self.current_memory_bytes.fetch_sub(op_size, Ordering::AcqRel);
        
        Ok(op)
    }

    /// Get a UserOp by hash.
    pub fn get(&self, hash: &[u8; 32]) -> Option<UserOperation> {
        self.ops.lock().unwrap().get(hash).cloned()
    }

    /// Drain up to `max` ops for bundling, sorted by max_fee_per_gas descending.
    pub fn drain_batch(&self, max: usize) -> Vec<UserOperation> {
        let mut ops = self.ops.lock().unwrap();
        let mut entries: Vec<_> = ops.drain().collect();
        entries.sort_by(|a, b| b.1.max_fee_per_gas.cmp(&a.1.max_fee_per_gas));
        entries.truncate(max);
        entries.into_iter().map(|(_, op)| op).collect()
    }

    pub fn len(&self) -> usize {
        self.ops.lock().unwrap().len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }
}

/// EIP-1559 fee estimation.
#[derive(Debug, Clone)]
pub struct FeeEstimate {
    pub base_fee: u128,
    pub priority_fee: u128,
    pub max_fee: u128,
}

/// Gas/fee estimator with safety margins.
#[derive(Debug, Clone)]
pub struct FeeEstimator {
    /// Multiplier for base fee (e.g., 1.5 = 150%). Stored as basis points (15000 = 1.5x).
    pub base_fee_margin_bps: u64,
    /// Default priority fee in wei.
    pub default_priority_fee: u128,
    /// Gas estimation margin in basis points.
    pub gas_margin_bps: u64,
}

impl Default for FeeEstimator {
    fn default() -> Self {
        Self {
            base_fee_margin_bps: 15000, // 1.5x
            default_priority_fee: 1_500_000_000, // 1.5 gwei
            gas_margin_bps: 12000, // 1.2x
        }
    }
}

impl FeeEstimator {
    pub fn new(base_fee_margin_bps: u64, default_priority_fee: u128, gas_margin_bps: u64) -> Self {
        Self {
            base_fee_margin_bps,
            default_priority_fee,
            gas_margin_bps,
        }
    }

    /// Estimate fees given a current base fee.
    pub fn estimate(&self, current_base_fee: u128) -> FeeEstimate {
        let adjusted_base = current_base_fee * self.base_fee_margin_bps as u128 / 10000;
        let max_fee = adjusted_base + self.default_priority_fee;
        FeeEstimate {
            base_fee: adjusted_base,
            priority_fee: self.default_priority_fee,
            max_fee,
        }
    }

    /// Apply gas margin to an estimated gas value.
    pub fn adjust_gas(&self, estimated_gas: u64) -> u64 {
        (estimated_gas as u128 * self.gas_margin_bps as u128 / 10000) as u64
    }
}

/// Bundler that batches UserOps and creates the bundle call to EntryPoint.
#[derive(Debug)]
pub struct Bundler {
    pub mempool: Arc<UserOpMempool>,
    pub fee_estimator: FeeEstimator,
    pub entry_point: [u8; 20],
    pub chain_id: u64,
    pub max_bundle_size: usize,
    pub max_gas_per_bundle: u64,
}

/// Represents a bundle ready for on-chain submission.
#[derive(Debug, Clone)]
pub struct Bundle {
    pub ops: Vec<UserOperation>,
    pub entry_point: [u8; 20],
    pub total_gas: u64,
}

impl Bundler {
    pub fn new(
        entry_point: [u8; 20],
        chain_id: u64,
        max_bundle_size: usize,
        max_gas_per_bundle: u64,
    ) -> Self {
        let mempool = Arc::new(UserOpMempool::new(entry_point, chain_id, 4096));
        Self {
            mempool,
            fee_estimator: FeeEstimator::default(),
            entry_point,
            chain_id,
            max_bundle_size,
            max_gas_per_bundle,
        }
    }

    /// Submit a UserOp to the mempool after validation.
    pub fn submit_op(
        &self,
        op: UserOperation,
        expected_min_nonce: u64,
    ) -> Result<[u8; 32], BundlerError> {
        validate_user_op(&op, expected_min_nonce, self.max_gas_per_bundle, Some(&self.mempool.rate_limiter))?;
        self.mempool.add(op)
    }

    /// Create a bundle from pending ops, respecting gas limits.
    pub fn create_bundle(&self) -> Bundle {
        let ops = self.mempool.drain_batch(self.max_bundle_size);
        let mut selected = Vec::new();
        let mut total_gas: u64 = 0;
        for op in ops {
            let gas = op.total_gas();
            if total_gas.saturating_add(gas) <= self.max_gas_per_bundle {
                total_gas += gas;
                selected.push(op);
            }
            // ops that don't fit are dropped (in production, re-add to mempool)
        }
        Bundle {
            ops: selected,
            entry_point: self.entry_point,
            total_gas,
        }
    }

    /// Encode the handleOps call data for the EntryPoint contract (stub).
    pub fn encode_handle_ops(bundle: &Bundle, beneficiary: [u8; 20]) -> Vec<u8> {
        // In production: abi.encodeWithSelector(IEntryPoint.handleOps.selector, ops, beneficiary)
        // Stub: return a placeholder encoding
        let mut data = vec![0x1f, 0xad, 0x94, 0x8c]; // handleOps selector stub
        data.extend_from_slice(&(bundle.ops.len() as u32).to_be_bytes());
        data.extend_from_slice(&beneficiary);
        data
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
            paymaster_and_data: vec![],
            signature: vec![0x01; 65],
        }
    }

    #[test]
    fn test_user_op_hash_deterministic() {
        let op = sample_op();
        let ep = [0xAAu8; 20];
        let h1 = op.hash(&ep, 1);
        let h2 = op.hash(&ep, 1);
        assert_eq!(h1, h2);

        let h3 = op.hash(&ep, 2);
        assert_ne!(h1, h3);
    }

    #[test]
    fn test_user_op_total_gas() {
        let op = sample_op();
        assert_eq!(op.total_gas(), 171_000);
    }

    #[test]
    fn test_user_op_max_cost() {
        let op = sample_op();
        assert_eq!(op.max_cost(), 171_000u128 * 30_000_000_000u128);
    }

    #[test]
    fn test_validate_user_op_ok() {
        let op = sample_op();
        assert!(validate_user_op(&op, 0, 1_000_000).is_ok());
    }

    #[test]
    fn test_validate_nonce_too_low() {
        let op = sample_op();
        let err = validate_user_op(&op, 5, 1_000_000).unwrap_err();
        assert!(matches!(err, BundlerError::NonceTooLow { expected: 5, got: 0 }));
    }

    #[test]
    fn test_validate_gas_exceeded() {
        let op = sample_op();
        let err = validate_user_op(&op, 0, 100).unwrap_err();
        assert!(matches!(err, BundlerError::GasLimitExceeded(_, _)));
    }

    #[test]
    fn test_validate_empty_signature() {
        let mut op = sample_op();
        op.signature = vec![];
        assert!(matches!(
            validate_user_op(&op, 0, 1_000_000),
            Err(BundlerError::InvalidSignature)
        ));
    }

    #[test]
    fn test_mempool_add_get_remove() {
        let pool = UserOpMempool::new([0xBB; 20], 1, 100);
        let op = sample_op();
        let hash = pool.add(op.clone()).unwrap();
        assert_eq!(pool.len(), 1);

        let retrieved = pool.get(&hash).unwrap();
        assert_eq!(retrieved.nonce, 0);

        let removed = pool.remove(&hash).unwrap();
        assert_eq!(removed.nonce, 0);
        assert!(pool.is_empty());
    }

    #[test]
    fn test_mempool_full() {
        let pool = UserOpMempool::new([0xBB; 20], 1, 1);
        pool.add(sample_op()).unwrap();
        let mut op2 = sample_op();
        op2.nonce = 1;
        assert!(matches!(pool.add(op2), Err(BundlerError::MempoolFull)));
    }

    #[test]
    fn test_mempool_drain_batch_sorted() {
        let pool = UserOpMempool::new([0xBB; 20], 1, 100);
        let mut op1 = sample_op();
        op1.max_fee_per_gas = 10;
        let mut op2 = sample_op();
        op2.nonce = 1;
        op2.max_fee_per_gas = 50;
        let mut op3 = sample_op();
        op3.nonce = 2;
        op3.max_fee_per_gas = 30;

        pool.add(op1).unwrap();
        pool.add(op2).unwrap();
        pool.add(op3).unwrap();

        let batch = pool.drain_batch(10);
        assert_eq!(batch.len(), 3);
        assert_eq!(batch[0].max_fee_per_gas, 50);
        assert_eq!(batch[1].max_fee_per_gas, 30);
        assert_eq!(batch[2].max_fee_per_gas, 10);
        assert!(pool.is_empty());
    }

    #[test]
    fn test_fee_estimator_default() {
        let est = FeeEstimator::default();
        let fee = est.estimate(20_000_000_000); // 20 gwei base
        // 20 gwei * 1.5 = 30 gwei adjusted base
        assert_eq!(fee.base_fee, 30_000_000_000);
        assert_eq!(fee.priority_fee, 1_500_000_000);
        assert_eq!(fee.max_fee, 31_500_000_000);
    }

    #[test]
    fn test_fee_estimator_adjust_gas() {
        let est = FeeEstimator::default();
        let adjusted = est.adjust_gas(100_000);
        assert_eq!(adjusted, 120_000); // 1.2x
    }

    #[test]
    fn test_bundler_submit_and_bundle() {
        let bundler = Bundler::new([0xCC; 20], 1, 10, 10_000_000);
        let op = sample_op();
        bundler.submit_op(op, 0).unwrap();
        assert_eq!(bundler.mempool.len(), 1);

        let bundle = bundler.create_bundle();
        assert_eq!(bundle.ops.len(), 1);
        assert!(bundler.mempool.is_empty());
    }

    #[test]
    fn test_bundler_gas_limit_in_bundle() {
        let bundler = Bundler::new([0xCC; 20], 1, 10, 200_000);
        // Each op uses 171k gas, so only 1 fits in 200k
        let op1 = sample_op();
        let mut op2 = sample_op();
        op2.nonce = 1;

        bundler.submit_op(op1, 0).unwrap();
        // op2 total gas is 171k which is < 200k, so it passes validation
        bundler.submit_op(op2, 0).unwrap();

        let bundle = bundler.create_bundle();
        assert_eq!(bundle.ops.len(), 1); // only 1 fits
    }

    #[test]
    fn test_encode_handle_ops() {
        let bundle = Bundle {
            ops: vec![sample_op()],
            entry_point: [0xCC; 20],
            total_gas: 171_000,
        };
        let data = Bundler::encode_handle_ops(&bundle, [0xDD; 20]);
        assert!(!data.is_empty());
        assert_eq!(&data[..4], &[0x1f, 0xad, 0x94, 0x8c]);
    }
}
