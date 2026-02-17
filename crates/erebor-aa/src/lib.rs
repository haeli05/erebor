pub mod bundler;
pub mod paymaster;
pub mod wallet;

use std::sync::Arc;

use crate::bundler::{Bundler, UserOperation, BundlerError};
use crate::paymaster::{Paymaster, PaymasterError};
use crate::wallet::{SessionKeyManager, AccountFactory, WalletError};

/// Top-level Account Abstraction service tying bundler, paymaster, and wallet modules together.
pub struct AAService {
    pub bundler: Bundler,
    pub paymaster: Arc<dyn Paymaster>,
    pub session_keys: SessionKeyManager,
    pub account_factory: AccountFactory,
}

#[derive(Debug, thiserror::Error)]
pub enum AAError {
    #[error("bundler error: {0}")]
    Bundler(#[from] BundlerError),
    #[error("paymaster error: {0}")]
    Paymaster(#[from] PaymasterError),
    #[error("wallet error: {0}")]
    Wallet(#[from] WalletError),
}

impl AAService {
    pub fn new(
        bundler: Bundler,
        paymaster: Arc<dyn Paymaster>,
        account_factory: AccountFactory,
    ) -> Self {
        Self {
            bundler,
            paymaster,
            session_keys: SessionKeyManager::new(),
            account_factory,
        }
    }

    /// Submit a UserOp: validate via paymaster, then add to bundler mempool.
    pub fn submit_user_op(
        &self,
        op: UserOperation,
        expected_min_nonce: u64,
    ) -> Result<[u8; 32], AAError> {
        let max_cost = op.max_cost();
        // Validate with paymaster if paymaster_and_data is present
        if !op.paymaster_and_data.is_empty() {
            self.paymaster
                .validate_paymaster_user_op(&op, max_cost)?;
        }
        let hash = self.bundler.submit_op(op, expected_min_nonce)?;
        Ok(hash)
    }

    /// Create a bundle from pending ops.
    pub fn create_bundle(&self) -> bundler::Bundle {
        self.bundler.create_bundle()
    }

    /// Compute a counterfactual account address.
    pub fn compute_account_address(&self, owner: &[u8; 20], salt: u64) -> [u8; 20] {
        self.account_factory.compute_address(owner, salt)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::paymaster::VerifyingPaymaster;

    #[test]
    fn test_aa_service_submit_and_bundle() {
        let bundler = Bundler::new([0xEE; 20], 1, 10, 10_000_000);
        let pm = Arc::new(VerifyingPaymaster::new([0xBB; 32], 10u128.pow(18)));
        let factory = AccountFactory::new([0xAA; 20], [0xBB; 20]);
        let service = AAService::new(bundler, pm, factory);

        let op = UserOperation {
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
        };

        let hash = service.submit_user_op(op, 0).unwrap();
        assert!(!hash.iter().all(|&b| b == 0));

        let bundle = service.create_bundle();
        assert_eq!(bundle.ops.len(), 1);
    }

    #[test]
    fn test_aa_service_no_paymaster() {
        let bundler = Bundler::new([0xEE; 20], 1, 10, 10_000_000);
        let pm = Arc::new(VerifyingPaymaster::new([0xBB; 32], 10u128.pow(18)));
        let factory = AccountFactory::new([0xAA; 20], [0xBB; 20]);
        let service = AAService::new(bundler, pm, factory);

        let op = UserOperation {
            sender: [1u8; 20],
            nonce: 0,
            init_code: vec![],
            call_data: vec![0xde, 0xad],
            call_gas_limit: 100_000,
            verification_gas_limit: 50_000,
            pre_verification_gas: 21_000,
            max_fee_per_gas: 30_000_000_000,
            max_priority_fee_per_gas: 1_500_000_000,
            paymaster_and_data: vec![], // no paymaster
            signature: vec![0x01; 65],
        };

        assert!(service.submit_user_op(op, 0).is_ok());
    }

    #[test]
    fn test_compute_account_address() {
        let bundler = Bundler::new([0xEE; 20], 1, 10, 10_000_000);
        let pm = Arc::new(VerifyingPaymaster::new([0xBB; 32], 10u128.pow(18)));
        let factory = AccountFactory::new([0xAA; 20], [0xBB; 20]);
        let service = AAService::new(bundler, pm, factory);

        let addr = service.compute_account_address(&[1u8; 20], 0);
        assert_eq!(addr, service.account_factory.compute_address(&[1u8; 20], 0));
    }
}
