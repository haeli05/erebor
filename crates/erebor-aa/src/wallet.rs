use std::collections::HashMap;
use std::sync::Mutex;

use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use thiserror::Error;
use uuid::Uuid;

#[derive(Debug, Error)]
pub enum WalletError {
    #[error("account not found: {0}")]
    AccountNotFound(String),
    #[error("session key expired")]
    SessionKeyExpired,
    #[error("session key revoked")]
    SessionKeyRevoked,
    #[error("contract not allowed: {0}")]
    ContractNotAllowed(String),
    #[error("spending limit exceeded: spent {spent}, limit {limit}")]
    SpendingLimitExceeded { spent: u128, limit: u128 },
    #[error("invalid signature")]
    InvalidSignature,
    #[error("deployment failed: {0}")]
    DeploymentFailed(String),
}

/// Smart account interface.
pub trait SmartAccount: Send + Sync {
    /// Address of the smart account.
    fn address(&self) -> [u8; 20];

    /// Validate a user operation signature.
    fn validate_signature(&self, op_hash: &[u8; 32], signature: &[u8]) -> Result<(), WalletError>;

    /// Execute a call from the smart account (stub).
    fn execute(&self, target: [u8; 20], value: u128, data: &[u8]) -> Result<Vec<u8>, WalletError>;
}

/// A basic smart account implementation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct BasicSmartAccount {
    pub address: [u8; 20],
    pub owner: [u8; 20],
    pub nonce: u64,
}

impl SmartAccount for BasicSmartAccount {
    fn address(&self) -> [u8; 20] {
        self.address
    }

    fn validate_signature(&self, _op_hash: &[u8; 32], signature: &[u8]) -> Result<(), WalletError> {
        if signature.is_empty() {
            return Err(WalletError::InvalidSignature);
        }
        // Simplified: in production, recover signer from signature and compare to owner.
        Ok(())
    }

    fn execute(&self, _target: [u8; 20], _value: u128, _data: &[u8]) -> Result<Vec<u8>, WalletError> {
        // Stub: would forward call via the smart contract
        Ok(vec![])
    }
}

// ---------------------------------------------------------------------------
// AccountFactory — deterministic CREATE2 address computation
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct AccountFactory {
    pub factory_address: [u8; 20],
    pub implementation: [u8; 20],
}

impl AccountFactory {
    pub fn new(factory_address: [u8; 20], implementation: [u8; 20]) -> Self {
        Self {
            factory_address,
            implementation,
        }
    }

    /// Compute the CREATE2 address for a given owner and salt.
    /// CREATE2: keccak256(0xff ++ factory ++ salt ++ keccak256(init_code))
    /// We use SHA256 as a stand-in for keccak256.
    pub fn compute_address(&self, owner: &[u8; 20], salt: u64) -> [u8; 20] {
        // Compute init_code_hash
        let mut init_hasher = Sha256::new();
        init_hasher.update(self.implementation);
        init_hasher.update(owner);
        let init_code_hash = init_hasher.finalize();

        // Compute CREATE2
        let mut hasher = Sha256::new();
        hasher.update([0xff]);
        hasher.update(self.factory_address);
        hasher.update(salt.to_be_bytes());
        hasher.update(init_code_hash);
        let result = hasher.finalize();

        let mut addr = [0u8; 20];
        addr.copy_from_slice(&result[12..32]);
        addr
    }

    /// Generate init_code bytes for deploying a new account.
    pub fn encode_init_code(&self, owner: &[u8; 20], salt: u64) -> Vec<u8> {
        let mut init_code = Vec::with_capacity(48);
        init_code.extend_from_slice(&self.factory_address);
        // createAccount(owner, salt) selector stub
        init_code.extend_from_slice(&[0x5f, 0xbf, 0xb9, 0xcf]);
        init_code.extend_from_slice(&[0u8; 12]); // padding
        init_code.extend_from_slice(owner);
        init_code.extend_from_slice(&salt.to_be_bytes());
        init_code
    }

    /// Create a BasicSmartAccount with a deterministic address.
    pub fn create_account(&self, owner: [u8; 20], salt: u64) -> BasicSmartAccount {
        let address = self.compute_address(&owner, salt);
        BasicSmartAccount {
            address,
            owner,
            nonce: 0,
        }
    }
}

// ---------------------------------------------------------------------------
// Session Keys — delegated permissions
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionKey {
    pub id: Uuid,
    pub key: [u8; 20],
    pub permissions: SessionPermissions,
    pub valid_after: DateTime<Utc>,
    pub valid_until: DateTime<Utc>,
    pub revoked: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SessionPermissions {
    /// Contracts this session key can interact with (empty = any).
    pub allowed_contracts: Vec<[u8; 20]>,
    /// Max spend per transaction in wei.
    pub max_spend_per_tx: u128,
    /// Total spending limit for the session.
    pub total_spending_limit: u128,
    /// Amount spent so far.
    pub total_spent: u128,
}

impl SessionPermissions {
    pub fn new(
        allowed_contracts: Vec<[u8; 20]>,
        max_spend_per_tx: u128,
        total_spending_limit: u128,
    ) -> Self {
        Self {
            allowed_contracts,
            max_spend_per_tx,
            total_spending_limit,
            total_spent: 0,
        }
    }
}

/// Manages session keys for smart accounts.
#[derive(Debug)]
pub struct SessionKeyManager {
    sessions: Mutex<HashMap<Uuid, SessionKey>>,
    /// account address → list of session key IDs
    account_sessions: Mutex<HashMap<[u8; 20], Vec<Uuid>>>,
}

impl SessionKeyManager {
    pub fn new() -> Self {
        Self {
            sessions: Mutex::new(HashMap::new()),
            account_sessions: Mutex::new(HashMap::new()),
        }
    }

    /// Create a new session key for an account.
    pub fn create_session(
        &self,
        account: [u8; 20],
        key: [u8; 20],
        permissions: SessionPermissions,
        valid_after: DateTime<Utc>,
        valid_until: DateTime<Utc>,
    ) -> SessionKey {
        let session = SessionKey {
            id: Uuid::new_v4(),
            key,
            permissions,
            valid_after,
            valid_until,
            revoked: false,
        };
        let id = session.id;
        self.sessions.lock().unwrap().insert(id, session.clone());
        self.account_sessions
            .lock()
            .unwrap()
            .entry(account)
            .or_default()
            .push(id);
        session
    }

    /// Validate a session key for a specific operation.
    pub fn validate_session(
        &self,
        session_id: Uuid,
        target_contract: &[u8; 20],
        value: u128,
    ) -> Result<(), WalletError> {
        let sessions = self.sessions.lock().unwrap();
        let session = sessions
            .get(&session_id)
            .ok_or_else(|| WalletError::AccountNotFound(session_id.to_string()))?;

        if session.revoked {
            return Err(WalletError::SessionKeyRevoked);
        }

        let now = Utc::now();
        if now < session.valid_after || now > session.valid_until {
            return Err(WalletError::SessionKeyExpired);
        }

        let perms = &session.permissions;
        if !perms.allowed_contracts.is_empty()
            && !perms.allowed_contracts.contains(target_contract)
        {
            return Err(WalletError::ContractNotAllowed(hex::encode(target_contract)));
        }

        if value > perms.max_spend_per_tx {
            return Err(WalletError::SpendingLimitExceeded {
                spent: value,
                limit: perms.max_spend_per_tx,
            });
        }

        if perms.total_spent.saturating_add(value) > perms.total_spending_limit {
            return Err(WalletError::SpendingLimitExceeded {
                spent: perms.total_spent,
                limit: perms.total_spending_limit,
            });
        }

        Ok(())
    }

    /// Record spending against a session key.
    pub fn record_spend(&self, session_id: Uuid, amount: u128) -> Result<(), WalletError> {
        let mut sessions = self.sessions.lock().unwrap();
        let session = sessions
            .get_mut(&session_id)
            .ok_or_else(|| WalletError::AccountNotFound(session_id.to_string()))?;
        session.permissions.total_spent += amount;
        Ok(())
    }

    /// Revoke a session key.
    pub fn revoke_session(&self, session_id: Uuid) -> Result<(), WalletError> {
        let mut sessions = self.sessions.lock().unwrap();
        let session = sessions
            .get_mut(&session_id)
            .ok_or_else(|| WalletError::AccountNotFound(session_id.to_string()))?;
        session.revoked = true;
        Ok(())
    }

    /// Get all active session keys for an account.
    pub fn get_sessions(&self, account: &[u8; 20]) -> Vec<SessionKey> {
        let account_sessions = self.account_sessions.lock().unwrap();
        let sessions = self.sessions.lock().unwrap();
        account_sessions
            .get(account)
            .map(|ids| {
                ids.iter()
                    .filter_map(|id| sessions.get(id).cloned())
                    .filter(|s| !s.revoked)
                    .collect()
            })
            .unwrap_or_default()
    }
}

impl Default for SessionKeyManager {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// SpendingPolicy — configurable spending rules
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SpendingPolicy {
    pub max_per_tx: u128,
    pub max_daily: u128,
    pub allowed_contracts: Vec<[u8; 20]>,
    pub require_session_key: bool,
}

impl SpendingPolicy {
    pub fn new(max_per_tx: u128, max_daily: u128) -> Self {
        Self {
            max_per_tx,
            max_daily,
            allowed_contracts: vec![],
            require_session_key: false,
        }
    }

    pub fn validate_tx(&self, value: u128, target: &[u8; 20]) -> Result<(), WalletError> {
        if value > self.max_per_tx {
            return Err(WalletError::SpendingLimitExceeded {
                spent: value,
                limit: self.max_per_tx,
            });
        }
        if !self.allowed_contracts.is_empty() && !self.allowed_contracts.contains(target) {
            return Err(WalletError::ContractNotAllowed(hex::encode(target)));
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::Duration;

    #[test]
    fn test_account_factory_deterministic_address() {
        let factory = AccountFactory::new([0xAA; 20], [0xBB; 20]);
        let owner = [1u8; 20];
        let addr1 = factory.compute_address(&owner, 0);
        let addr2 = factory.compute_address(&owner, 0);
        assert_eq!(addr1, addr2);

        let addr3 = factory.compute_address(&owner, 1);
        assert_ne!(addr1, addr3);
    }

    #[test]
    fn test_account_factory_different_owners() {
        let factory = AccountFactory::new([0xAA; 20], [0xBB; 20]);
        let addr1 = factory.compute_address(&[1u8; 20], 0);
        let addr2 = factory.compute_address(&[2u8; 20], 0);
        assert_ne!(addr1, addr2);
    }

    #[test]
    fn test_account_factory_create_account() {
        let factory = AccountFactory::new([0xAA; 20], [0xBB; 20]);
        let account = factory.create_account([1u8; 20], 0);
        assert_eq!(account.owner, [1u8; 20]);
        assert_eq!(account.nonce, 0);
        assert_eq!(account.address, factory.compute_address(&[1u8; 20], 0));
    }

    #[test]
    fn test_encode_init_code() {
        let factory = AccountFactory::new([0xAA; 20], [0xBB; 20]);
        let init = factory.encode_init_code(&[1u8; 20], 42);
        assert!(init.len() > 20);
        assert_eq!(&init[..20], &[0xAA; 20]);
    }

    #[test]
    fn test_basic_smart_account_validate_signature() {
        let account = BasicSmartAccount {
            address: [1u8; 20],
            owner: [2u8; 20],
            nonce: 0,
        };
        let hash = [0u8; 32];
        assert!(account.validate_signature(&hash, &[1, 2, 3]).is_ok());
        assert!(matches!(
            account.validate_signature(&hash, &[]),
            Err(WalletError::InvalidSignature)
        ));
    }

    #[test]
    fn test_basic_smart_account_execute() {
        let account = BasicSmartAccount {
            address: [1u8; 20],
            owner: [2u8; 20],
            nonce: 0,
        };
        let result = account.execute([3u8; 20], 0, &[0xde, 0xad]);
        assert!(result.is_ok());
    }

    #[test]
    fn test_session_key_create_and_validate() {
        let mgr = SessionKeyManager::new();
        let account = [1u8; 20];
        let target = [0xCC; 20];

        let perms = SessionPermissions::new(vec![target], 1000, 5000);
        let now = Utc::now();
        let session = mgr.create_session(
            account,
            [0xDD; 20],
            perms,
            now - Duration::hours(1),
            now + Duration::hours(1),
        );

        assert!(mgr.validate_session(session.id, &target, 500).is_ok());
    }

    #[test]
    fn test_session_key_wrong_contract() {
        let mgr = SessionKeyManager::new();
        let account = [1u8; 20];
        let allowed = [0xCC; 20];
        let forbidden = [0xDD; 20];

        let perms = SessionPermissions::new(vec![allowed], 1000, 5000);
        let now = Utc::now();
        let session = mgr.create_session(
            account,
            [0xEE; 20],
            perms,
            now - Duration::hours(1),
            now + Duration::hours(1),
        );

        assert!(matches!(
            mgr.validate_session(session.id, &forbidden, 500),
            Err(WalletError::ContractNotAllowed(_))
        ));
    }

    #[test]
    fn test_session_key_spending_limit() {
        let mgr = SessionKeyManager::new();
        let account = [1u8; 20];
        let target = [0xCC; 20];

        let perms = SessionPermissions::new(vec![], 1000, 2000);
        let now = Utc::now();
        let session = mgr.create_session(
            account,
            [0xDD; 20],
            perms,
            now - Duration::hours(1),
            now + Duration::hours(1),
        );

        // Per-tx limit exceeded
        assert!(matches!(
            mgr.validate_session(session.id, &target, 1500),
            Err(WalletError::SpendingLimitExceeded { .. })
        ));

        // Within limits
        mgr.validate_session(session.id, &target, 800).unwrap();
        mgr.record_spend(session.id, 800).unwrap();
        mgr.validate_session(session.id, &target, 800).unwrap();
        mgr.record_spend(session.id, 800).unwrap();

        // Total limit exceeded
        assert!(matches!(
            mgr.validate_session(session.id, &target, 500),
            Err(WalletError::SpendingLimitExceeded { .. })
        ));
    }

    #[test]
    fn test_session_key_revoke() {
        let mgr = SessionKeyManager::new();
        let account = [1u8; 20];
        let target = [0xCC; 20];

        let perms = SessionPermissions::new(vec![], 1000, 5000);
        let now = Utc::now();
        let session = mgr.create_session(
            account,
            [0xDD; 20],
            perms,
            now - Duration::hours(1),
            now + Duration::hours(1),
        );

        mgr.revoke_session(session.id).unwrap();
        assert!(matches!(
            mgr.validate_session(session.id, &target, 100),
            Err(WalletError::SessionKeyRevoked)
        ));
    }

    #[test]
    fn test_session_key_expired() {
        let mgr = SessionKeyManager::new();
        let account = [1u8; 20];
        let target = [0xCC; 20];

        let perms = SessionPermissions::new(vec![], 1000, 5000);
        let now = Utc::now();
        // Already expired
        let session = mgr.create_session(
            account,
            [0xDD; 20],
            perms,
            now - Duration::hours(2),
            now - Duration::hours(1),
        );

        assert!(matches!(
            mgr.validate_session(session.id, &target, 100),
            Err(WalletError::SessionKeyExpired)
        ));
    }

    #[test]
    fn test_get_sessions() {
        let mgr = SessionKeyManager::new();
        let account = [1u8; 20];
        let now = Utc::now();

        let perms1 = SessionPermissions::new(vec![], 1000, 5000);
        let perms2 = SessionPermissions::new(vec![], 2000, 10000);

        let s1 = mgr.create_session(account, [0xAA; 20], perms1, now - Duration::hours(1), now + Duration::hours(1));
        let _s2 = mgr.create_session(account, [0xBB; 20], perms2, now - Duration::hours(1), now + Duration::hours(1));

        let sessions = mgr.get_sessions(&account);
        assert_eq!(sessions.len(), 2);

        mgr.revoke_session(s1.id).unwrap();
        let sessions = mgr.get_sessions(&account);
        assert_eq!(sessions.len(), 1);
    }

    #[test]
    fn test_spending_policy_valid() {
        let policy = SpendingPolicy::new(1000, 10000);
        assert!(policy.validate_tx(500, &[0xCC; 20]).is_ok());
    }

    #[test]
    fn test_spending_policy_exceeds_per_tx() {
        let policy = SpendingPolicy::new(1000, 10000);
        assert!(matches!(
            policy.validate_tx(1500, &[0xCC; 20]),
            Err(WalletError::SpendingLimitExceeded { .. })
        ));
    }

    #[test]
    fn test_spending_policy_contract_restriction() {
        let mut policy = SpendingPolicy::new(1000, 10000);
        policy.allowed_contracts = vec![[0xAA; 20]];
        assert!(policy.validate_tx(500, &[0xAA; 20]).is_ok());
        assert!(matches!(
            policy.validate_tx(500, &[0xBB; 20]),
            Err(WalletError::ContractNotAllowed(_))
        ));
    }
}
