use chrono::{DateTime, Utc};
use erebor_common::{EreborError, Result, UserId};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, Mutex};
use uuid::Uuid;

/// Metadata for a stored encrypted share
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct StoredShare {
    pub share_id: Uuid,
    pub user_id: UserId,
    pub share_index: u8,
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub rotated_at: Option<DateTime<Utc>>,
}

/// Audit log entry for key operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEntry {
    pub id: Uuid,
    pub user_id: UserId,
    pub operation: KeyOperation,
    pub timestamp: DateTime<Utc>,
    pub details: String,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum KeyOperation {
    CreateWallet,
    StoreShare,
    RetrieveShare,
    RotateShares,
    SignTransaction,
    ExportRecoveryShare,
    DeleteShares,
}

/// Pluggable backend for encrypted share storage
#[allow(async_fn_in_trait)]
pub trait ShareStore: Send + Sync {
    /// Store a share (insert or update)
    async fn store_share(&self, share: StoredShare) -> Result<()>;

    /// Get all shares for a user
    async fn get_shares(&self, user_id: &UserId) -> Result<Vec<StoredShare>>;

    /// Get a specific share by user + index
    async fn get_share(&self, user_id: &UserId, index: u8) -> Result<Option<StoredShare>>;

    /// Replace all shares for a user atomically (for rotation)
    async fn replace_shares(&self, user_id: &UserId, shares: Vec<StoredShare>) -> Result<()>;

    /// Delete all shares for a user
    async fn delete_shares(&self, user_id: &UserId) -> Result<()>;

    /// Append an audit log entry
    async fn log_audit(&self, entry: AuditEntry) -> Result<()>;

    /// Get audit log for a user
    async fn get_audit_log(&self, user_id: &UserId) -> Result<Vec<AuditEntry>>;
}

/// In-memory implementation for testing
#[derive(Clone, Default)]
pub struct InMemoryStore {
    shares: Arc<Mutex<HashMap<String, Vec<StoredShare>>>>,
    audit_log: Arc<Mutex<Vec<AuditEntry>>>,
}

impl InMemoryStore {
    pub fn new() -> Self {
        Self::default()
    }

    fn user_key(user_id: &UserId) -> String {
        user_id.0.to_string()
    }
}

impl ShareStore for InMemoryStore {
    async fn store_share(&self, share: StoredShare) -> Result<()> {
        let key = Self::user_key(&share.user_id);
        let mut map = self.shares.lock().map_err(|_| EreborError::Internal("Lock poisoned".into()))?;
        map.entry(key).or_default().push(share);
        Ok(())
    }

    async fn get_shares(&self, user_id: &UserId) -> Result<Vec<StoredShare>> {
        let key = Self::user_key(user_id);
        let map = self.shares.lock().map_err(|_| EreborError::Internal("Lock poisoned".into()))?;
        Ok(map.get(&key).cloned().unwrap_or_default())
    }

    async fn get_share(&self, user_id: &UserId, index: u8) -> Result<Option<StoredShare>> {
        let shares = self.get_shares(user_id).await?;
        Ok(shares.into_iter().find(|s| s.share_index == index))
    }

    async fn replace_shares(&self, user_id: &UserId, shares: Vec<StoredShare>) -> Result<()> {
        let key = Self::user_key(user_id);
        let mut map = self.shares.lock().map_err(|_| EreborError::Internal("Lock poisoned".into()))?;
        map.insert(key, shares);
        Ok(())
    }

    async fn delete_shares(&self, user_id: &UserId) -> Result<()> {
        let key = Self::user_key(user_id);
        let mut map = self.shares.lock().map_err(|_| EreborError::Internal("Lock poisoned".into()))?;
        map.remove(&key);
        Ok(())
    }

    async fn log_audit(&self, entry: AuditEntry) -> Result<()> {
        let mut log = self.audit_log.lock().map_err(|_| EreborError::Internal("Lock poisoned".into()))?;
        log.push(entry);
        Ok(())
    }

    async fn get_audit_log(&self, user_id: &UserId) -> Result<Vec<AuditEntry>> {
        let log = self.audit_log.lock().map_err(|_| EreborError::Internal("Lock poisoned".into()))?;
        Ok(log.iter().filter(|e| e.user_id == *user_id).cloned().collect())
    }
}

/// Helper to create an audit entry
pub fn audit_entry(user_id: &UserId, operation: KeyOperation, details: impl Into<String>) -> AuditEntry {
    AuditEntry {
        id: Uuid::new_v4(),
        user_id: user_id.clone(),
        operation,
        timestamp: Utc::now(),
        details: details.into(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_user() -> UserId {
        UserId::new()
    }

    fn test_share(user_id: &UserId, index: u8) -> StoredShare {
        StoredShare {
            share_id: Uuid::new_v4(),
            user_id: user_id.clone(),
            share_index: index,
            ciphertext: vec![0xAA; 48],
            nonce: vec![0xBB; 12],
            created_at: Utc::now(),
            rotated_at: None,
        }
    }

    #[tokio::test]
    async fn test_store_and_retrieve() {
        let store = InMemoryStore::new();
        let user = test_user();
        store.store_share(test_share(&user, 1)).await.unwrap();
        store.store_share(test_share(&user, 2)).await.unwrap();
        let shares = store.get_shares(&user).await.unwrap();
        assert_eq!(shares.len(), 2);
    }

    #[tokio::test]
    async fn test_get_specific_share() {
        let store = InMemoryStore::new();
        let user = test_user();
        store.store_share(test_share(&user, 1)).await.unwrap();
        store.store_share(test_share(&user, 2)).await.unwrap();
        let share = store.get_share(&user, 2).await.unwrap();
        assert!(share.is_some());
        assert_eq!(share.unwrap().share_index, 2);
    }

    #[tokio::test]
    async fn test_replace_shares() {
        let store = InMemoryStore::new();
        let user = test_user();
        store.store_share(test_share(&user, 1)).await.unwrap();
        store.store_share(test_share(&user, 2)).await.unwrap();
        // Replace with new set
        let new_shares = vec![test_share(&user, 1), test_share(&user, 2), test_share(&user, 3)];
        store.replace_shares(&user, new_shares).await.unwrap();
        let shares = store.get_shares(&user).await.unwrap();
        assert_eq!(shares.len(), 3);
    }

    #[tokio::test]
    async fn test_delete_shares() {
        let store = InMemoryStore::new();
        let user = test_user();
        store.store_share(test_share(&user, 1)).await.unwrap();
        store.delete_shares(&user).await.unwrap();
        let shares = store.get_shares(&user).await.unwrap();
        assert!(shares.is_empty());
    }

    #[tokio::test]
    async fn test_audit_log() {
        let store = InMemoryStore::new();
        let user = test_user();
        store.log_audit(audit_entry(&user, KeyOperation::CreateWallet, "created")).await.unwrap();
        store.log_audit(audit_entry(&user, KeyOperation::SignTransaction, "signed tx")).await.unwrap();
        let log = store.get_audit_log(&user).await.unwrap();
        assert_eq!(log.len(), 2);
        assert_eq!(log[0].operation, KeyOperation::CreateWallet);
    }

    #[tokio::test]
    async fn test_audit_log_isolation() {
        let store = InMemoryStore::new();
        let user1 = test_user();
        let user2 = test_user();
        store.log_audit(audit_entry(&user1, KeyOperation::CreateWallet, "u1")).await.unwrap();
        store.log_audit(audit_entry(&user2, KeyOperation::CreateWallet, "u2")).await.unwrap();
        assert_eq!(store.get_audit_log(&user1).await.unwrap().len(), 1);
        assert_eq!(store.get_audit_log(&user2).await.unwrap().len(), 1);
    }

    #[tokio::test]
    async fn test_empty_store() {
        let store = InMemoryStore::new();
        let user = test_user();
        assert!(store.get_shares(&user).await.unwrap().is_empty());
        assert!(store.get_share(&user, 1).await.unwrap().is_none());
    }
}
