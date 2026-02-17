pub mod encryption;
pub mod key_derivation;
pub mod shamir;
pub mod storage;

pub use encryption::EncryptionService;
pub use shamir::{Share, ShamirVault};
pub use storage::{AuditEntry, InMemoryStore, KeyOperation, ShareStore, StoredShare};

use chrono::Utc;
use erebor_common::{EreborError, Result, SecretBytes, UserId};
use rand::RngCore;
use uuid::Uuid;
use zeroize::Zeroize;

/// High-level vault service tying Shamir + Encryption + Storage together
pub struct VaultService<S: ShareStore> {
    shamir: ShamirVault,
    encryption: EncryptionService,
    store: S,
}

/// Result of wallet creation
#[derive(Debug, Clone)]
pub struct WalletInfo {
    pub user_id: UserId,
    pub ethereum_address: String,
    pub share_indices: Vec<u8>,
}

impl<S: ShareStore> VaultService<S> {
    pub fn new(shamir: ShamirVault, encryption: EncryptionService, store: S) -> Self {
        Self { shamir, encryption, store }
    }

    /// Create a new wallet for a user: generate key, split, encrypt, store
    pub async fn create_wallet(&self, user_id: &UserId) -> Result<WalletInfo> {
        // Generate random seed
        let mut seed = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut seed);

        // Derive Ethereum key
        let eth_key = key_derivation::derive_ethereum_key(&seed, 0)?;
        let eth_address = key_derivation::ethereum_address(&eth_key.secret_key)?;

        // Split the seed (not the derived key - seed allows deriving all chains)
        let shares = self.shamir.split(&seed)?;
        seed.zeroize();

        let user_ctx = user_id.0.as_bytes().to_vec();
        let mut share_indices = Vec::new();

        for share in &shares {
            let (ciphertext, nonce) = self.encryption.encrypt(&share.data, &user_ctx)?;
            let stored = StoredShare {
                share_id: Uuid::new_v4(),
                user_id: user_id.clone(),
                share_index: share.index,
                ciphertext,
                nonce,
                created_at: Utc::now(),
                rotated_at: None,
            };
            share_indices.push(share.index);
            self.store.store_share(stored).await?;
        }

        self.store
            .log_audit(storage::audit_entry(
                user_id,
                KeyOperation::CreateWallet,
                format!("Created wallet, eth={eth_address}"),
            ))
            .await?;

        Ok(WalletInfo {
            user_id: user_id.clone(),
            ethereum_address: eth_address,
            share_indices,
        })
    }

    /// Sign a transaction hash: decrypt shares, reconstruct seed, derive key, sign, zeroize
    pub async fn sign_transaction(
        &self,
        user_id: &UserId,
        share_indices: &[u8],
        tx_hash: &[u8; 32],
    ) -> Result<Vec<u8>> {
        if share_indices.len() < self.shamir.threshold {
            return Err(EreborError::ShareError(format!(
                "Need {} shares, got {}",
                self.shamir.threshold,
                share_indices.len()
            )));
        }

        let user_ctx = user_id.0.as_bytes().to_vec();
        let mut decrypted_shares = Vec::new();

        for &idx in share_indices {
            let stored = self
                .store
                .get_share(user_id, idx)
                .await?
                .ok_or_else(|| EreborError::NotFound(format!("Share index {idx}")))?;
            let plaintext = self.encryption.decrypt(&stored.ciphertext, &stored.nonce, &user_ctx)?;
            decrypted_shares.push(Share {
                index: idx,
                data: plaintext.0.clone(),
            });
        }

        let mut seed = self.shamir.reconstruct(&decrypted_shares)?;
        let eth_key = key_derivation::derive_ethereum_key(&seed.0, 0)?;
        let signature = key_derivation::secp256k1_sign(&eth_key.secret_key, tx_hash)?;
        seed.0.zeroize();

        self.store
            .log_audit(storage::audit_entry(
                user_id,
                KeyOperation::SignTransaction,
                format!("Signed tx {}", hex::encode(tx_hash)),
            ))
            .await?;

        Ok(signature)
    }

    /// Re-split the secret without changing the underlying key
    pub async fn rotate_shares(&self, user_id: &UserId) -> Result<Vec<u8>> {
        // Retrieve all current shares
        let stored = self.store.get_shares(user_id).await?;
        if stored.len() < self.shamir.threshold {
            return Err(EreborError::ShareError("Not enough stored shares to reconstruct".into()));
        }

        let user_ctx = user_id.0.as_bytes().to_vec();

        // Decrypt enough shares to reconstruct
        let mut decrypted = Vec::new();
        for s in stored.iter().take(self.shamir.threshold) {
            let pt = self.encryption.decrypt(&s.ciphertext, &s.nonce, &user_ctx)?;
            decrypted.push(Share {
                index: s.share_index,
                data: pt.0.clone(),
            });
        }

        let mut seed = self.shamir.reconstruct(&decrypted)?;

        // Re-split with fresh randomness
        let new_shares = self.shamir.split(&seed.0)?;
        seed.0.zeroize();

        let now = Utc::now();
        let mut new_stored = Vec::new();
        let mut indices = Vec::new();

        for share in &new_shares {
            let (ciphertext, nonce) = self.encryption.encrypt(&share.data, &user_ctx)?;
            indices.push(share.index);
            new_stored.push(StoredShare {
                share_id: Uuid::new_v4(),
                user_id: user_id.clone(),
                share_index: share.index,
                ciphertext,
                nonce,
                created_at: now,
                rotated_at: Some(now),
            });
        }

        // Atomic replace
        self.store.replace_shares(user_id, new_stored).await?;

        self.store
            .log_audit(storage::audit_entry(
                user_id,
                KeyOperation::RotateShares,
                "Rotated shares",
            ))
            .await?;

        Ok(indices)
    }

    /// Export an encrypted recovery share for backup
    pub async fn export_recovery_share(
        &self,
        user_id: &UserId,
        share_index: u8,
        export_password: &[u8],
    ) -> Result<Vec<u8>> {
        let stored = self
            .store
            .get_share(user_id, share_index)
            .await?
            .ok_or_else(|| EreborError::NotFound(format!("Share index {share_index}")))?;

        let user_ctx = user_id.0.as_bytes().to_vec();
        let plaintext = self.encryption.decrypt(&stored.ciphertext, &stored.nonce, &user_ctx)?;

        // Re-encrypt with the export password as context
        let export_enc = EncryptionService::new(SecretBytes(export_password.to_vec()));
        let (ciphertext, nonce) = export_enc.encrypt(&plaintext.0, b"recovery-export")?;

        // Pack as nonce || ciphertext
        let mut packed = nonce;
        packed.extend_from_slice(&ciphertext);

        self.store
            .log_audit(storage::audit_entry(
                user_id,
                KeyOperation::ExportRecoveryShare,
                format!("Exported share index {share_index}"),
            ))
            .await?;

        Ok(packed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_vault() -> VaultService<InMemoryStore> {
        let shamir = ShamirVault::new(2, 3).unwrap();
        let encryption = EncryptionService::new(SecretBytes(vec![0x42; 32]));
        let store = InMemoryStore::new();
        VaultService::new(shamir, encryption, store)
    }

    #[tokio::test]
    async fn test_create_wallet() {
        let vault = test_vault();
        let user = UserId::new();
        let info = vault.create_wallet(&user).await.unwrap();
        assert!(info.ethereum_address.starts_with("0x"));
        assert_eq!(info.share_indices.len(), 3);
    }

    #[tokio::test]
    async fn test_create_and_sign() {
        let vault = test_vault();
        let user = UserId::new();
        let info = vault.create_wallet(&user).await.unwrap();

        let tx_hash = [0xAB_u8; 32];
        // Sign with first 2 shares (threshold = 2)
        let sig = vault
            .sign_transaction(&user, &info.share_indices[..2], &tx_hash)
            .await
            .unwrap();
        assert_eq!(sig.len(), 64);
    }

    #[tokio::test]
    async fn test_sign_with_different_share_pairs() {
        let vault = test_vault();
        let user = UserId::new();
        let info = vault.create_wallet(&user).await.unwrap();
        let tx_hash = [0xCD_u8; 32];

        // All pairs of 2 shares should produce the same signature
        let sig1 = vault.sign_transaction(&user, &[info.share_indices[0], info.share_indices[1]], &tx_hash).await.unwrap();
        let sig2 = vault.sign_transaction(&user, &[info.share_indices[0], info.share_indices[2]], &tx_hash).await.unwrap();
        let sig3 = vault.sign_transaction(&user, &[info.share_indices[1], info.share_indices[2]], &tx_hash).await.unwrap();
        assert_eq!(sig1, sig2);
        assert_eq!(sig2, sig3);
    }

    #[tokio::test]
    async fn test_insufficient_shares() {
        let vault = test_vault();
        let user = UserId::new();
        let info = vault.create_wallet(&user).await.unwrap();
        let tx_hash = [0x00_u8; 32];
        let result = vault.sign_transaction(&user, &info.share_indices[..1], &tx_hash).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_rotate_shares() {
        let vault = test_vault();
        let user = UserId::new();
        let info = vault.create_wallet(&user).await.unwrap();

        let new_indices = vault.rotate_shares(&user).await.unwrap();
        assert_eq!(new_indices.len(), 3);

        // Should still be able to sign with new shares
        let tx_hash = [0xEF_u8; 32];
        let sig = vault.sign_transaction(&user, &new_indices[..2], &tx_hash).await.unwrap();
        assert_eq!(sig.len(), 64);
    }

    #[tokio::test]
    async fn test_rotate_preserves_key() {
        let vault = test_vault();
        let user = UserId::new();
        let info = vault.create_wallet(&user).await.unwrap();
        let tx_hash = [0x11_u8; 32];

        // Sign before rotation
        let sig_before = vault.sign_transaction(&user, &info.share_indices[..2], &tx_hash).await.unwrap();

        // Rotate
        let new_indices = vault.rotate_shares(&user).await.unwrap();

        // Sign after rotation — same signature (same underlying key)
        let sig_after = vault.sign_transaction(&user, &new_indices[..2], &tx_hash).await.unwrap();
        assert_eq!(sig_before, sig_after);
    }

    #[tokio::test]
    async fn test_export_recovery_share() {
        let vault = test_vault();
        let user = UserId::new();
        let info = vault.create_wallet(&user).await.unwrap();

        let export = vault
            .export_recovery_share(&user, info.share_indices[0], b"my-backup-password-32-bytes-long")
            .await
            .unwrap();
        assert!(!export.is_empty());
        // Should contain nonce (12) + ciphertext (share_len + 16 tag)
        assert!(export.len() > 12);
    }

    #[tokio::test]
    async fn test_audit_trail() {
        let vault = test_vault();
        let user = UserId::new();
        vault.create_wallet(&user).await.unwrap();

        let log = vault.store.get_audit_log(&user).await.unwrap();
        assert_eq!(log.len(), 1);
        assert_eq!(log[0].operation, KeyOperation::CreateWallet);
    }

    #[tokio::test]
    async fn test_full_lifecycle() {
        let vault = test_vault();
        let user = UserId::new();

        // 1. Create wallet
        let info = vault.create_wallet(&user).await.unwrap();
        assert!(info.ethereum_address.starts_with("0x"));

        // 2. Sign a transaction
        let tx = [0xFF_u8; 32];
        let sig1 = vault.sign_transaction(&user, &info.share_indices[..2], &tx).await.unwrap();

        // 3. Rotate shares
        let new_indices = vault.rotate_shares(&user).await.unwrap();

        // 4. Sign again — same result
        let sig2 = vault.sign_transaction(&user, &new_indices[..2], &tx).await.unwrap();
        assert_eq!(sig1, sig2);

        // 5. Export recovery
        let _export = vault.export_recovery_share(&user, new_indices[2], b"backup-key-32-bytes-long!!!!!!!!").await.unwrap();

        // 6. Verify audit trail
        let log = vault.store.get_audit_log(&user).await.unwrap();
        assert!(log.len() >= 4); // create + sign + rotate + sign + export
    }
}
