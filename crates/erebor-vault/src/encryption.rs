use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use erebor_common::{EreborError, Result, SecretBytes};
use hkdf::Hkdf;
use rand::RngCore;
use sha2::Sha256;
use zeroize::Zeroize;

/// AES-256-GCM encryption for key shares at rest
pub struct EncryptionService {
    master_key: SecretBytes,
}

impl EncryptionService {
    pub fn new(master_key: SecretBytes) -> Self {
        Self { master_key }
    }

    /// Derive a per-user data encryption key from master key + user context
    fn derive_dek(&self, context: &[u8]) -> Result<SecretBytes> {
        let hk = Hkdf::<Sha256>::new(None, &self.master_key.0);
        let mut dek = vec![0u8; 32];
        hk.expand(context, &mut dek)
            .map_err(|e| EreborError::EncryptionError(format!("HKDF expand failed: {e}")))?;
        Ok(SecretBytes(dek))
    }

    /// Encrypt data with per-user derived key
    pub fn encrypt(&self, plaintext: &[u8], user_context: &[u8]) -> Result<(Vec<u8>, Vec<u8>)> {
        let dek = self.derive_dek(user_context)?;
        let cipher = Aes256Gcm::new_from_slice(&dek.0)
            .map_err(|e| EreborError::EncryptionError(format!("Cipher init failed: {e}")))?;

        let mut nonce_bytes = [0u8; 12];
        rand::thread_rng().fill_bytes(&mut nonce_bytes);
        let nonce = Nonce::from_slice(&nonce_bytes);

        let ciphertext = cipher
            .encrypt(nonce, plaintext)
            .map_err(|e| EreborError::EncryptionError(format!("Encrypt failed: {e}")))?;

        Ok((ciphertext, nonce_bytes.to_vec()))
    }

    /// Decrypt data with per-user derived key
    pub fn decrypt(
        &self,
        ciphertext: &[u8],
        nonce_bytes: &[u8],
        user_context: &[u8],
    ) -> Result<SecretBytes> {
        let dek = self.derive_dek(user_context)?;
        let cipher = Aes256Gcm::new_from_slice(&dek.0)
            .map_err(|e| EreborError::EncryptionError(format!("Cipher init failed: {e}")))?;

        let nonce = Nonce::from_slice(nonce_bytes);
        let mut plaintext = cipher
            .decrypt(nonce, ciphertext)
            .map_err(|e| EreborError::EncryptionError(format!("Decrypt failed: {e}")))?;

        let result = SecretBytes(plaintext.clone());
        plaintext.zeroize();
        Ok(result)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn test_service() -> EncryptionService {
        EncryptionService::new(SecretBytes(vec![0x42; 32]))
    }

    #[test]
    fn test_encrypt_decrypt_roundtrip() {
        let svc = test_service();
        let plaintext = b"this is a secret key share";
        let context = b"user:abc123";

        let (ciphertext, nonce) = svc.encrypt(plaintext, context).unwrap();
        let decrypted = svc.decrypt(&ciphertext, &nonce, context).unwrap();

        assert_eq!(&decrypted.0, plaintext);
    }

    #[test]
    fn test_wrong_context_fails() {
        let svc = test_service();
        let plaintext = b"secret";
        let (ciphertext, nonce) = svc.encrypt(plaintext, b"user:alice").unwrap();
        let result = svc.decrypt(&ciphertext, &nonce, b"user:bob");
        assert!(result.is_err());
    }

    #[test]
    fn test_tampered_ciphertext_fails() {
        let svc = test_service();
        let plaintext = b"secret";
        let context = b"user:alice";
        let (mut ciphertext, nonce) = svc.encrypt(plaintext, context).unwrap();
        ciphertext[0] ^= 0xFF; // flip a byte
        let result = svc.decrypt(&ciphertext, &nonce, context);
        assert!(result.is_err());
    }

    #[test]
    fn test_different_nonces_per_encrypt() {
        let svc = test_service();
        let plaintext = b"same data";
        let context = b"user:alice";
        let (ct1, n1) = svc.encrypt(plaintext, context).unwrap();
        let (ct2, n2) = svc.encrypt(plaintext, context).unwrap();
        assert_ne!(n1, n2, "Each encryption must use unique nonce");
        assert_ne!(ct1, ct2, "Same plaintext should produce different ciphertext");
    }
}
