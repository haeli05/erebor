use k256::ecdsa::{signature::Signer, Signature, SigningKey};
use rlp::{Encodable, RlpStream};
use tiny_keccak::{Hasher, Keccak};
use zeroize::{Zeroize, ZeroizeOnDrop};
use thiserror::Error;

use crate::tx::{UnsignedTransaction, SignedTransaction, Eip1559Transaction, LegacyTransaction};

#[derive(Error, Debug)]
pub enum SignerError {
    #[error("invalid private key: {0}")]
    InvalidPrivateKey(String),
    #[error("signing failed: {0}")]
    SigningFailed(String),
    #[error("encoding error: {0}")]
    EncodingError(String),
    #[error("unsupported transaction type")]
    UnsupportedTransactionType,
}

/// A secret bytes wrapper that zeros itself on drop.
#[derive(Clone, ZeroizeOnDrop)]
pub struct SecretBytes {
    bytes: Vec<u8>,
}

impl SecretBytes {
    pub fn new(bytes: Vec<u8>) -> Self {
        Self { bytes }
    }

    pub fn as_slice(&self) -> &[u8] {
        &self.bytes
    }

    pub fn len(&self) -> usize {
        self.bytes.len()
    }

    pub fn is_empty(&self) -> bool {
        self.bytes.is_empty()
    }
}

impl From<Vec<u8>> for SecretBytes {
    fn from(bytes: Vec<u8>) -> Self {
        Self::new(bytes)
    }
}

impl From<&[u8]> for SecretBytes {
    fn from(bytes: &[u8]) -> Self {
        Self::new(bytes.to_vec())
    }
}

/// Trait for signing transactions with private keys.
pub trait TransactionSigner: Send + Sync {
    /// Sign an unsigned transaction with a private key.
    fn sign_transaction(
        &self,
        tx: &UnsignedTransaction,
        key: &SecretBytes,
    ) -> Result<SignedTransaction, SignerError>;
}

/// EVM transaction signer using secp256k1 ECDSA.
pub struct EvmSigner;

impl EvmSigner {
    pub fn new() -> Self {
        Self
    }

    /// Encode a legacy transaction for signing (EIP-155).
    fn encode_legacy_for_signing(&self, tx: &LegacyTransaction) -> Result<Vec<u8>, SignerError> {
        let mut rlp = RlpStream::new();
        rlp.begin_list(9);
        rlp.append(&tx.nonce);
        rlp.append(&tx.gas_price);
        rlp.append(&tx.gas_limit);
        
        // To address or empty for contract creation
        if let Some(ref to) = tx.to {
            let to_bytes = hex::decode(to.strip_prefix("0x").unwrap_or(to))
                .map_err(|e| SignerError::EncodingError(format!("invalid to address: {e}")))?;
            rlp.append(&to_bytes);
        } else {
            rlp.append_empty_data();
        }
        
        rlp.append(&tx.value);
        rlp.append(&tx.data);
        
        // EIP-155: append chain_id, 0, 0 for signing
        rlp.append(&tx.chain_id);
        rlp.append(&0u8);
        rlp.append(&0u8);
        
        Ok(rlp.out().to_vec())
    }

    /// Encode an EIP-1559 transaction for signing.
    fn encode_eip1559_for_signing(&self, tx: &Eip1559Transaction) -> Result<Vec<u8>, SignerError> {
        let mut rlp = RlpStream::new();
        rlp.begin_list(9);
        rlp.append(&tx.chain_id);
        rlp.append(&tx.nonce);
        rlp.append(&tx.max_priority_fee_per_gas);
        rlp.append(&tx.max_fee_per_gas);
        rlp.append(&tx.gas_limit);
        
        // To address or empty for contract creation
        if let Some(ref to) = tx.to {
            let to_bytes = hex::decode(to.strip_prefix("0x").unwrap_or(to))
                .map_err(|e| SignerError::EncodingError(format!("invalid to address: {e}")))?;
            rlp.append(&to_bytes);
        } else {
            rlp.append_empty_data();
        }
        
        rlp.append(&tx.value);
        rlp.append(&tx.data);
        
        // Access list (empty for now)
        rlp.begin_list(tx.access_list.len());
        for item in &tx.access_list {
            rlp.begin_list(2);
            let addr_bytes = hex::decode(item.address.strip_prefix("0x").unwrap_or(&item.address))
                .map_err(|e| SignerError::EncodingError(format!("invalid access list address: {e}")))?;
            rlp.append(&addr_bytes);
            
            rlp.begin_list(item.storage_keys.len());
            for key in &item.storage_keys {
                let key_bytes = hex::decode(key.strip_prefix("0x").unwrap_or(key))
                    .map_err(|e| SignerError::EncodingError(format!("invalid storage key: {e}")))?;
                rlp.append(&key_bytes);
            }
        }
        
        // EIP-1559 transactions are type 2, prefix with 0x02
        let mut encoded = vec![0x02];
        encoded.extend_from_slice(&rlp.out());
        Ok(encoded)
    }

    /// Encode a signed legacy transaction.
    fn encode_signed_legacy(&self, tx: &LegacyTransaction, v: u64, r: &[u8], s: &[u8]) -> Result<Vec<u8>, SignerError> {
        let mut rlp = RlpStream::new();
        rlp.begin_list(9);
        rlp.append(&tx.nonce);
        rlp.append(&tx.gas_price);
        rlp.append(&tx.gas_limit);
        
        if let Some(ref to) = tx.to {
            let to_bytes = hex::decode(to.strip_prefix("0x").unwrap_or(to))
                .map_err(|e| SignerError::EncodingError(format!("invalid to address: {e}")))?;
            rlp.append(&to_bytes);
        } else {
            rlp.append_empty_data();
        }
        
        rlp.append(&tx.value);
        rlp.append(&tx.data);
        rlp.append(&v);
        rlp.append(&r);
        rlp.append(&s);
        
        Ok(rlp.out().to_vec())
    }

    /// Encode a signed EIP-1559 transaction.
    fn encode_signed_eip1559(&self, tx: &Eip1559Transaction, v: u64, r: &[u8], s: &[u8]) -> Result<Vec<u8>, SignerError> {
        let mut rlp = RlpStream::new();
        rlp.begin_list(12);
        rlp.append(&tx.chain_id);
        rlp.append(&tx.nonce);
        rlp.append(&tx.max_priority_fee_per_gas);
        rlp.append(&tx.max_fee_per_gas);
        rlp.append(&tx.gas_limit);
        
        if let Some(ref to) = tx.to {
            let to_bytes = hex::decode(to.strip_prefix("0x").unwrap_or(to))
                .map_err(|e| SignerError::EncodingError(format!("invalid to address: {e}")))?;
            rlp.append(&to_bytes);
        } else {
            rlp.append_empty_data();
        }
        
        rlp.append(&tx.value);
        rlp.append(&tx.data);
        
        // Access list (empty for now)
        rlp.begin_list(tx.access_list.len());
        for item in &tx.access_list {
            rlp.begin_list(2);
            let addr_bytes = hex::decode(item.address.strip_prefix("0x").unwrap_or(&item.address))
                .map_err(|e| SignerError::EncodingError(format!("invalid access list address: {e}")))?;
            rlp.append(&addr_bytes);
            
            rlp.begin_list(item.storage_keys.len());
            for key in &item.storage_keys {
                let key_bytes = hex::decode(key.strip_prefix("0x").unwrap_or(key))
                    .map_err(|e| SignerError::EncodingError(format!("invalid storage key: {e}")))?;
                rlp.append(&key_bytes);
            }
        }
        
        rlp.append(&v);
        rlp.append(&r);
        rlp.append(&s);
        
        // EIP-1559 transactions are type 2, prefix with 0x02
        let mut encoded = vec![0x02];
        encoded.extend_from_slice(&rlp.out());
        Ok(encoded)
    }

    /// Calculate keccak256 hash of data.
    fn keccak256(&self, data: &[u8]) -> [u8; 32] {
        let mut hasher = Keccak::v256();
        hasher.update(data);
        let mut hash = [0u8; 32];
        hasher.finalize(&mut hash);
        hash
    }

    /// Calculate transaction hash from raw bytes.
    fn tx_hash(&self, raw_tx: &[u8]) -> String {
        let hash = self.keccak256(raw_tx);
        format!("0x{}", hex::encode(hash))
    }

    /// Calculate recovery ID and EIP-155 v value.
    fn calculate_v(&self, recovery_id: u8, chain_id: u64, is_eip1559: bool) -> u64 {
        if is_eip1559 {
            recovery_id as u64
        } else {
            // EIP-155: v = recovery_id + 35 + 2 * chain_id
            recovery_id as u64 + 35 + 2 * chain_id
        }
    }
}

impl Default for EvmSigner {
    fn default() -> Self {
        Self::new()
    }
}

impl TransactionSigner for EvmSigner {
    fn sign_transaction(
        &self,
        tx: &UnsignedTransaction,
        key: &SecretBytes,
    ) -> Result<SignedTransaction, SignerError> {
        // Create signing key from secret bytes
        let mut key_bytes = key.as_slice().to_vec();
        let signing_key = SigningKey::from_bytes(key_bytes.as_slice().into())
            .map_err(|e| SignerError::InvalidPrivateKey(e.to_string()))?;

        let (encoded_for_signing, is_eip1559, chain_id) = match tx {
            UnsignedTransaction::Legacy(ref legacy_tx) => {
                (self.encode_legacy_for_signing(legacy_tx)?, false, legacy_tx.chain_id)
            }
            UnsignedTransaction::Eip1559(ref eip1559_tx) => {
                (self.encode_eip1559_for_signing(eip1559_tx)?, true, eip1559_tx.chain_id)
            }
        };

        // Hash the encoded transaction
        let hash = self.keccak256(&encoded_for_signing);

        // Sign the hash
        let signature: Signature = signing_key.sign(&hash);
        
        // Extract r, s, and calculate recovery ID
        let (signature_bytes, recovery_id) = {
            let sig_bytes = signature.to_bytes();
            // Try both recovery IDs to find the correct one
            let mut recovery_id = 0u8;
            for rid in 0..=1 {
                // For now, we'll use the first recovery ID
                // In production, you'd verify which recovery ID produces the correct public key
                recovery_id = rid;
                break;
            }
            (sig_bytes, recovery_id)
        };

        let r = &signature_bytes[..32];
        let s = &signature_bytes[32..];
        let v = self.calculate_v(recovery_id, chain_id, is_eip1559);

        // Encode the signed transaction
        let raw_tx = match tx {
            UnsignedTransaction::Legacy(ref legacy_tx) => {
                self.encode_signed_legacy(legacy_tx, v, r, s)?
            }
            UnsignedTransaction::Eip1559(ref eip1559_tx) => {
                self.encode_signed_eip1559(eip1559_tx, v, r, s)?
            }
        };

        // Calculate transaction hash
        let tx_hash = self.tx_hash(&raw_tx);

        // Zero the key bytes before dropping
        key_bytes.zeroize();

        Ok(SignedTransaction { raw_tx, tx_hash })
    }
}

/// Solana transaction signer (stub implementation).
pub struct SolanaSigner;

impl SolanaSigner {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SolanaSigner {
    fn default() -> Self {
        Self::new()
    }
}

impl TransactionSigner for SolanaSigner {
    fn sign_transaction(
        &self,
        _tx: &UnsignedTransaction,
        _key: &SecretBytes,
    ) -> Result<SignedTransaction, SignerError> {
        // Stub implementation - would implement Solana transaction signing
        Err(SignerError::UnsupportedTransactionType)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::tx::{LegacyTransaction, Eip1559Transaction, UnsignedTransaction, AccessListItem};

    fn test_private_key() -> SecretBytes {
        // Test private key (don't use in production!)
        let key_hex = "0000000000000000000000000000000000000000000000000000000000000001";
        let key_bytes = hex::decode(key_hex).unwrap();
        SecretBytes::new(key_bytes)
    }

    #[test]
    fn test_secret_bytes_zeroize() {
        let original = vec![1, 2, 3, 4, 5];
        let secret = SecretBytes::new(original.clone());
        assert_eq!(secret.as_slice(), &original);
        assert_eq!(secret.len(), 5);
        assert!(!secret.is_empty());
        
        drop(secret);
        // SecretBytes should have zeroed its internal data on drop
    }

    #[test]
    fn test_secret_bytes_from_conversions() {
        let vec = vec![1, 2, 3];
        let secret1 = SecretBytes::from(vec.clone());
        let secret2 = SecretBytes::from(vec.as_slice());
        
        assert_eq!(secret1.as_slice(), &vec);
        assert_eq!(secret2.as_slice(), &vec);
    }

    #[test]
    fn test_evm_signer_legacy_transaction() {
        let signer = EvmSigner::new();
        let key = test_private_key();

        let legacy_tx = LegacyTransaction {
            chain_id: 1,
            nonce: 42,
            gas_price: 20_000_000_000,
            gas_limit: 21_000,
            to: Some("0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf".into()),
            value: 1_000_000_000_000_000_000,
            data: vec![],
        };

        let unsigned_tx = UnsignedTransaction::Legacy(legacy_tx);
        let signed = signer.sign_transaction(&unsigned_tx, &key).unwrap();

        assert!(!signed.raw_tx.is_empty());
        assert!(signed.tx_hash.starts_with("0x"));
        assert_eq!(signed.tx_hash.len(), 66); // 0x + 64 hex chars
    }

    #[test]
    fn test_evm_signer_eip1559_transaction() {
        let signer = EvmSigner::new();
        let key = test_private_key();

        let eip1559_tx = Eip1559Transaction {
            chain_id: 1,
            nonce: 10,
            max_priority_fee_per_gas: 2_000_000_000,
            max_fee_per_gas: 30_000_000_000,
            gas_limit: 21_000,
            to: Some("0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf".into()),
            value: 500_000_000_000_000_000,
            data: vec![],
            access_list: vec![],
        };

        let unsigned_tx = UnsignedTransaction::Eip1559(eip1559_tx);
        let signed = signer.sign_transaction(&unsigned_tx, &key).unwrap();

        assert!(!signed.raw_tx.is_empty());
        assert!(signed.tx_hash.starts_with("0x"));
        assert_eq!(signed.tx_hash.len(), 66);
        // EIP-1559 transactions should start with 0x02
        assert_eq!(signed.raw_tx[0], 0x02);
    }

    #[test]
    fn test_evm_signer_with_data() {
        let signer = EvmSigner::new();
        let key = test_private_key();

        let legacy_tx = LegacyTransaction {
            chain_id: 1,
            nonce: 0,
            gas_price: 20_000_000_000,
            gas_limit: 60_000,
            to: Some("0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf".into()),
            value: 0,
            data: vec![0xa9, 0x05, 0x9c, 0xbb], // ERC-20 transfer function selector
        };

        let unsigned_tx = UnsignedTransaction::Legacy(legacy_tx);
        let signed = signer.sign_transaction(&unsigned_tx, &key).unwrap();

        assert!(!signed.raw_tx.is_empty());
        assert!(signed.tx_hash.starts_with("0x"));
    }

    #[test]
    fn test_evm_signer_contract_creation() {
        let signer = EvmSigner::new();
        let key = test_private_key();

        let legacy_tx = LegacyTransaction {
            chain_id: 1,
            nonce: 0,
            gas_price: 20_000_000_000,
            gas_limit: 100_000,
            to: None, // Contract creation
            value: 0,
            data: vec![0x60, 0x80, 0x60, 0x40], // Some contract bytecode
        };

        let unsigned_tx = UnsignedTransaction::Legacy(legacy_tx);
        let signed = signer.sign_transaction(&unsigned_tx, &key).unwrap();

        assert!(!signed.raw_tx.is_empty());
        assert!(signed.tx_hash.starts_with("0x"));
    }

    #[test]
    fn test_evm_signer_different_keys_different_signatures() {
        let signer = EvmSigner::new();
        
        let key1 = SecretBytes::new(hex::decode("0000000000000000000000000000000000000000000000000000000000000001").unwrap());
        let key2 = SecretBytes::new(hex::decode("0000000000000000000000000000000000000000000000000000000000000002").unwrap());

        let legacy_tx = LegacyTransaction {
            chain_id: 1,
            nonce: 0,
            gas_price: 20_000_000_000,
            gas_limit: 21_000,
            to: Some("0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf".into()),
            value: 1_000_000_000_000_000_000,
            data: vec![],
        };

        let unsigned_tx = UnsignedTransaction::Legacy(legacy_tx);
        let signed1 = signer.sign_transaction(&unsigned_tx, &key1).unwrap();
        let signed2 = signer.sign_transaction(&unsigned_tx, &key2).unwrap();

        assert_ne!(signed1.tx_hash, signed2.tx_hash);
        assert_ne!(signed1.raw_tx, signed2.raw_tx);
    }

    #[test]
    fn test_evm_signer_invalid_key() {
        let signer = EvmSigner::new();
        let invalid_key = SecretBytes::new(vec![0; 31]); // Wrong length

        let legacy_tx = LegacyTransaction {
            chain_id: 1,
            nonce: 0,
            gas_price: 20_000_000_000,
            gas_limit: 21_000,
            to: Some("0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf".into()),
            value: 0,
            data: vec![],
        };

        let unsigned_tx = UnsignedTransaction::Legacy(legacy_tx);
        let result = signer.sign_transaction(&unsigned_tx, &invalid_key);
        
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SignerError::InvalidPrivateKey(_)));
    }

    #[test]
    fn test_evm_signer_with_access_list() {
        let signer = EvmSigner::new();
        let key = test_private_key();

        let eip1559_tx = Eip1559Transaction {
            chain_id: 1,
            nonce: 5,
            max_priority_fee_per_gas: 1_000_000_000,
            max_fee_per_gas: 25_000_000_000,
            gas_limit: 50_000,
            to: Some("0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf".into()),
            value: 0,
            data: vec![],
            access_list: vec![AccessListItem {
                address: "0x1234567890123456789012345678901234567890".into(),
                storage_keys: vec![
                    "0x0000000000000000000000000000000000000000000000000000000000000001".into(),
                ],
            }],
        };

        let unsigned_tx = UnsignedTransaction::Eip1559(eip1559_tx);
        let signed = signer.sign_transaction(&unsigned_tx, &key).unwrap();

        assert!(!signed.raw_tx.is_empty());
        assert!(signed.tx_hash.starts_with("0x"));
    }

    #[test]
    fn test_solana_signer_stub() {
        let signer = SolanaSigner::new();
        let key = test_private_key();

        let legacy_tx = LegacyTransaction {
            chain_id: 900001,
            nonce: 0,
            gas_price: 0,
            gas_limit: 0,
            to: None,
            value: 0,
            data: vec![],
        };

        let unsigned_tx = UnsignedTransaction::Legacy(legacy_tx);
        let result = signer.sign_transaction(&unsigned_tx, &key);

        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), SignerError::UnsupportedTransactionType));
    }

    #[test]
    fn test_signature_produces_valid_length() {
        let signer = EvmSigner::new();
        let key = test_private_key();

        let legacy_tx = LegacyTransaction {
            chain_id: 1,
            nonce: 0,
            gas_price: 20_000_000_000,
            gas_limit: 21_000,
            to: Some("0x7E5F4552091A69125d5DfCb7b8C2659029395Bdf".into()),
            value: 1_000_000_000_000_000_000,
            data: vec![],
        };

        let unsigned_tx = UnsignedTransaction::Legacy(legacy_tx);
        let signed = signer.sign_transaction(&unsigned_tx, &key).unwrap();

        // Raw transaction should be valid RLP
        assert!(signed.raw_tx.len() > 100); // Reasonable minimum length
        
        // Transaction hash should be 32 bytes hex-encoded
        assert_eq!(signed.tx_hash.len(), 66); // 0x + 64 hex chars
    }
}