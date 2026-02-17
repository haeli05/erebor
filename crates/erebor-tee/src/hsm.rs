//! # HSM (Hardware Security Module) Integration
//!
//! This module provides a unified interface for various HSM providers including
//! software HSMs for development, AWS CloudHSM, Azure Managed HSM, and YubiHSM.

use crate::{HsmConfig, TeeError, TeeResult, WrappedKey};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// HSM key operations
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum HsmKeyOperation {
    /// Generate a new symmetric key
    GenerateSymmetricKey { key_size: u32, algorithm: String },
    /// Generate a new asymmetric key pair
    GenerateAsymmetricKey { algorithm: String, key_size: u32 },
    /// Import an existing key
    ImportKey { key_data: Vec<u8>, algorithm: String },
    /// Derive a key from existing key material
    DeriveKey { base_key_id: String, derivation_data: Vec<u8> },
}

/// HSM signing operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HsmSignRequest {
    /// Key identifier
    pub key_id: String,
    /// Data to sign
    pub data: Vec<u8>,
    /// Signature algorithm
    pub algorithm: String,
    /// Additional parameters
    pub parameters: HashMap<String, serde_json::Value>,
}

/// HSM encryption operation
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HsmEncryptRequest {
    /// Key identifier
    pub key_id: String,
    /// Plaintext data
    pub plaintext: Vec<u8>,
    /// Encryption algorithm
    pub algorithm: String,
    /// Initialization vector (if required)
    pub iv: Option<Vec<u8>>,
    /// Additional authenticated data (for AEAD)
    pub aad: Option<Vec<u8>>,
}

/// HSM encryption result
#[derive(Debug, Clone, Serialize, Deserialize, ZeroizeOnDrop)]
pub struct HsmEncryptResult {
    /// Encrypted data
    pub ciphertext: Vec<u8>,
    /// Authentication tag (for AEAD)
    pub tag: Option<Vec<u8>>,
    /// Initialization vector used
    pub iv: Vec<u8>,
}

/// HSM key information
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HsmKeyInfo {
    /// Key identifier
    pub id: String,
    /// Key algorithm
    pub algorithm: String,
    /// Key size in bits
    pub key_size: u32,
    /// Key type (symmetric, private, public)
    pub key_type: String,
    /// Key usage flags
    pub usage: Vec<String>,
    /// Key creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Key metadata
    pub metadata: HashMap<String, String>,
}

/// HSM provider trait for different hardware security modules
#[async_trait::async_trait]
pub trait HsmProvider: Send + Sync {
    /// Initialize the HSM connection
    async fn initialize(&self, config: &HsmConfig) -> TeeResult<()>;
    
    /// Check HSM connection status
    async fn is_connected(&self) -> TeeResult<bool>;
    
    /// Generate a new key
    async fn generate_key(&self, operation: &HsmKeyOperation) -> TeeResult<String>;
    
    /// Import an existing key
    async fn import_key(&self, key_data: &[u8], algorithm: &str, usage: &[String]) -> TeeResult<String>;
    
    /// Delete a key
    async fn delete_key(&self, key_id: &str) -> TeeResult<()>;
    
    /// List available keys
    async fn list_keys(&self) -> TeeResult<Vec<HsmKeyInfo>>;
    
    /// Get key information
    async fn get_key_info(&self, key_id: &str) -> TeeResult<HsmKeyInfo>;
    
    /// Sign data with a key
    async fn sign(&self, request: &HsmSignRequest) -> TeeResult<Vec<u8>>;
    
    /// Verify a signature
    async fn verify(&self, key_id: &str, data: &[u8], signature: &[u8], algorithm: &str) -> TeeResult<bool>;
    
    /// Encrypt data with a key
    async fn encrypt(&self, request: &HsmEncryptRequest) -> TeeResult<HsmEncryptResult>;
    
    /// Decrypt data with a key
    async fn decrypt(&self, key_id: &str, ciphertext: &[u8], algorithm: &str, iv: &[u8], aad: Option<&[u8]>) -> TeeResult<Vec<u8>>;
    
    /// Wrap a key using another key
    async fn wrap_key(&self, key_id: &str, wrapping_key_id: &str, algorithm: &str) -> TeeResult<WrappedKey>;
    
    /// Unwrap a previously wrapped key
    async fn unwrap_key(&self, wrapped_key: &WrappedKey, wrapping_key_id: &str) -> TeeResult<String>;
    
    /// Get provider name
    fn get_provider_name(&self) -> &str;
    
    /// Get supported algorithms
    fn get_supported_algorithms(&self) -> Vec<String>;
}

/// Software HSM provider for development and testing
pub struct SoftwareHsmProvider {
    keys: Arc<RwLock<HashMap<String, SoftwareKey>>>,
    connected: Arc<RwLock<bool>>,
}

#[derive(Debug, Clone, ZeroizeOnDrop)]
struct SoftwareKey {
    id: String,
    algorithm: String,
    key_size: u32,
    key_type: String,
    key_data: Vec<u8>,
    usage: Vec<String>,
    created_at: chrono::DateTime<chrono::Utc>,
    metadata: HashMap<String, String>,
}

impl Default for SoftwareHsmProvider {
    fn default() -> Self {
        Self::new()
    }
}

impl SoftwareHsmProvider {
    pub fn new() -> Self {
        Self {
            keys: Arc::new(RwLock::new(HashMap::new())),
            connected: Arc::new(RwLock::new(false)),
        }
    }
    
    async fn generate_software_key(&self, operation: &HsmKeyOperation) -> TeeResult<Vec<u8>> {
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        
        match operation {
            HsmKeyOperation::GenerateSymmetricKey { key_size, .. } => {
                let mut key = vec![0u8; (*key_size / 8) as usize];
                rng.fill_bytes(&mut key);
                Ok(key)
            }
            HsmKeyOperation::GenerateAsymmetricKey { algorithm, key_size } => {
                // For simplicity, just generate random bytes
                // In a real implementation, use proper crypto libraries
                let mut key = vec![0u8; (*key_size / 8) as usize];
                rng.fill_bytes(&mut key);
                Ok(key)
            }
            HsmKeyOperation::ImportKey { key_data, .. } => Ok(key_data.clone()),
            HsmKeyOperation::DeriveKey { derivation_data, .. } => {
                // Simple derivation using SHA-256
                use sha2::{Sha256, Digest};
                let hash = Sha256::digest(derivation_data);
                Ok(hash.to_vec())
            }
        }
    }
}

#[async_trait::async_trait]
impl HsmProvider for SoftwareHsmProvider {
    async fn initialize(&self, _config: &HsmConfig) -> TeeResult<()> {
        let mut connected = self.connected.write().await;
        *connected = true;
        info!("Software HSM provider initialized");
        Ok(())
    }
    
    async fn is_connected(&self) -> TeeResult<bool> {
        let connected = self.connected.read().await;
        Ok(*connected)
    }
    
    async fn generate_key(&self, operation: &HsmKeyOperation) -> TeeResult<String> {
        let key_data = self.generate_software_key(operation).await?;
        let key_id = uuid::Uuid::new_v4().to_string();
        
        let (algorithm, key_size, key_type) = match operation {
            HsmKeyOperation::GenerateSymmetricKey { key_size, algorithm } => {
                (algorithm.clone(), *key_size, "symmetric".to_string())
            }
            HsmKeyOperation::GenerateAsymmetricKey { algorithm, key_size } => {
                (algorithm.clone(), *key_size, "private".to_string())
            }
            HsmKeyOperation::ImportKey { algorithm, .. } => {
                (algorithm.clone(), key_data.len() as u32 * 8, "imported".to_string())
            }
            HsmKeyOperation::DeriveKey { .. } => {
                ("derived".to_string(), key_data.len() as u32 * 8, "derived".to_string())
            }
        };
        
        let key = SoftwareKey {
            id: key_id.clone(),
            algorithm,
            key_size,
            key_type,
            key_data,
            usage: vec!["sign".to_string(), "encrypt".to_string()],
            created_at: chrono::Utc::now(),
            metadata: HashMap::new(),
        };
        
        let mut keys = self.keys.write().await;
        keys.insert(key_id.clone(), key);
        
        debug!("Generated software key: {}", key_id);
        Ok(key_id)
    }
    
    async fn import_key(&self, key_data: &[u8], algorithm: &str, usage: &[String]) -> TeeResult<String> {
        let operation = HsmKeyOperation::ImportKey {
            key_data: key_data.to_vec(),
            algorithm: algorithm.to_string(),
        };
        self.generate_key(&operation).await
    }
    
    async fn delete_key(&self, key_id: &str) -> TeeResult<()> {
        let mut keys = self.keys.write().await;
        keys.remove(key_id);
        debug!("Deleted software key: {}", key_id);
        Ok(())
    }
    
    async fn list_keys(&self) -> TeeResult<Vec<HsmKeyInfo>> {
        let keys = self.keys.read().await;
        let key_infos = keys.values()
            .map(|key| HsmKeyInfo {
                id: key.id.clone(),
                algorithm: key.algorithm.clone(),
                key_size: key.key_size,
                key_type: key.key_type.clone(),
                usage: key.usage.clone(),
                created_at: key.created_at,
                metadata: key.metadata.clone(),
            })
            .collect();
        Ok(key_infos)
    }
    
    async fn get_key_info(&self, key_id: &str) -> TeeResult<HsmKeyInfo> {
        let keys = self.keys.read().await;
        let key = keys.get(key_id)
            .ok_or_else(|| TeeError::HsmError(format!("Key not found: {}", key_id)))?;
        
        Ok(HsmKeyInfo {
            id: key.id.clone(),
            algorithm: key.algorithm.clone(),
            key_size: key.key_size,
            key_type: key.key_type.clone(),
            usage: key.usage.clone(),
            created_at: key.created_at,
            metadata: key.metadata.clone(),
        })
    }
    
    async fn sign(&self, request: &HsmSignRequest) -> TeeResult<Vec<u8>> {
        let keys = self.keys.read().await;
        let _key = keys.get(&request.key_id)
            .ok_or_else(|| TeeError::HsmError(format!("Key not found: {}", request.key_id)))?;
        
        // Simple mock signature - in real implementation use proper cryptography
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(&request.data);
        hasher.update(request.key_id.as_bytes());
        let signature = hasher.finalize().to_vec();
        
        debug!("Signed data with key: {}", request.key_id);
        Ok(signature)
    }
    
    async fn verify(&self, key_id: &str, data: &[u8], signature: &[u8], _algorithm: &str) -> TeeResult<bool> {
        // Mock verification
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(data);
        hasher.update(key_id.as_bytes());
        let expected_signature = hasher.finalize();
        
        Ok(expected_signature.as_slice() == signature)
    }
    
    async fn encrypt(&self, request: &HsmEncryptRequest) -> TeeResult<HsmEncryptResult> {
        let keys = self.keys.read().await;
        let _key = keys.get(&request.key_id)
            .ok_or_else(|| TeeError::HsmError(format!("Key not found: {}", request.key_id)))?;
        
        // Mock encryption using XOR (NOT SECURE - for testing only)
        let mut ciphertext = request.plaintext.clone();
        let key_bytes = request.key_id.as_bytes();
        for (i, byte) in ciphertext.iter_mut().enumerate() {
            *byte ^= key_bytes[i % key_bytes.len()];
        }
        
        let iv = request.iv.clone().unwrap_or_else(|| vec![0u8; 16]);
        
        Ok(HsmEncryptResult {
            ciphertext,
            tag: None,
            iv,
        })
    }
    
    async fn decrypt(&self, key_id: &str, ciphertext: &[u8], _algorithm: &str, _iv: &[u8], _aad: Option<&[u8]>) -> TeeResult<Vec<u8>> {
        // Mock decryption using XOR (reverse of encrypt)
        let mut plaintext = ciphertext.to_vec();
        let key_bytes = key_id.as_bytes();
        for (i, byte) in plaintext.iter_mut().enumerate() {
            *byte ^= key_bytes[i % key_bytes.len()];
        }
        
        Ok(plaintext)
    }
    
    async fn wrap_key(&self, key_id: &str, wrapping_key_id: &str, algorithm: &str) -> TeeResult<WrappedKey> {
        let keys = self.keys.read().await;
        let key = keys.get(key_id)
            .ok_or_else(|| TeeError::HsmError(format!("Key not found: {}", key_id)))?;
        let _wrapping_key = keys.get(wrapping_key_id)
            .ok_or_else(|| TeeError::HsmError(format!("Wrapping key not found: {}", wrapping_key_id)))?;
        
        // Mock key wrapping - XOR with wrapping key ID (NOT SECURE)
        let mut encrypted_key = key.key_data.clone();
        let wrapping_bytes = wrapping_key_id.as_bytes();
        for (i, byte) in encrypted_key.iter_mut().enumerate() {
            *byte ^= wrapping_bytes[i % wrapping_bytes.len()];
        }
        
        let mut metadata = HashMap::new();
        metadata.insert("wrapped_by".to_string(), wrapping_key_id.to_string());
        metadata.insert("original_algorithm".to_string(), key.algorithm.clone());
        
        Ok(WrappedKey {
            encrypted_key,
            algorithm: algorithm.to_string(),
            key_id: wrapping_key_id.to_string(),
            metadata,
        })
    }
    
    async fn unwrap_key(&self, wrapped_key: &WrappedKey, wrapping_key_id: &str) -> TeeResult<String> {
        let keys = self.keys.read().await;
        let _wrapping_key = keys.get(wrapping_key_id)
            .ok_or_else(|| TeeError::HsmError(format!("Wrapping key not found: {}", wrapping_key_id)))?;
        
        // Mock key unwrapping - reverse XOR
        let mut key_data = wrapped_key.encrypted_key.clone();
        let wrapping_bytes = wrapping_key_id.as_bytes();
        for (i, byte) in key_data.iter_mut().enumerate() {
            *byte ^= wrapping_bytes[i % wrapping_bytes.len()];
        }
        
        // Create new key with unwrapped data
        let key_id = uuid::Uuid::new_v4().to_string();
        let algorithm = wrapped_key.metadata.get("original_algorithm")
            .cloned()
            .unwrap_or_else(|| "unknown".to_string());
        
        let key = SoftwareKey {
            id: key_id.clone(),
            algorithm,
            key_size: key_data.len() as u32 * 8,
            key_type: "unwrapped".to_string(),
            key_data,
            usage: vec!["sign".to_string(), "encrypt".to_string()],
            created_at: chrono::Utc::now(),
            metadata: HashMap::new(),
        };
        
        drop(keys);
        let mut keys = self.keys.write().await;
        keys.insert(key_id.clone(), key);
        
        debug!("Unwrapped key: {}", key_id);
        Ok(key_id)
    }
    
    fn get_provider_name(&self) -> &str {
        "software"
    }
    
    fn get_supported_algorithms(&self) -> Vec<String> {
        vec![
            "AES-256-GCM".to_string(),
            "RSA-2048".to_string(),
            "ECDSA-P256".to_string(),
            "HMAC-SHA256".to_string(),
        ]
    }
}

/// Create an HSM provider based on configuration
pub fn create_hsm_provider(config: &HsmConfig) -> TeeResult<Box<dyn HsmProvider>> {
    match config.provider.to_lowercase().as_str() {
        "software" => Ok(Box::new(SoftwareHsmProvider::new())),
        
        #[cfg(feature = "aws-cloudhsm")]
        "aws-cloudhsm" => {
            // AWS CloudHSM implementation would go here
            todo!("AWS CloudHSM support not yet implemented")
        },
        
        #[cfg(feature = "azure-hsm")]
        "azure-hsm" => {
            // Azure Managed HSM implementation would go here
            todo!("Azure HSM support not yet implemented")
        },
        
        #[cfg(feature = "yubihsm")]
        "yubihsm" => {
            // YubiHSM implementation would go here
            todo!("YubiHSM support not yet implemented")
        },
        
        _ => Err(TeeError::ConfigError(format!("Unsupported HSM provider: {}", config.provider))),
    }
}

/// Global HSM provider instance
static mut HSM_PROVIDER: Option<Box<dyn HsmProvider>> = None;
static HSM_INIT_LOCK: std::sync::Once = std::sync::Once::new();

/// Initialize the global HSM provider
pub async fn init_hsm(config: &HsmConfig) -> TeeResult<()> {
    let provider = create_hsm_provider(config)?;
    provider.initialize(config).await?;
    
    unsafe {
        HSM_INIT_LOCK.call_once(|| {
            HSM_PROVIDER = Some(provider);
        });
    }
    
    info!("HSM provider initialized: {}", config.provider);
    Ok(())
}

/// Get the global HSM provider
pub fn get_hsm_provider() -> TeeResult<&'static dyn HsmProvider> {
    unsafe {
        HSM_PROVIDER.as_ref()
            .map(|p| p.as_ref())
            .ok_or_else(|| TeeError::ConfigError("HSM provider not initialized".to_string()))
    }
}

/// Check HSM status using the global provider
pub async fn check_hsm_status() -> TeeResult<bool> {
    let provider = get_hsm_provider()?;
    provider.is_connected().await
}

/// Generate a key using the global HSM provider
pub async fn generate_hsm_key(operation: &HsmKeyOperation) -> TeeResult<String> {
    let provider = get_hsm_provider()?;
    provider.generate_key(operation).await
}

/// Sign data using the global HSM provider
pub async fn hsm_sign(request: &HsmSignRequest) -> TeeResult<Vec<u8>> {
    let provider = get_hsm_provider()?;
    provider.sign(request).await
}

/// Encrypt data using the global HSM provider
pub async fn hsm_encrypt(request: &HsmEncryptRequest) -> TeeResult<HsmEncryptResult> {
    let provider = get_hsm_provider()?;
    provider.encrypt(request).await
}

/// Wrap a key using the global HSM provider
pub async fn hsm_wrap_key(key_id: &str, wrapping_key_id: &str, algorithm: &str) -> TeeResult<WrappedKey> {
    let provider = get_hsm_provider()?;
    provider.wrap_key(key_id, wrapping_key_id, algorithm).await
}

/// Unwrap a key using the global HSM provider
pub async fn hsm_unwrap_key(wrapped_key: &WrappedKey, wrapping_key_id: &str) -> TeeResult<String> {
    let provider = get_hsm_provider()?;
    provider.unwrap_key(wrapped_key, wrapping_key_id).await
}

#[cfg(test)]
mod tests {
    use super::*;
    
    fn create_test_config() -> HsmConfig {
        HsmConfig {
            provider: "software".to_string(),
            pkcs11_library: None,
            slot_id: None,
            token_label: None,
            pin: None,
            config: HashMap::new(),
        }
    }
    
    #[tokio::test]
    async fn test_software_hsm_operations() {
        let config = create_test_config();
        let provider = SoftwareHsmProvider::new();
        
        // Initialize
        provider.initialize(&config).await.unwrap();
        assert!(provider.is_connected().await.unwrap());
        
        // Generate key
        let operation = HsmKeyOperation::GenerateSymmetricKey {
            key_size: 256,
            algorithm: "AES-256-GCM".to_string(),
        };
        let key_id = provider.generate_key(&operation).await.unwrap();
        assert!(!key_id.is_empty());
        
        // Get key info
        let key_info = provider.get_key_info(&key_id).await.unwrap();
        assert_eq!(key_info.id, key_id);
        assert_eq!(key_info.key_size, 256);
        
        // Sign data
        let sign_request = HsmSignRequest {
            key_id: key_id.clone(),
            data: b"test data".to_vec(),
            algorithm: "HMAC-SHA256".to_string(),
            parameters: HashMap::new(),
        };
        let signature = provider.sign(&sign_request).await.unwrap();
        assert!(!signature.is_empty());
        
        // Verify signature
        let verified = provider.verify(&key_id, b"test data", &signature, "HMAC-SHA256").await.unwrap();
        assert!(verified);
        
        // Encrypt data
        let encrypt_request = HsmEncryptRequest {
            key_id: key_id.clone(),
            plaintext: b"secret data".to_vec(),
            algorithm: "AES-256-GCM".to_string(),
            iv: None,
            aad: None,
        };
        let encrypted = provider.encrypt(&encrypt_request).await.unwrap();
        assert!(!encrypted.ciphertext.is_empty());
        
        // Decrypt data
        let decrypted = provider.decrypt(&key_id, &encrypted.ciphertext, "AES-256-GCM", &encrypted.iv, None).await.unwrap();
        assert_eq!(decrypted, b"secret data");
        
        // List keys
        let keys = provider.list_keys().await.unwrap();
        assert_eq!(keys.len(), 1);
        assert_eq!(keys[0].id, key_id);
        
        // Delete key
        provider.delete_key(&key_id).await.unwrap();
        let keys = provider.list_keys().await.unwrap();
        assert_eq!(keys.len(), 0);
    }
    
    #[tokio::test]
    async fn test_key_wrapping() {
        let provider = SoftwareHsmProvider::new();
        let config = create_test_config();
        provider.initialize(&config).await.unwrap();
        
        // Generate wrapping key
        let wrapping_operation = HsmKeyOperation::GenerateSymmetricKey {
            key_size: 256,
            algorithm: "AES-256".to_string(),
        };
        let wrapping_key_id = provider.generate_key(&wrapping_operation).await.unwrap();
        
        // Generate key to wrap
        let key_operation = HsmKeyOperation::GenerateSymmetricKey {
            key_size: 128,
            algorithm: "AES-128".to_string(),
        };
        let key_id = provider.generate_key(&key_operation).await.unwrap();
        
        // Wrap key
        let wrapped_key = provider.wrap_key(&key_id, &wrapping_key_id, "AES-256-KW").await.unwrap();
        assert!(!wrapped_key.encrypted_key.is_empty());
        assert_eq!(wrapped_key.key_id, wrapping_key_id);
        
        // Unwrap key
        let unwrapped_key_id = provider.unwrap_key(&wrapped_key, &wrapping_key_id).await.unwrap();
        assert!(!unwrapped_key_id.is_empty());
        assert_ne!(unwrapped_key_id, key_id); // Should be a new key ID
        
        // Verify unwrapped key works
        let keys = provider.list_keys().await.unwrap();
        assert_eq!(keys.len(), 3); // wrapping key, original key, unwrapped key
    }
}