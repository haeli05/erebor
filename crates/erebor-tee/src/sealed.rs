//! # Sealed Storage
//!
//! This module provides encrypted storage that can only be decrypted within the same TEE environment.
//! Data is sealed to specific platform measurements and can only be unsealed by the same or
//! equivalent TEE instance.

use crate::{SealedData, SealedStorageConfig, TeeError, TeeResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tokio::fs;
use tokio::sync::RwLock;
use tracing::{debug, info, warn};
use zeroize::{Zeroize, ZeroizeOnDrop};

/// Sealing policy defining what measurements are used for sealing
#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum SealingPolicy {
    /// Seal to current enclave measurement only
    CurrentEnclave,
    /// Seal to signer measurement (allows updates with same signer)
    Signer,
    /// Seal to both enclave and signer measurements
    Both,
    /// Seal to custom measurements
    Custom(HashMap<String, String>),
    /// Software mode - no actual sealing (for testing)
    Software,
}

/// Sealed storage entry metadata
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedEntry {
    /// Entry identifier
    pub id: String,
    /// Sealing policy used
    pub policy: SealingPolicy,
    /// Creation timestamp
    pub created_at: chrono::DateTime<chrono::Utc>,
    /// Last access timestamp
    pub last_accessed: chrono::DateTime<chrono::Utc>,
    /// Data size in bytes
    pub size: u64,
    /// Content type hint
    pub content_type: Option<String>,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// Sealed storage manager
pub struct SealedStorageManager {
    config: SealedStorageConfig,
    storage_dir: PathBuf,
    entries: RwLock<HashMap<String, SealedEntry>>,
}

impl SealedStorageManager {
    /// Create a new sealed storage manager
    pub async fn new(config: SealedStorageConfig) -> TeeResult<Self> {
        let storage_dir = PathBuf::from(&config.storage_dir);
        
        // Create storage directory if it doesn't exist
        if !storage_dir.exists() {
            fs::create_dir_all(&storage_dir).await
                .map_err(|e| TeeError::SealedStorageError(format!("Failed to create storage directory: {}", e)))?;
        }
        
        let manager = Self {
            config,
            storage_dir,
            entries: RwLock::new(HashMap::new()),
        };
        
        // Load existing entries
        manager.load_entries().await?;
        
        info!("Sealed storage manager initialized at: {}", manager.storage_dir.display());
        Ok(manager)
    }
    
    /// Seal data with the specified policy
    pub async fn seal(&self, id: &str, data: &[u8], policy: SealingPolicy) -> TeeResult<()> {
        debug!("Sealing data with ID: {} (size: {} bytes)", id, data.len());
        
        let sealed_data = self.seal_data(data, &policy).await?;
        let file_path = self.get_data_path(id);
        
        // Write sealed data to file
        let serialized = bincode::serialize(&sealed_data)
            .map_err(|e| TeeError::SealedStorageError(format!("Serialization failed: {}", e)))?;
        
        fs::write(&file_path, serialized).await
            .map_err(|e| TeeError::SealedStorageError(format!("Failed to write sealed data: {}", e)))?;
        
        // Update entry metadata
        let entry = SealedEntry {
            id: id.to_string(),
            policy,
            created_at: chrono::Utc::now(),
            last_accessed: chrono::Utc::now(),
            size: data.len() as u64,
            content_type: None,
            metadata: HashMap::new(),
        };
        
        let mut entries = self.entries.write().await;
        entries.insert(id.to_string(), entry);
        
        // Save metadata
        self.save_entries().await?;
        
        info!("Data sealed with ID: {}", id);
        Ok(())
    }
    
    /// Unseal data with the specified ID
    pub async fn unseal(&self, id: &str) -> TeeResult<Vec<u8>> {
        debug!("Unsealing data with ID: {}", id);
        
        let file_path = self.get_data_path(id);
        if !file_path.exists() {
            return Err(TeeError::SealedStorageError(format!("Sealed data not found: {}", id)));
        }
        
        // Read sealed data from file
        let serialized = fs::read(&file_path).await
            .map_err(|e| TeeError::SealedStorageError(format!("Failed to read sealed data: {}", e)))?;
        
        let sealed_data: SealedData = bincode::deserialize(&serialized)
            .map_err(|e| TeeError::SealedStorageError(format!("Deserialization failed: {}", e)))?;
        
        // Get entry metadata to determine policy
        let policy = {
            let entries = self.entries.read().await;
            entries.get(id)
                .map(|e| e.policy.clone())
                .ok_or_else(|| TeeError::SealedStorageError(format!("Entry metadata not found: {}", id)))?
        };
        
        // Unseal data
        let data = self.unseal_data(&sealed_data, &policy).await?;
        
        // Update last accessed timestamp
        {
            let mut entries = self.entries.write().await;
            if let Some(entry) = entries.get_mut(id) {
                entry.last_accessed = chrono::Utc::now();
            }
        }
        
        debug!("Data unsealed with ID: {} (size: {} bytes)", id, data.len());
        Ok(data)
    }
    
    /// Delete sealed data
    pub async fn delete(&self, id: &str) -> TeeResult<()> {
        debug!("Deleting sealed data with ID: {}", id);
        
        let file_path = self.get_data_path(id);
        if file_path.exists() {
            fs::remove_file(&file_path).await
                .map_err(|e| TeeError::SealedStorageError(format!("Failed to delete sealed data: {}", e)))?;
        }
        
        // Remove from metadata
        {
            let mut entries = self.entries.write().await;
            entries.remove(id);
        }
        
        self.save_entries().await?;
        
        info!("Sealed data deleted: {}", id);
        Ok(())
    }
    
    /// List all sealed entries
    pub async fn list(&self) -> TeeResult<Vec<SealedEntry>> {
        let entries = self.entries.read().await;
        Ok(entries.values().cloned().collect())
    }
    
    /// Get entry metadata
    pub async fn get_entry(&self, id: &str) -> TeeResult<SealedEntry> {
        let entries = self.entries.read().await;
        entries.get(id)
            .cloned()
            .ok_or_else(|| TeeError::SealedStorageError(format!("Entry not found: {}", id)))
    }
    
    /// Check if an entry exists
    pub async fn exists(&self, id: &str) -> bool {
        let entries = self.entries.read().await;
        entries.contains_key(id)
    }
    
    /// Get storage statistics
    pub async fn get_stats(&self) -> TeeResult<SealedStorageStats> {
        let entries = self.entries.read().await;
        
        let total_entries = entries.len();
        let total_size = entries.values().map(|e| e.size).sum();
        
        let policy_counts = entries.values().fold(HashMap::new(), |mut acc, entry| {
            let policy_name = match &entry.policy {
                SealingPolicy::CurrentEnclave => "current_enclave",
                SealingPolicy::Signer => "signer",
                SealingPolicy::Both => "both",
                SealingPolicy::Custom(_) => "custom",
                SealingPolicy::Software => "software",
            };
            *acc.entry(policy_name.to_string()).or_insert(0) += 1;
            acc
        });
        
        Ok(SealedStorageStats {
            total_entries,
            total_size,
            policy_counts,
            storage_dir: self.storage_dir.display().to_string(),
        })
    }
    
    /// Actually perform the sealing operation
    async fn seal_data(&self, data: &[u8], policy: &SealingPolicy) -> TeeResult<SealedData> {
        // Get current platform measurements for sealing policy
        let policy_data = self.get_policy_data(policy).await?;
        
        // Generate a random nonce
        use rand::RngCore;
        let mut rng = rand::thread_rng();
        let mut nonce = vec![0u8; 12]; // GCM nonce size
        rng.fill_bytes(&mut nonce);
        
        // Derive sealing key from policy and additional data
        let sealing_key = self.derive_sealing_key(&policy_data, &nonce).await?;
        
        // Encrypt data using AES-GCM
        use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, NewAead}};
        let key = Key::from_slice(&sealing_key);
        let cipher = Aes256Gcm::new(key);
        let nonce_array = Nonce::from_slice(&nonce);
        
        let aad = self.config.additional_data.as_ref().map(|s| s.as_bytes()).unwrap_or(&[]);
        
        let ciphertext = cipher.encrypt(nonce_array, aead::Payload { msg: data, aad })
            .map_err(|e| TeeError::CryptoError(format!("Encryption failed: {}", e)))?;
        
        // Extract the authentication tag (last 16 bytes)
        let tag_start = ciphertext.len().saturating_sub(16);
        let (encrypted_data, tag) = ciphertext.split_at(tag_start);
        
        Ok(SealedData {
            ciphertext: encrypted_data.to_vec(),
            tag: tag.to_vec(),
            nonce,
            policy: policy_data,
            aad: if aad.is_empty() { None } else { Some(aad.to_vec()) },
        })
    }
    
    /// Actually perform the unsealing operation
    async fn unseal_data(&self, sealed_data: &SealedData, policy: &SealingPolicy) -> TeeResult<Vec<u8>> {
        // Verify current platform measurements match sealing policy
        let current_policy_data = self.get_policy_data(policy).await?;
        if current_policy_data != sealed_data.policy {
            return Err(TeeError::SealedStorageError(
                "Policy measurement mismatch - data cannot be unsealed".to_string()
            ));
        }
        
        // Derive the same sealing key
        let sealing_key = self.derive_sealing_key(&sealed_data.policy, &sealed_data.nonce).await?;
        
        // Reconstruct full ciphertext with tag
        let mut full_ciphertext = sealed_data.ciphertext.clone();
        full_ciphertext.extend_from_slice(&sealed_data.tag);
        
        // Decrypt data using AES-GCM
        use aes_gcm::{Aes256Gcm, Key, Nonce, aead::{Aead, NewAead}};
        let key = Key::from_slice(&sealing_key);
        let cipher = Aes256Gcm::new(key);
        let nonce_array = Nonce::from_slice(&sealed_data.nonce);
        
        let aad = sealed_data.aad.as_ref().map(|v| v.as_slice()).unwrap_or(&[]);
        
        let plaintext = cipher.decrypt(nonce_array, aead::Payload { msg: &full_ciphertext, aad })
            .map_err(|e| TeeError::CryptoError(format!("Decryption failed: {}", e)))?;
        
        Ok(plaintext)
    }
    
    /// Get policy data based on the sealing policy
    async fn get_policy_data(&self, policy: &SealingPolicy) -> TeeResult<Vec<u8>> {
        match policy {
            SealingPolicy::Software => {
                // For software mode, use a fixed policy
                Ok(b"software_sealing_policy".to_vec())
            }
            SealingPolicy::CurrentEnclave => {
                // Get current enclave measurement
                self.get_current_enclave_measurement().await
            }
            SealingPolicy::Signer => {
                // Get signer measurement
                self.get_signer_measurement().await
            }
            SealingPolicy::Both => {
                // Combine enclave and signer measurements
                let mut policy_data = self.get_current_enclave_measurement().await?;
                policy_data.extend_from_slice(&self.get_signer_measurement().await?);
                Ok(policy_data)
            }
            SealingPolicy::Custom(measurements) => {
                // Use custom measurements
                let serialized = bincode::serialize(measurements)
                    .map_err(|e| TeeError::SealedStorageError(format!("Policy serialization failed: {}", e)))?;
                Ok(serialized)
            }
        }
    }
    
    /// Get current enclave measurement (platform-specific)
    async fn get_current_enclave_measurement(&self) -> TeeResult<Vec<u8>> {
        // In a real implementation, this would call platform-specific APIs
        // For now, return a mock measurement
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(b"mock_enclave_measurement");
        hasher.update(std::process::id().to_be_bytes()); // Add some uniqueness
        Ok(hasher.finalize().to_vec())
    }
    
    /// Get signer measurement (platform-specific)
    async fn get_signer_measurement(&self) -> TeeResult<Vec<u8>> {
        // In a real implementation, this would call platform-specific APIs
        use sha2::{Sha256, Digest};
        let mut hasher = Sha256::new();
        hasher.update(b"mock_signer_measurement");
        Ok(hasher.finalize().to_vec())
    }
    
    /// Derive sealing key from policy data and nonce
    async fn derive_sealing_key(&self, policy_data: &[u8], nonce: &[u8]) -> TeeResult<Vec<u8>> {
        use hkdf::Hkdf;
        use sha2::Sha256;
        
        // Use HKDF to derive a sealing key from policy data
        let hk = Hkdf::<Sha256>::new(Some(nonce), policy_data);
        let mut key = [0u8; 32]; // 256-bit key
        let info = self.config.additional_data.as_ref()
            .map(|s| s.as_bytes())
            .unwrap_or(b"erebor_sealed_storage");
        
        hk.expand(info, &mut key)
            .map_err(|e| TeeError::CryptoError(format!("Key derivation failed: {}", e)))?;
        
        Ok(key.to_vec())
    }
    
    /// Get file path for sealed data
    fn get_data_path(&self, id: &str) -> PathBuf {
        self.storage_dir.join(format!("{}.sealed", id))
    }
    
    /// Get file path for metadata
    fn get_metadata_path(&self) -> PathBuf {
        self.storage_dir.join("metadata.json")
    }
    
    /// Load existing entries from metadata file
    async fn load_entries(&self) -> TeeResult<()> {
        let metadata_path = self.get_metadata_path();
        if !metadata_path.exists() {
            return Ok(());
        }
        
        let metadata_content = fs::read_to_string(&metadata_path).await
            .map_err(|e| TeeError::SealedStorageError(format!("Failed to read metadata: {}", e)))?;
        
        let entries: HashMap<String, SealedEntry> = serde_json::from_str(&metadata_content)
            .map_err(|e| TeeError::SealedStorageError(format!("Failed to parse metadata: {}", e)))?;
        
        let mut current_entries = self.entries.write().await;
        *current_entries = entries;
        
        debug!("Loaded {} sealed storage entries", current_entries.len());
        Ok(())
    }
    
    /// Save entries metadata to file
    async fn save_entries(&self) -> TeeResult<()> {
        let entries = self.entries.read().await;
        let metadata_content = serde_json::to_string_pretty(&*entries)
            .map_err(|e| TeeError::SealedStorageError(format!("Failed to serialize metadata: {}", e)))?;
        
        let metadata_path = self.get_metadata_path();
        fs::write(&metadata_path, metadata_content).await
            .map_err(|e| TeeError::SealedStorageError(format!("Failed to write metadata: {}", e)))?;
        
        Ok(())
    }
}

/// Sealed storage statistics
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedStorageStats {
    pub total_entries: usize,
    pub total_size: u64,
    pub policy_counts: HashMap<String, usize>,
    pub storage_dir: String,
}

/// Global sealed storage manager instance
static mut SEALED_STORAGE: Option<SealedStorageManager> = None;
static SEALED_INIT_LOCK: std::sync::Once = std::sync::Once::new();

/// Initialize the global sealed storage manager
pub async fn init_sealed_storage(config: &SealedStorageConfig) -> TeeResult<()> {
    let manager = SealedStorageManager::new(config.clone()).await?;
    
    unsafe {
        SEALED_INIT_LOCK.call_once(|| {
            SEALED_STORAGE = Some(manager);
        });
    }
    
    info!("Sealed storage initialized");
    Ok(())
}

/// Get the global sealed storage manager
pub fn get_sealed_storage() -> TeeResult<&'static SealedStorageManager> {
    unsafe {
        SEALED_STORAGE.as_ref()
            .ok_or_else(|| TeeError::ConfigError("Sealed storage not initialized".to_string()))
    }
}

/// Check if sealed storage is available
pub async fn check_sealed_storage() -> TeeResult<bool> {
    match get_sealed_storage() {
        Ok(_) => Ok(true),
        Err(_) => Ok(false),
    }
}

/// Seal data using the global manager
pub async fn seal_data(id: &str, data: &[u8], policy: SealingPolicy) -> TeeResult<()> {
    let manager = get_sealed_storage()?;
    manager.seal(id, data, policy).await
}

/// Unseal data using the global manager
pub async fn unseal_data(id: &str) -> TeeResult<Vec<u8>> {
    let manager = get_sealed_storage()?;
    manager.unseal(id).await
}

/// Delete sealed data using the global manager
pub async fn delete_sealed_data(id: &str) -> TeeResult<()> {
    let manager = get_sealed_storage()?;
    manager.delete(id).await
}

/// List all sealed entries using the global manager
pub async fn list_sealed_data() -> TeeResult<Vec<SealedEntry>> {
    let manager = get_sealed_storage()?;
    manager.list().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    
    fn create_test_config() -> SealedStorageConfig {
        let temp_dir = TempDir::new().unwrap();
        SealedStorageConfig {
            storage_dir: temp_dir.path().to_string_lossy().to_string(),
            kdf_rounds: 1000, // Reduced for tests
            additional_data: Some("test_aad".to_string()),
        }
    }
    
    #[tokio::test]
    async fn test_seal_unseal_data() {
        let config = create_test_config();
        let manager = SealedStorageManager::new(config).await.unwrap();
        
        let test_data = b"sensitive test data";
        let policy = SealingPolicy::Software;
        
        // Seal data
        manager.seal("test_key", test_data, policy.clone()).await.unwrap();
        
        // Verify entry exists
        assert!(manager.exists("test_key").await);
        
        // Get entry metadata
        let entry = manager.get_entry("test_key").await.unwrap();
        assert_eq!(entry.id, "test_key");
        assert_eq!(entry.size, test_data.len() as u64);
        
        // Unseal data
        let unsealed = manager.unseal("test_key").await.unwrap();
        assert_eq!(unsealed, test_data);
        
        // List entries
        let entries = manager.list().await.unwrap();
        assert_eq!(entries.len(), 1);
        assert_eq!(entries[0].id, "test_key");
        
        // Delete entry
        manager.delete("test_key").await.unwrap();
        assert!(!manager.exists("test_key").await);
    }
    
    #[tokio::test]
    async fn test_sealing_policies() {
        let config = create_test_config();
        let manager = SealedStorageManager::new(config).await.unwrap();
        
        let test_data = b"policy test data";
        
        // Test different policies
        let policies = vec![
            ("software", SealingPolicy::Software),
            ("current_enclave", SealingPolicy::CurrentEnclave),
            ("signer", SealingPolicy::Signer),
            ("both", SealingPolicy::Both),
        ];
        
        for (name, policy) in policies {
            let key_id = format!("policy_test_{}", name);
            manager.seal(&key_id, test_data, policy).await.unwrap();
            
            let unsealed = manager.unseal(&key_id).await.unwrap();
            assert_eq!(unsealed, test_data, "Policy {} failed", name);
        }
        
        // Test custom policy
        let mut custom_measurements = HashMap::new();
        custom_measurements.insert("test_measurement".to_string(), "test_value".to_string());
        let custom_policy = SealingPolicy::Custom(custom_measurements);
        
        manager.seal("custom_test", test_data, custom_policy).await.unwrap();
        let unsealed = manager.unseal("custom_test").await.unwrap();
        assert_eq!(unsealed, test_data);
    }
    
    #[tokio::test]
    async fn test_storage_stats() {
        let config = create_test_config();
        let manager = SealedStorageManager::new(config).await.unwrap();
        
        // Add some test data
        manager.seal("test1", b"data1", SealingPolicy::Software).await.unwrap();
        manager.seal("test2", b"longer_data2", SealingPolicy::CurrentEnclave).await.unwrap();
        manager.seal("test3", b"data3", SealingPolicy::Software).await.unwrap();
        
        let stats = manager.get_stats().await.unwrap();
        assert_eq!(stats.total_entries, 3);
        assert_eq!(stats.total_size, 5 + 12 + 5); // Sum of data sizes
        assert_eq!(stats.policy_counts.get("software"), Some(&2));
        assert_eq!(stats.policy_counts.get("current_enclave"), Some(&1));
    }
    
    #[tokio::test]
    async fn test_persistence() {
        let temp_dir = TempDir::new().unwrap();
        let config = SealedStorageConfig {
            storage_dir: temp_dir.path().to_string_lossy().to_string(),
            kdf_rounds: 1000,
            additional_data: None,
        };
        
        // Create first manager and seal data
        {
            let manager = SealedStorageManager::new(config.clone()).await.unwrap();
            manager.seal("persistent_test", b"persistent data", SealingPolicy::Software).await.unwrap();
        }
        
        // Create second manager and verify data persists
        {
            let manager = SealedStorageManager::new(config).await.unwrap();
            assert!(manager.exists("persistent_test").await);
            
            let unsealed = manager.unseal("persistent_test").await.unwrap();
            assert_eq!(unsealed, b"persistent data");
        }
    }
}