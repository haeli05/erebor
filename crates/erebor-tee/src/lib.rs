//! # Erebor TEE (Trusted Execution Environment) Support
//!
//! This crate provides comprehensive TEE support for the Erebor key management system,
//! including attestation frameworks, HSM integration, and sealed storage capabilities.
//!
//! ## Features
//!
//! - **Attestation Framework**: Verify code execution inside genuine TEEs
//! - **SGX Support**: Intel SGX DCAP-based remote attestation
//! - **AWS Nitro Enclaves**: Attestation document verification with PCR validation
//! - **Sealed Storage**: Encrypt data that can only be decrypted within the same TEE
//! - **HSM Integration**: PKCS#11 interface for hardware security modules
//! - **Key Protection**: Wrap vault keys for TEE-bound decryption
//!
//! ## Architecture
//!
//! ```text
//! ┌─────────────────┐    ┌─────────────────┐    ┌─────────────────┐
//! │   Application   │    │   HSM Provider  │    │  TEE Attestation│
//! │                 │    │                 │    │                 │
//! │ ┌─────────────┐ │    │ ┌─────────────┐ │    │ ┌─────────────┐ │
//! │ │ Key Wrapper │ │────│ │   PKCS#11   │ │    │ │ SGX/Nitro   │ │
//! │ └─────────────┘ │    │ └─────────────┘ │    │ │ Validator   │ │
//! │                 │    │                 │    │ └─────────────┘ │
//! │ ┌─────────────┐ │    │ ┌─────────────┐ │    │                 │
//! │ │Sealed Store │ │    │ │Key Hierarchy│ │    │ ┌─────────────┐ │
//! │ └─────────────┘ │    │ └─────────────┘ │    │ │   Report    │ │
//! └─────────────────┘    └─────────────────┘    │ │ Verification│ │
//!                                               │ └─────────────┘ │
//!                                               └─────────────────┘
//! ```

pub mod attestation;
pub mod hsm;
pub mod sealed;

#[cfg(feature = "sgx")]
pub mod sgx;

#[cfg(feature = "nitro")]
pub mod nitro;

use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use thiserror::Error;
use zeroize::Zeroize;

/// Common error types for TEE operations
#[derive(Debug, Error)]
pub enum TeeError {
    #[error("Attestation failed: {0}")]
    AttestationFailed(String),
    
    #[error("HSM operation failed: {0}")]
    HsmError(String),
    
    #[error("Sealed storage error: {0}")]
    SealedStorageError(String),
    
    #[error("Key wrapping failed: {0}")]
    KeyWrappingError(String),
    
    #[error("Cryptographic operation failed: {0}")]
    CryptoError(String),
    
    #[error("Invalid attestation report: {0}")]
    InvalidAttestation(String),
    
    #[error("Certificate validation failed: {0}")]
    CertificateError(String),
    
    #[error("TEE not supported on this platform")]
    UnsupportedPlatform,
    
    #[error("Configuration error: {0}")]
    ConfigError(String),
    
    #[error("I/O error: {0}")]
    IoError(#[from] std::io::Error),
    
    #[error("JSON error: {0}")]
    JsonError(#[from] serde_json::Error),
}

/// Result type for TEE operations
pub type TeeResult<T> = Result<T, TeeError>;

/// Configuration for TEE services
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeeConfig {
    /// HSM configuration
    pub hsm: HsmConfig,
    
    /// Attestation configuration
    pub attestation: AttestationConfig,
    
    /// Sealed storage configuration
    pub sealed_storage: SealedStorageConfig,
}

/// HSM configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct HsmConfig {
    /// HSM provider type
    pub provider: String,
    
    /// PKCS#11 library path (for PKCS#11 providers)
    pub pkcs11_library: Option<String>,
    
    /// Slot ID for PKCS#11 operations
    pub slot_id: Option<u64>,
    
    /// Token label
    pub token_label: Option<String>,
    
    /// User PIN (will be zeroized)
    #[serde(skip_serializing)]
    pub pin: Option<String>,
    
    /// Additional provider-specific configuration
    pub config: HashMap<String, String>,
}

impl Drop for HsmConfig {
    fn drop(&mut self) {
        if let Some(ref mut pin) = self.pin {
            pin.zeroize();
        }
    }
}

/// Attestation configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationConfig {
    /// TEE type (sgx, nitro, software)
    pub tee_type: String,
    
    /// Require valid attestation for operations
    pub require_attestation: bool,
    
    /// Maximum age for attestation reports (seconds)
    pub max_report_age: u64,
    
    /// Trusted root certificates for attestation verification
    pub trusted_roots: Vec<String>,
    
    /// Expected enclave measurements (for SGX/Nitro)
    pub expected_measurements: HashMap<String, String>,
}

/// Sealed storage configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedStorageConfig {
    /// Storage directory for sealed data
    pub storage_dir: String,
    
    /// Key derivation parameters
    pub kdf_rounds: u32,
    
    /// Additional authenticated data for sealing
    pub additional_data: Option<String>,
}

/// Attestation report containing TEE verification data
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationReport {
    /// TEE platform type
    pub platform: String,
    
    /// Report data/nonce
    pub report_data: Vec<u8>,
    
    /// Platform-specific attestation data
    pub attestation_data: Vec<u8>,
    
    /// Certificate chain (if applicable)
    pub certificate_chain: Option<Vec<Vec<u8>>>,
    
    /// Timestamp of report generation
    pub timestamp: chrono::DateTime<chrono::Utc>,
    
    /// Additional claims
    pub claims: HashMap<String, serde_json::Value>,
}

/// Key wrapping result
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WrappedKey {
    /// Encrypted key data
    pub encrypted_key: Vec<u8>,
    
    /// Wrapping algorithm used
    pub algorithm: String,
    
    /// Key identifier in HSM
    pub key_id: String,
    
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

impl Zeroize for WrappedKey {
    fn zeroize(&mut self) {
        self.encrypted_key.zeroize();
        self.key_id.zeroize();
    }
}

/// Sealed data container
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SealedData {
    /// Encrypted data
    pub ciphertext: Vec<u8>,
    
    /// Authentication tag
    pub tag: Vec<u8>,
    
    /// Nonce/IV
    pub nonce: Vec<u8>,
    
    /// Sealing policy/measurement
    pub policy: Vec<u8>,
    
    /// Additional authenticated data
    pub aad: Option<Vec<u8>>,
}

impl Zeroize for SealedData {
    fn zeroize(&mut self) {
        self.ciphertext.zeroize();
        self.tag.zeroize();
        self.nonce.zeroize();
        self.policy.zeroize();
        if let Some(ref mut aad) = self.aad {
            aad.zeroize();
        }
    }
}

/// TEE capabilities and status
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TeeStatus {
    /// TEE platform available
    pub available: bool,
    
    /// Platform type
    pub platform: String,
    
    /// Attestation support
    pub attestation_supported: bool,
    
    /// HSM connectivity
    pub hsm_connected: bool,
    
    /// Sealed storage available
    pub sealed_storage_available: bool,
    
    /// Last attestation time
    pub last_attestation: Option<chrono::DateTime<chrono::Utc>>,
    
    /// Error messages (if any)
    pub errors: Vec<String>,
}

/// Initialize TEE services with given configuration
pub async fn init_tee(config: TeeConfig) -> TeeResult<()> {
    tracing::info!("Initializing TEE services");
    
    // Initialize HSM
    hsm::init_hsm(&config.hsm).await?;
    
    // Initialize attestation
    attestation::init_attestation(&config.attestation).await?;
    
    // Initialize sealed storage
    sealed::init_sealed_storage(&config.sealed_storage).await?;
    
    tracing::info!("TEE services initialized successfully");
    Ok(())
}

/// Get current TEE status
pub async fn get_tee_status() -> TeeResult<TeeStatus> {
    let mut status = TeeStatus {
        available: false,
        platform: "unknown".to_string(),
        attestation_supported: false,
        hsm_connected: false,
        sealed_storage_available: false,
        last_attestation: None,
        errors: vec![],
    };
    
    // Check platform availability
    match detect_tee_platform() {
        Ok(platform) => {
            status.available = true;
            status.platform = platform;
            status.attestation_supported = true;
        }
        Err(e) => {
            status.errors.push(format!("TEE detection failed: {}", e));
        }
    }
    
    // Check HSM connectivity
    match hsm::check_hsm_status().await {
        Ok(connected) => status.hsm_connected = connected,
        Err(e) => status.errors.push(format!("HSM check failed: {}", e)),
    }
    
    // Check sealed storage
    match sealed::check_sealed_storage().await {
        Ok(available) => status.sealed_storage_available = available,
        Err(e) => status.errors.push(format!("Sealed storage check failed: {}", e)),
    }
    
    Ok(status)
}

/// Detect TEE platform type
fn detect_tee_platform() -> TeeResult<String> {
    // Check for SGX
    #[cfg(feature = "sgx")]
    {
        if sgx::is_sgx_available()? {
            return Ok("sgx".to_string());
        }
    }
    
    // Check for AWS Nitro Enclaves
    #[cfg(feature = "nitro")]
    {
        if nitro::is_nitro_available()? {
            return Ok("nitro".to_string());
        }
    }
    
    // Fall back to software implementation
    Ok("software".to_string())
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::TempDir;
    
    fn create_test_config() -> TeeConfig {
        let temp_dir = TempDir::new().unwrap();
        
        TeeConfig {
            hsm: HsmConfig {
                provider: "software".to_string(),
                pkcs11_library: None,
                slot_id: None,
                token_label: None,
                pin: None,
                config: HashMap::new(),
            },
            attestation: AttestationConfig {
                tee_type: "software".to_string(),
                require_attestation: false,
                max_report_age: 3600,
                trusted_roots: vec![],
                expected_measurements: HashMap::new(),
            },
            sealed_storage: SealedStorageConfig {
                storage_dir: temp_dir.path().to_string_lossy().to_string(),
                kdf_rounds: 100000,
                additional_data: None,
            },
        }
    }
    
    #[tokio::test]
    async fn test_tee_status() {
        let status = get_tee_status().await.unwrap();
        assert!(!status.platform.is_empty());
    }
    
    #[tokio::test]
    async fn test_detect_platform() {
        let platform = detect_tee_platform().unwrap();
        assert_eq!(platform, "software");
    }
}