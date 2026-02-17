//! # Attestation Framework
//!
//! This module provides a generic attestation framework for verifying that code
//! is running inside genuine TEE environments.

use crate::{AttestationConfig, AttestationReport, TeeError, TeeResult};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::time::{SystemTime, UNIX_EPOCH};
use tracing::{debug, info, warn};

/// Attestation provider trait for different TEE platforms
#[async_trait::async_trait]
pub trait AttestationProvider: Send + Sync {
    /// Generate an attestation report for the current environment
    async fn generate_report(&self, report_data: &[u8]) -> TeeResult<AttestationReport>;
    
    /// Verify an attestation report from a remote TEE
    async fn verify_report(&self, report: &AttestationReport) -> TeeResult<AttestationClaims>;
    
    /// Get platform-specific attestation metadata
    fn get_platform(&self) -> &str;
    
    /// Check if attestation is supported in current environment
    fn is_supported(&self) -> bool;
}

/// Attestation claims extracted from a verified report
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AttestationClaims {
    /// Platform type (sgx, nitro, etc.)
    pub platform: String,
    
    /// Enclave/environment measurements
    pub measurements: HashMap<String, String>,
    
    /// Security version numbers
    pub security_versions: HashMap<String, u32>,
    
    /// Product ID
    pub product_id: Option<u64>,
    
    /// Enclave debug mode
    pub debug_mode: bool,
    
    /// Attestation timestamp
    pub timestamp: chrono::DateTime<chrono::Utc>,
    
    /// Additional platform-specific claims
    pub additional_claims: HashMap<String, serde_json::Value>,
}

/// Main attestation manager
pub struct AttestationManager {
    config: AttestationConfig,
    provider: Box<dyn AttestationProvider>,
}

impl AttestationManager {
    /// Create a new attestation manager with the given configuration
    pub async fn new(config: AttestationConfig) -> TeeResult<Self> {
        let provider = create_attestation_provider(&config.tee_type)?;
        
        if !provider.is_supported() {
            return Err(TeeError::UnsupportedPlatform);
        }
        
        Ok(Self { config, provider })
    }
    
    /// Generate an attestation report for the current environment
    pub async fn attest(&self, nonce: Option<&[u8]>) -> TeeResult<AttestationReport> {
        let report_data = nonce.unwrap_or(&[0u8; 32]);
        
        info!(
            platform = %self.provider.get_platform(),
            "Generating attestation report"
        );
        
        let report = self.provider.generate_report(report_data).await?;
        
        debug!(
            platform = %report.platform,
            timestamp = %report.timestamp,
            "Attestation report generated"
        );
        
        Ok(report)
    }
    
    /// Verify an attestation report from a remote TEE
    pub async fn verify(&self, report: &AttestationReport) -> TeeResult<AttestationClaims> {
        info!(
            platform = %report.platform,
            timestamp = %report.timestamp,
            "Verifying attestation report"
        );
        
        // Check report age
        let report_age = chrono::Utc::now()
            .signed_duration_since(report.timestamp)
            .num_seconds() as u64;
            
        if report_age > self.config.max_report_age {
            return Err(TeeError::InvalidAttestation(
                format!("Report too old: {} seconds", report_age)
            ));
        }
        
        // Verify platform matches
        if report.platform != self.provider.get_platform() && self.provider.get_platform() != "software" {
            return Err(TeeError::InvalidAttestation(
                format!("Platform mismatch: expected {}, got {}", 
                    self.provider.get_platform(), report.platform)
            ));
        }
        
        // Delegate to platform-specific verification
        let claims = self.provider.verify_report(report).await?;
        
        // Verify expected measurements if configured
        self.verify_measurements(&claims)?;
        
        // Check debug mode if in production
        if claims.debug_mode && self.config.require_attestation {
            warn!("Debug mode enclave detected in production environment");
            return Err(TeeError::InvalidAttestation(
                "Debug mode not allowed in production".to_string()
            ));
        }
        
        info!(
            platform = %claims.platform,
            debug_mode = claims.debug_mode,
            "Attestation report verified successfully"
        );
        
        Ok(claims)
    }
    
    /// Verify that measurements match expected values
    fn verify_measurements(&self, claims: &AttestationClaims) -> TeeResult<()> {
        for (key, expected) in &self.config.expected_measurements {
            if let Some(actual) = claims.measurements.get(key) {
                if actual != expected {
                    return Err(TeeError::InvalidAttestation(
                        format!("Measurement mismatch for {}: expected {}, got {}", 
                            key, expected, actual)
                    ));
                }
            } else if !expected.is_empty() {
                return Err(TeeError::InvalidAttestation(
                    format!("Missing expected measurement: {}", key)
                ));
            }
        }
        
        Ok(())
    }
    
    /// Get attestation configuration
    pub fn config(&self) -> &AttestationConfig {
        &self.config
    }
    
    /// Get platform name
    pub fn platform(&self) -> &str {
        self.provider.get_platform()
    }
}

/// Software attestation provider for testing and development
pub struct SoftwareAttestationProvider;

#[async_trait::async_trait]
impl AttestationProvider for SoftwareAttestationProvider {
    async fn generate_report(&self, report_data: &[u8]) -> TeeResult<AttestationReport> {
        let timestamp = chrono::Utc::now();
        
        // Create a mock attestation report
        let mut claims = HashMap::new();
        claims.insert("environment".to_string(), serde_json::Value::String("software".to_string()));
        claims.insert("version".to_string(), serde_json::Value::String("1.0.0".to_string()));
        
        Ok(AttestationReport {
            platform: "software".to_string(),
            report_data: report_data.to_vec(),
            attestation_data: b"mock_attestation_data".to_vec(),
            certificate_chain: None,
            timestamp,
            claims,
        })
    }
    
    async fn verify_report(&self, report: &AttestationReport) -> TeeResult<AttestationClaims> {
        if report.platform != "software" {
            return Err(TeeError::InvalidAttestation(
                "Invalid platform for software attestation".to_string()
            ));
        }
        
        let mut measurements = HashMap::new();
        measurements.insert("mrenclave".to_string(), "software_measurement".to_string());
        measurements.insert("mrsigner".to_string(), "software_signer".to_string());
        
        let mut security_versions = HashMap::new();
        security_versions.insert("cpu_svn".to_string(), 1);
        security_versions.insert("isv_svn".to_string(), 1);
        
        Ok(AttestationClaims {
            platform: "software".to_string(),
            measurements,
            security_versions,
            product_id: Some(0),
            debug_mode: true,
            timestamp: report.timestamp,
            additional_claims: report.claims.clone(),
        })
    }
    
    fn get_platform(&self) -> &str {
        "software"
    }
    
    fn is_supported(&self) -> bool {
        true
    }
}

/// Create an attestation provider for the specified platform
fn create_attestation_provider(platform: &str) -> TeeResult<Box<dyn AttestationProvider>> {
    match platform.to_lowercase().as_str() {
        "software" => Ok(Box::new(SoftwareAttestationProvider)),
        
        #[cfg(feature = "sgx")]
        "sgx" => {
            use crate::sgx::SgxAttestationProvider;
            Ok(Box::new(SgxAttestationProvider::new()?))
        },
        
        #[cfg(feature = "nitro")]
        "nitro" => {
            use crate::nitro::NitroAttestationProvider;
            Ok(Box::new(NitroAttestationProvider::new()?))
        },
        
        _ => Err(TeeError::UnsupportedPlatform),
    }
}

/// Global attestation manager instance
static mut ATTESTATION_MANAGER: Option<AttestationManager> = None;
static INIT_LOCK: std::sync::Once = std::sync::Once::new();

/// Initialize the global attestation manager
pub async fn init_attestation(config: &AttestationConfig) -> TeeResult<()> {
    let manager = AttestationManager::new(config.clone()).await?;
    
    unsafe {
        INIT_LOCK.call_once(|| {
            ATTESTATION_MANAGER = Some(manager);
        });
    }
    
    info!("Attestation manager initialized");
    Ok(())
}

/// Get the global attestation manager
pub fn get_attestation_manager() -> TeeResult<&'static AttestationManager> {
    unsafe {
        ATTESTATION_MANAGER.as_ref()
            .ok_or_else(|| TeeError::ConfigError("Attestation manager not initialized".to_string()))
    }
}

/// Generate an attestation report using the global manager
pub async fn generate_attestation_report(nonce: Option<&[u8]>) -> TeeResult<AttestationReport> {
    let manager = get_attestation_manager()?;
    manager.attest(nonce).await
}

/// Verify an attestation report using the global manager
pub async fn verify_attestation_report(report: &AttestationReport) -> TeeResult<AttestationClaims> {
    let manager = get_attestation_manager()?;
    manager.verify(report).await
}

/// Utility function to create a nonce from current timestamp and random data
pub fn create_nonce() -> Vec<u8> {
    let mut nonce = Vec::with_capacity(32);
    
    // Add timestamp
    let timestamp = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_secs();
    nonce.extend_from_slice(&timestamp.to_be_bytes());
    
    // Add random data
    use rand::RngCore;
    let mut rng = rand::thread_rng();
    let mut random_bytes = [0u8; 24];
    rng.fill_bytes(&mut random_bytes);
    nonce.extend_from_slice(&random_bytes);
    
    nonce
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashMap;
    
    fn create_test_config() -> AttestationConfig {
        AttestationConfig {
            tee_type: "software".to_string(),
            require_attestation: false,
            max_report_age: 3600,
            trusted_roots: vec![],
            expected_measurements: HashMap::new(),
        }
    }
    
    #[tokio::test]
    async fn test_software_attestation() {
        let config = create_test_config();
        let manager = AttestationManager::new(config).await.unwrap();
        
        // Generate report
        let nonce = create_nonce();
        let report = manager.attest(Some(&nonce)).await.unwrap();
        
        assert_eq!(report.platform, "software");
        assert_eq!(report.report_data, nonce);
        
        // Verify report
        let claims = manager.verify(&report).await.unwrap();
        assert_eq!(claims.platform, "software");
        assert!(claims.debug_mode);
    }
    
    #[tokio::test]
    async fn test_report_age_validation() {
        let config = AttestationConfig {
            max_report_age: 1, // 1 second
            ..create_test_config()
        };
        let manager = AttestationManager::new(config).await.unwrap();
        
        // Create an old report
        let mut report = AttestationReport {
            platform: "software".to_string(),
            report_data: vec![],
            attestation_data: vec![],
            certificate_chain: None,
            timestamp: chrono::Utc::now() - chrono::Duration::seconds(10),
            claims: HashMap::new(),
        };
        
        // Should fail due to age
        tokio::time::sleep(tokio::time::Duration::from_secs(2)).await;
        let result = manager.verify(&report).await;
        assert!(result.is_err());
    }
    
    #[tokio::test]
    async fn test_measurement_verification() {
        let mut expected_measurements = HashMap::new();
        expected_measurements.insert("mrenclave".to_string(), "expected_measurement".to_string());
        
        let config = AttestationConfig {
            expected_measurements,
            ..create_test_config()
        };
        let manager = AttestationManager::new(config).await.unwrap();
        
        let report = AttestationReport {
            platform: "software".to_string(),
            report_data: vec![],
            attestation_data: vec![],
            certificate_chain: None,
            timestamp: chrono::Utc::now(),
            claims: HashMap::new(),
        };
        
        // Should fail due to measurement mismatch
        let result = manager.verify(&report).await;
        assert!(result.is_err());
    }
    
    #[test]
    fn test_create_nonce() {
        let nonce1 = create_nonce();
        let nonce2 = create_nonce();
        
        assert_eq!(nonce1.len(), 32);
        assert_eq!(nonce2.len(), 32);
        assert_ne!(nonce1, nonce2); // Should be different due to timestamp and randomness
    }
}