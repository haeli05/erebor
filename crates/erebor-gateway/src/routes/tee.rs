//! TEE (Trusted Execution Environment) API routes

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use erebor_tee::{
    attestation::{AttestationProvider, AttestationRequest, AttestationVerifier},
    TeeResult, TeeStatus, AttestationReport,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::{error::ApiError, state::AppState};
use tracing::{error, info};

/// Attestation request payload
#[derive(Debug, Deserialize)]
pub struct AttestRequest {
    /// Platform type (sgx, nitro, software)
    pub platform: String,
    /// Report data/nonce to include
    pub report_data: Option<String>,
    /// Additional context
    pub context: Option<HashMap<String, serde_json::Value>>,
}

/// Attestation verification request
#[derive(Debug, Deserialize)]
pub struct VerifyAttestationRequest {
    /// Base64-encoded attestation report
    pub report: String,
    /// Platform type
    pub platform: String,
    /// Expected measurements
    pub expected_measurements: Option<HashMap<String, String>>,
}

/// Attestation response
#[derive(Debug, Serialize)]
pub struct AttestationResponse {
    /// Success status
    pub success: bool,
    /// Platform type
    pub platform: String,
    /// Base64-encoded attestation report
    pub report: Option<String>,
    /// Verification result
    pub verified: Option<bool>,
    /// Error message if failed
    pub error: Option<String>,
    /// Additional metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Query parameters for attestation list
#[derive(Debug, Deserialize)]
pub struct AttestationQuery {
    /// Platform filter
    pub platform: Option<String>,
    /// Limit number of results
    pub limit: Option<u32>,
}

/// TEE routes
pub fn tee_router() -> Router<AppState> {
    Router::new()
        .route("/v1/tee/status", get(get_tee_status))
        .route("/v1/tee/attest", post(create_attestation))
        .route("/v1/tee/verify", post(verify_attestation))
        .route("/v1/tee/reports", get(list_attestation_reports))
}

/// Get TEE system status
async fn get_tee_status(
    State(_state): State<AppState>,
) -> Result<Json<TeeStatus>, ApiError> {
    info!("Getting TEE status");
    
    match erebor_tee::get_tee_status().await {
        Ok(status) => {
            info!("TEE status retrieved successfully");
            Ok(Json(status))
        }
        Err(e) => {
            error!("Failed to get TEE status: {}", e);
            Err(ApiError::Internal(format!("Failed to get TEE status: {}", e)))
        }
    }
}

/// Create attestation report
async fn create_attestation(
    State(_state): State<AppState>,
    Json(request): Json<AttestRequest>,
) -> Result<Json<AttestationResponse>, ApiError> {
    info!("Creating attestation for platform: {}", request.platform);
    
    // Decode report data if provided
    let report_data = if let Some(data) = request.report_data {
        base64::decode(&data)
            .map_err(|e| ApiError::BadRequest(format!("Invalid base64 report data: {}", e)))?
    } else {
        // Generate random nonce if no report data provided
        use rand::RngCore;
        let mut nonce = [0u8; 32];
        rand::thread_rng().fill_bytes(&mut nonce);
        nonce.to_vec()
    };
    
    let attest_request = AttestationRequest {
        platform: request.platform.clone(),
        report_data,
        context: request.context.unwrap_or_default(),
    };
    
    match AttestationProvider::create_attestation(attest_request).await {
        Ok(report) => {
            info!("Attestation created successfully for platform: {}", request.platform);
            
            // Encode report to base64
            let encoded_report = base64::encode(&report.attestation_data);
            
            let mut metadata = HashMap::new();
            metadata.insert("timestamp".to_string(), 
                           serde_json::json!(report.timestamp.to_rfc3339()));
            metadata.insert("claims".to_string(), 
                           serde_json::json!(report.claims));
            
            Ok(Json(AttestationResponse {
                success: true,
                platform: report.platform,
                report: Some(encoded_report),
                verified: None,
                error: None,
                metadata,
            }))
        }
        Err(e) => {
            error!("Failed to create attestation: {}", e);
            Ok(Json(AttestationResponse {
                success: false,
                platform: request.platform,
                report: None,
                verified: None,
                error: Some(e.to_string()),
                metadata: HashMap::new(),
            }))
        }
    }
}

/// Verify attestation report
async fn verify_attestation(
    State(_state): State<AppState>,
    Json(request): Json<VerifyAttestationRequest>,
) -> Result<Json<AttestationResponse>, ApiError> {
    info!("Verifying attestation for platform: {}", request.platform);
    
    // Decode the attestation report
    let report_data = base64::decode(&request.report)
        .map_err(|e| ApiError::BadRequest(format!("Invalid base64 report: {}", e)))?;
    
    // Create attestation report structure
    let report = AttestationReport {
        platform: request.platform.clone(),
        report_data: vec![], // Will be filled by verifier
        attestation_data: report_data,
        certificate_chain: None,
        timestamp: chrono::Utc::now(),
        claims: HashMap::new(),
    };
    
    let expected_measurements = request.expected_measurements.unwrap_or_default();
    
    match AttestationVerifier::verify_attestation(&report, &expected_measurements).await {
        Ok(verified) => {
            info!("Attestation verification completed for platform: {} (verified: {})", 
                  request.platform, verified);
            
            let mut metadata = HashMap::new();
            metadata.insert("verification_time".to_string(), 
                           serde_json::json!(chrono::Utc::now().to_rfc3339()));
            
            Ok(Json(AttestationResponse {
                success: true,
                platform: request.platform,
                report: Some(request.report),
                verified: Some(verified),
                error: None,
                metadata,
            }))
        }
        Err(e) => {
            error!("Failed to verify attestation: {}", e);
            Ok(Json(AttestationResponse {
                success: false,
                platform: request.platform,
                report: Some(request.report),
                verified: Some(false),
                error: Some(e.to_string()),
                metadata: HashMap::new(),
            }))
        }
    }
}

/// List attestation reports (placeholder - would integrate with database)
async fn list_attestation_reports(
    State(_state): State<AppState>,
    Query(params): Query<AttestationQuery>,
) -> Result<Json<Vec<AttestationResponse>>, ApiError> {
    info!("Listing attestation reports (platform: {:?}, limit: {:?})", 
          params.platform, params.limit);
    
    // This is a placeholder implementation
    // In a real system, this would query a database of stored attestation reports
    let reports = vec![
        AttestationResponse {
            success: true,
            platform: params.platform.unwrap_or_else(|| "software".to_string()),
            report: None,
            verified: Some(true),
            error: None,
            metadata: {
                let mut m = HashMap::new();
                m.insert("id".to_string(), serde_json::json!("example-1"));
                m.insert("created".to_string(), 
                        serde_json::json!(chrono::Utc::now().to_rfc3339()));
                m
            },
        }
    ];
    
    let limit = params.limit.unwrap_or(50) as usize;
    let limited_reports = reports.into_iter().take(limit).collect();
    
    Ok(Json(limited_reports))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;
    
    async fn create_test_app() -> Router {
        let state = AppState::new().expect("Failed to create test state");
        tee_router().with_state(state)
    }
    
    #[tokio::test]
    async fn test_tee_status() {
        let app = create_test_app().await;
        
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/tee/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        
        assert_eq!(response.status(), StatusCode::OK);
    }
    
    #[tokio::test]
    async fn test_create_attestation() {
        let app = create_test_app().await;
        
        let request_body = serde_json::json!({
            "platform": "software"
        });
        
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/tee/attest")
                    .header("content-type", "application/json")
                    .body(Body::from(request_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        
        assert_eq!(response.status(), StatusCode::OK);
    }
}