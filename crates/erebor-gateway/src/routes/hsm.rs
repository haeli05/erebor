//! HSM (Hardware Security Module) API routes

use axum::{
    extract::{Path, Query, State},
    http::StatusCode,
    response::Json,
    routing::{get, post},
    Router,
};
use erebor_tee::{
    hsm::{HsmProvider, HsmStatus},
    TeeResult, WrappedKey,
};
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use crate::{error::ApiError, state::AppState};
use tracing::{error, info, warn};
use zeroize::Zeroize;

/// HSM key wrapping request
#[derive(Debug, Deserialize)]
pub struct WrapKeyRequest {
    /// Base64-encoded key data to wrap
    pub key_data: String,
    /// Key algorithm/type
    pub algorithm: String,
    /// HSM key ID to use for wrapping
    pub wrapping_key_id: Option<String>,
    /// Additional metadata
    pub metadata: Option<HashMap<String, String>>,
}

/// HSM key unwrapping request
#[derive(Debug, Deserialize)]
pub struct UnwrapKeyRequest {
    /// Base64-encoded wrapped key data
    pub wrapped_key: String,
    /// Key ID used for wrapping
    pub key_id: String,
    /// Wrapping algorithm used
    pub algorithm: String,
}

/// HSM key generation request
#[derive(Debug, Deserialize)]
pub struct GenerateKeyRequest {
    /// Key type (aes256, rsa2048, ec-p256, etc.)
    pub key_type: String,
    /// Key label/name
    pub label: String,
    /// Whether key is extractable
    pub extractable: bool,
    /// Key attributes
    pub attributes: Option<HashMap<String, serde_json::Value>>,
}

/// HSM signing request
#[derive(Debug, Deserialize)]
pub struct SignRequest {
    /// Key ID to use for signing
    pub key_id: String,
    /// Base64-encoded data to sign
    pub data: String,
    /// Signature algorithm
    pub algorithm: String,
}

/// HSM response wrapper
#[derive(Debug, Serialize)]
pub struct HsmResponse<T> {
    /// Success status
    pub success: bool,
    /// Response data
    pub data: Option<T>,
    /// Error message if failed
    pub error: Option<String>,
    /// Additional metadata
    pub metadata: HashMap<String, serde_json::Value>,
}

/// Key wrapping response
#[derive(Debug, Serialize)]
pub struct WrapKeyResponse {
    /// Base64-encoded wrapped key
    pub wrapped_key: String,
    /// Key ID in HSM
    pub key_id: String,
    /// Algorithm used
    pub algorithm: String,
    /// Additional metadata
    pub metadata: HashMap<String, String>,
}

/// Key unwrapping response (careful with sensitive data)
#[derive(Debug, Serialize)]
pub struct UnwrapKeyResponse {
    /// Success indicator (actual key not returned for security)
    pub success: bool,
    /// Key size/length
    pub key_size: usize,
    /// Algorithm
    pub algorithm: String,
}

/// Key generation response
#[derive(Debug, Serialize)]
pub struct GenerateKeyResponse {
    /// Generated key ID
    pub key_id: String,
    /// Key type
    pub key_type: String,
    /// Key label
    pub label: String,
    /// Public key (if applicable, base64-encoded)
    pub public_key: Option<String>,
}

/// Signature response
#[derive(Debug, Serialize)]
pub struct SignResponse {
    /// Base64-encoded signature
    pub signature: String,
    /// Algorithm used
    pub algorithm: String,
    /// Key ID used
    pub key_id: String,
}

/// Query parameters for HSM operations
#[derive(Debug, Deserialize)]
pub struct HsmQuery {
    /// Provider filter
    pub provider: Option<String>,
    /// Limit number of results
    pub limit: Option<u32>,
}

/// HSM routes
pub fn hsm_router() -> Router<AppState> {
    Router::new()
        .route("/v1/hsm/status", get(get_hsm_status))
        .route("/v1/hsm/wrap", post(wrap_key))
        .route("/v1/hsm/unwrap", post(unwrap_key))
        .route("/v1/hsm/generate", post(generate_key))
        .route("/v1/hsm/sign", post(sign_data))
        .route("/v1/hsm/keys", get(list_keys))
        .route("/v1/hsm/keys/:key_id", get(get_key_info))
}

/// Get HSM status
async fn get_hsm_status(
    State(_state): State<AppState>,
) -> Result<Json<HsmResponse<HsmStatus>>, ApiError> {
    info!("Getting HSM status");
    
    match erebor_tee::hsm::get_hsm_status().await {
        Ok(status) => {
            info!("HSM status retrieved successfully");
            Ok(Json(HsmResponse {
                success: true,
                data: Some(status),
                error: None,
                metadata: {
                    let mut m = HashMap::new();
                    m.insert("timestamp".to_string(), 
                           serde_json::json!(chrono::Utc::now().to_rfc3339()));
                    m
                },
            }))
        }
        Err(e) => {
            error!("Failed to get HSM status: {}", e);
            Ok(Json(HsmResponse {
                success: false,
                data: None,
                error: Some(e.to_string()),
                metadata: HashMap::new(),
            }))
        }
    }
}

/// Wrap a key using HSM
async fn wrap_key(
    State(_state): State<AppState>,
    Json(mut request): Json<WrapKeyRequest>,
) -> Result<Json<HsmResponse<WrapKeyResponse>>, ApiError> {
    info!("Wrapping key with algorithm: {}", request.algorithm);
    
    // Decode key data
    let mut key_data = base64::decode(&request.key_data)
        .map_err(|e| ApiError::BadRequest(format!("Invalid base64 key data: {}", e)))?;
    
    // Clear sensitive input data
    request.key_data.zeroize();
    
    match erebor_tee::hsm::wrap_key(
        &key_data,
        &request.algorithm,
        request.wrapping_key_id.as_deref(),
        request.metadata.as_ref(),
    ).await {
        Ok(wrapped) => {
            info!("Key wrapped successfully");
            
            // Clear sensitive key data
            key_data.zeroize();
            
            let response_data = WrapKeyResponse {
                wrapped_key: base64::encode(&wrapped.encrypted_key),
                key_id: wrapped.key_id.clone(),
                algorithm: wrapped.algorithm.clone(),
                metadata: wrapped.metadata.clone(),
            };
            
            Ok(Json(HsmResponse {
                success: true,
                data: Some(response_data),
                error: None,
                metadata: {
                    let mut m = HashMap::new();
                    m.insert("timestamp".to_string(), 
                           serde_json::json!(chrono::Utc::now().to_rfc3339()));
                    m
                },
            }))
        }
        Err(e) => {
            error!("Failed to wrap key: {}", e);
            key_data.zeroize();
            
            Ok(Json(HsmResponse {
                success: false,
                data: None,
                error: Some(e.to_string()),
                metadata: HashMap::new(),
            }))
        }
    }
}

/// Unwrap a key using HSM
async fn unwrap_key(
    State(_state): State<AppState>,
    Json(request): Json<UnwrapKeyRequest>,
) -> Result<Json<HsmResponse<UnwrapKeyResponse>>, ApiError> {
    info!("Unwrapping key with ID: {}", request.key_id);
    
    // Decode wrapped key data
    let wrapped_data = base64::decode(&request.wrapped_key)
        .map_err(|e| ApiError::BadRequest(format!("Invalid base64 wrapped key: {}", e)))?;
    
    match erebor_tee::hsm::unwrap_key(
        &wrapped_data,
        &request.key_id,
        &request.algorithm,
    ).await {
        Ok(unwrapped_key) => {
            info!("Key unwrapped successfully");
            
            let key_size = unwrapped_key.len();
            
            // Don't return the actual key data for security reasons
            let response_data = UnwrapKeyResponse {
                success: true,
                key_size,
                algorithm: request.algorithm.clone(),
            };
            
            Ok(Json(HsmResponse {
                success: true,
                data: Some(response_data),
                error: None,
                metadata: {
                    let mut m = HashMap::new();
                    m.insert("timestamp".to_string(), 
                           serde_json::json!(chrono::Utc::now().to_rfc3339()));
                    m
                },
            }))
        }
        Err(e) => {
            error!("Failed to unwrap key: {}", e);
            
            Ok(Json(HsmResponse {
                success: false,
                data: Some(UnwrapKeyResponse {
                    success: false,
                    key_size: 0,
                    algorithm: request.algorithm,
                }),
                error: Some(e.to_string()),
                metadata: HashMap::new(),
            }))
        }
    }
}

/// Generate a new key in HSM
async fn generate_key(
    State(_state): State<AppState>,
    Json(request): Json<GenerateKeyRequest>,
) -> Result<Json<HsmResponse<GenerateKeyResponse>>, ApiError> {
    info!("Generating key of type: {} with label: {}", request.key_type, request.label);
    
    match erebor_tee::hsm::generate_key(
        &request.key_type,
        &request.label,
        request.extractable,
        request.attributes.as_ref(),
    ).await {
        Ok(key_info) => {
            info!("Key generated successfully: {}", key_info.key_id);
            
            Ok(Json(HsmResponse {
                success: true,
                data: Some(key_info),
                error: None,
                metadata: {
                    let mut m = HashMap::new();
                    m.insert("timestamp".to_string(), 
                           serde_json::json!(chrono::Utc::now().to_rfc3339()));
                    m
                },
            }))
        }
        Err(e) => {
            error!("Failed to generate key: {}", e);
            
            Ok(Json(HsmResponse {
                success: false,
                data: None,
                error: Some(e.to_string()),
                metadata: HashMap::new(),
            }))
        }
    }
}

/// Sign data using HSM key
async fn sign_data(
    State(_state): State<AppState>,
    Json(request): Json<SignRequest>,
) -> Result<Json<HsmResponse<SignResponse>>, ApiError> {
    info!("Signing data with key ID: {}", request.key_id);
    
    // Decode data to sign
    let data = base64::decode(&request.data)
        .map_err(|e| ApiError::BadRequest(format!("Invalid base64 data: {}", e)))?;
    
    match erebor_tee::hsm::sign_data(
        &request.key_id,
        &data,
        &request.algorithm,
    ).await {
        Ok(signature) => {
            info!("Data signed successfully");
            
            let response_data = SignResponse {
                signature: base64::encode(&signature),
                algorithm: request.algorithm.clone(),
                key_id: request.key_id.clone(),
            };
            
            Ok(Json(HsmResponse {
                success: true,
                data: Some(response_data),
                error: None,
                metadata: {
                    let mut m = HashMap::new();
                    m.insert("timestamp".to_string(), 
                           serde_json::json!(chrono::Utc::now().to_rfc3339()));
                    m
                },
            }))
        }
        Err(e) => {
            error!("Failed to sign data: {}", e);
            
            Ok(Json(HsmResponse {
                success: false,
                data: None,
                error: Some(e.to_string()),
                metadata: HashMap::new(),
            }))
        }
    }
}

/// List HSM keys (placeholder implementation)
async fn list_keys(
    State(_state): State<AppState>,
    Query(params): Query<HsmQuery>,
) -> Result<Json<HsmResponse<Vec<serde_json::Value>>>, ApiError> {
    info!("Listing HSM keys (provider: {:?}, limit: {:?})", 
          params.provider, params.limit);
    
    // This is a placeholder - in practice would query HSM for key list
    match erebor_tee::hsm::list_keys(params.provider.as_deref()).await {
        Ok(keys) => {
            let limit = params.limit.unwrap_or(50) as usize;
            let limited_keys = keys.into_iter().take(limit).collect();
            
            Ok(Json(HsmResponse {
                success: true,
                data: Some(limited_keys),
                error: None,
                metadata: {
                    let mut m = HashMap::new();
                    m.insert("timestamp".to_string(), 
                           serde_json::json!(chrono::Utc::now().to_rfc3339()));
                    m
                },
            }))
        }
        Err(e) => {
            error!("Failed to list keys: {}", e);
            
            Ok(Json(HsmResponse {
                success: false,
                data: None,
                error: Some(e.to_string()),
                metadata: HashMap::new(),
            }))
        }
    }
}

/// Get information about a specific key
async fn get_key_info(
    State(_state): State<AppState>,
    Path(key_id): Path<String>,
) -> Result<Json<HsmResponse<serde_json::Value>>, ApiError> {
    info!("Getting key info for: {}", key_id);
    
    match erebor_tee::hsm::get_key_info(&key_id).await {
        Ok(key_info) => {
            info!("Key info retrieved successfully for: {}", key_id);
            
            Ok(Json(HsmResponse {
                success: true,
                data: Some(key_info),
                error: None,
                metadata: {
                    let mut m = HashMap::new();
                    m.insert("timestamp".to_string(), 
                           serde_json::json!(chrono::Utc::now().to_rfc3339()));
                    m
                },
            }))
        }
        Err(e) => {
            warn!("Key not found or error retrieving info for {}: {}", key_id, e);
            
            Ok(Json(HsmResponse {
                success: false,
                data: None,
                error: Some(e.to_string()),
                metadata: HashMap::new(),
            }))
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::{Request, StatusCode};
    use tower::ServiceExt;
    
    async fn create_test_app() -> Router {
        let state = AppState::new().expect("Failed to create test state");
        hsm_router().with_state(state)
    }
    
    #[tokio::test]
    async fn test_hsm_status() {
        let app = create_test_app().await;
        
        let response = app
            .oneshot(
                Request::builder()
                    .uri("/v1/hsm/status")
                    .body(Body::empty())
                    .unwrap(),
            )
            .await
            .unwrap();
        
        assert_eq!(response.status(), StatusCode::OK);
    }
    
    #[tokio::test]
    async fn test_wrap_key() {
        let app = create_test_app().await;
        
        let request_body = serde_json::json!({
            "key_data": base64::encode(b"test-key-data-32bytes-long-test"),
            "algorithm": "aes256"
        });
        
        let response = app
            .oneshot(
                Request::builder()
                    .method("POST")
                    .uri("/v1/hsm/wrap")
                    .header("content-type", "application/json")
                    .body(Body::from(request_body.to_string()))
                    .unwrap(),
            )
            .await
            .unwrap();
        
        assert_eq!(response.status(), StatusCode::OK);
    }
}