use axum::{extract::State, http::StatusCode, response::Json, routing::post, Router};
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};

use crate::state::AppState;
use erebor_mpc::{
    DkgRequest, DkgResponse, SigningRequest, SigningResponse, RefreshRequest, RefreshResponse,
    RecoveryRequest, RecoveryApprovalRequest, AnomalyRequest, AnomalyResponse, RecoveryStatus,
    perform_dkg, perform_signing, perform_refresh, 
    initiate_recovery, approve_recovery, score_anomaly,
};

/// Build MPC router
pub fn mpc_router() -> Router<AppState> {
    Router::new()
        .route("/v1/mpc/keygen", post(mpc_keygen))
        .route("/v1/mpc/sign", post(mpc_sign))
        .route("/v1/mpc/refresh", post(mpc_refresh))
        .route("/v1/recovery/initiate", post(recovery_initiate))
        .route("/v1/recovery/approve", post(recovery_approve))
        .route("/v1/anomaly/score", post(anomaly_score))
}

/// MPC distributed key generation
#[axum::debug_handler]
async fn mpc_keygen(
    State(state): State<AppState>,
    Json(request): Json<DkgRequest>,
) -> Result<Json<DkgResponse>, StatusCode> {
    tracing::info!("MPC DKG request: threshold={}, parties={}", request.threshold, request.parties.len());
    
    match perform_dkg(request).await {
        Ok(response) => {
            tracing::info!("MPC DKG completed successfully");
            Ok(Json(response))
        }
        Err(e) => {
            tracing::error!("MPC DKG failed: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// MPC threshold signing
#[axum::debug_handler]
async fn mpc_sign(
    State(state): State<AppState>,
    Json(request): Json<SigningRequest>,
) -> Result<Json<SigningResponse>, StatusCode> {
    tracing::info!("MPC signing request for message: {}", hex::encode(&request.message));
    
    match perform_signing(request).await {
        Ok(response) => {
            tracing::info!("MPC signing completed successfully");
            Ok(Json(response))
        }
        Err(e) => {
            tracing::error!("MPC signing failed: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// MPC key refresh
#[axum::debug_handler]
async fn mpc_refresh(
    State(state): State<AppState>,
    Json(request): Json<RefreshRequest>,
) -> Result<Json<RefreshResponse>, StatusCode> {
    tracing::info!("MPC key refresh request");
    
    match perform_refresh(request).await {
        Ok(response) => {
            tracing::info!("MPC key refresh completed successfully");
            Ok(Json(response))
        }
        Err(e) => {
            tracing::error!("MPC key refresh failed: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Initiate social recovery
#[axum::debug_handler]
async fn recovery_initiate(
    State(state): State<AppState>,
    Json(request): Json<RecoveryRequest>,
) -> Result<Json<Value>, StatusCode> {
    tracing::info!("Recovery initiation request for wallet: {}", request.wallet_id);
    
    match initiate_recovery(request).await {
        Ok(recovery_id) => {
            tracing::info!("Recovery initiated with ID: {}", recovery_id);
            Ok(Json(json!({
                "recovery_id": recovery_id,
                "status": "initiated",
                "message": "Recovery process started. Guardians will be notified."
            })))
        }
        Err(e) => {
            tracing::error!("Recovery initiation failed: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Approve social recovery
#[axum::debug_handler]
async fn recovery_approve(
    State(state): State<AppState>,
    Json(request): Json<RecoveryApprovalRequest>,
) -> Result<Json<Value>, StatusCode> {
    tracing::info!("Recovery approval request for recovery: {}", request.recovery_id);
    
    match approve_recovery(request).await {
        Ok(status) => {
            tracing::info!("Recovery approval processed: {:?}", status);
            Ok(Json(json!({
                "recovery_id": request.recovery_id,
                "status": status,
                "message": "Recovery approval processed successfully"
            })))
        }
        Err(e) => {
            tracing::error!("Recovery approval failed: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}

/// Score transaction for anomalies
#[axum::debug_handler]
async fn anomaly_score(
    State(state): State<AppState>,
    Json(request): Json<AnomalyRequest>,
) -> Result<Json<AnomalyResponse>, StatusCode> {
    tracing::info!("Anomaly scoring request for transaction");
    
    match score_anomaly(request).await {
        Ok(response) => {
            tracing::info!("Anomaly scoring completed: risk_score={}", response.risk_score);
            Ok(Json(response))
        }
        Err(e) => {
            tracing::error!("Anomaly scoring failed: {}", e);
            Err(StatusCode::INTERNAL_SERVER_ERROR)
        }
    }
}