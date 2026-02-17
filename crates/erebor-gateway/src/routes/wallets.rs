use axum::{
    extract::{Path, State},
    routing::{get, post},
    Json, Router
};
use crate::auth::RequireAuth;
use erebor_common::EreborError;
use serde::{Deserialize, Serialize};
use crate::state::AppState;
use crate::error::{ApiError, ApiResult};

// ---------------------------------------------------------------------------
// Request/Response types
// ---------------------------------------------------------------------------

#[derive(Serialize)]
pub struct CreateWalletResponse {
    pub wallet_id: String,
    pub ethereum_address: String,
    pub share_indices: Vec<u8>,
    pub created_at: String,
}

#[derive(Serialize)]
pub struct WalletListResponse {
    pub wallets: Vec<WalletSummary>,
}

#[derive(Serialize)]
pub struct WalletSummary {
    pub wallet_id: String,
    pub ethereum_address: String,
    pub share_count: usize,
    pub created_at: String,
}

#[derive(Serialize)]
pub struct WalletDetailsResponse {
    pub wallet_id: String,
    pub ethereum_address: String,
    pub share_indices: Vec<u8>,
    pub created_at: String,
}

#[derive(Deserialize)]
pub struct SignMessageRequest {
    pub message: String,
    pub share_indices: Vec<u8>,
}

#[derive(Deserialize)]
pub struct SignTransactionRequest {
    pub transaction_hash: String,
    pub share_indices: Vec<u8>,
}

#[derive(Deserialize)]
pub struct SendTransactionRequest {
    pub to: String,
    pub value: String,
    pub data: Option<String>,
    pub gas_limit: Option<u64>,
    pub gas_price: Option<String>,
    pub share_indices: Vec<u8>,
}

#[derive(Serialize)]
pub struct SignatureResponse {
    pub signature: String,
    pub message: Option<String>,
    pub transaction_hash: Option<String>,
}

#[derive(Serialize)]
pub struct TransactionResponse {
    pub transaction_hash: String,
    pub signature: String,
    pub broadcast: bool,
}

// ---------------------------------------------------------------------------
// Route handlers
// ---------------------------------------------------------------------------

/// POST /wallets — Create a new wallet for authenticated user
pub async fn create_wallet(
    State(state): State<AppState>,
    RequireAuth(user_id): RequireAuth,
) -> ApiResult<Json<CreateWalletResponse>> {
    let wallet_info = state
        .vault
        .create_wallet(&user_id)
        .await
        .map_err(ApiError::from)?;

    Ok(Json(CreateWalletResponse {
        wallet_id: user_id.0.to_string(), // Using user_id as wallet_id for simplicity
        ethereum_address: wallet_info.ethereum_address,
        share_indices: wallet_info.share_indices,
        created_at: chrono::Utc::now().to_rfc3339(),
    }))
}

/// GET /wallets — List user's wallets
pub async fn list_wallets(
    State(_state): State<AppState>,
    RequireAuth(_user_id): RequireAuth,
) -> ApiResult<Json<WalletListResponse>> {
    // For this MVP, we assume one wallet per user
    // In a real implementation, you'd query the vault store for all user wallets
    
    // Since we don't have a direct way to check if wallet exists, 
    // we'll return an empty list for now
    // In production, you'd store wallet metadata separately
    
    Ok(Json(WalletListResponse {
        wallets: vec![],
    }))
}

/// GET /wallets/:id — Get wallet details
pub async fn get_wallet(
    State(_state): State<AppState>,
    RequireAuth(user_id): RequireAuth,
    Path(wallet_id): Path<String>,
) -> ApiResult<Json<WalletDetailsResponse>> {
    // Verify the wallet belongs to the user
    if wallet_id != user_id.0.to_string() {
        return Err(ApiError::from(EreborError::NotFound("Wallet not found".into())));
    }

    // For MVP, we can't easily retrieve wallet info without recreating it
    // In production, you'd store wallet metadata in a separate store
    return Err(ApiError::from(EreborError::Internal("Wallet details not implemented".into())));
}

/// POST /wallets/:id/sign-message — Sign arbitrary message
pub async fn sign_message(
    State(state): State<AppState>,
    RequireAuth(user_id): RequireAuth,
    Path(wallet_id): Path<String>,
    Json(req): Json<SignMessageRequest>,
) -> ApiResult<Json<SignatureResponse>> {
    // Verify the wallet belongs to the user
    if wallet_id != user_id.0.to_string() {
        return Err(ApiError::from(EreborError::NotFound("Wallet not found".into())));
    }

    // Hash the message
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(req.message.as_bytes());
    let message_hash = hasher.finalize();
    let hash_array: [u8; 32] = message_hash.into();

    let signature = state
        .vault
        .sign_transaction(&user_id, &req.share_indices, &hash_array)
        .await
        .map_err(ApiError::from)?;

    Ok(Json(SignatureResponse {
        signature: hex::encode(signature),
        message: Some(req.message),
        transaction_hash: None,
    }))
}

/// POST /wallets/:id/sign-transaction — Sign transaction but don't broadcast
pub async fn sign_transaction(
    State(state): State<AppState>,
    RequireAuth(user_id): RequireAuth,
    Path(wallet_id): Path<String>,
    Json(req): Json<SignTransactionRequest>,
) -> ApiResult<Json<SignatureResponse>> {
    // Verify the wallet belongs to the user
    if wallet_id != user_id.0.to_string() {
        return Err(ApiError::from(EreborError::NotFound("Wallet not found".into())));
    }

    // Parse transaction hash
    let tx_hash_bytes = hex::decode(&req.transaction_hash)
        .map_err(|_| ApiError::from(EreborError::ChainError("Invalid transaction hash".into())))?;
    
    if tx_hash_bytes.len() != 32 {
        return Err(ApiError::from(EreborError::ChainError("Transaction hash must be 32 bytes".into())));
    }

    let mut hash_array = [0u8; 32];
    hash_array.copy_from_slice(&tx_hash_bytes);

    let signature = state
        .vault
        .sign_transaction(&user_id, &req.share_indices, &hash_array)
        .await
        .map_err(ApiError::from)?;

    Ok(Json(SignatureResponse {
        signature: hex::encode(signature),
        message: None,
        transaction_hash: Some(req.transaction_hash),
    }))
}

/// POST /wallets/:id/send-transaction — Sign and broadcast transaction
pub async fn send_transaction(
    State(state): State<AppState>,
    RequireAuth(user_id): RequireAuth,
    Path(wallet_id): Path<String>,
    Json(req): Json<SendTransactionRequest>,
) -> ApiResult<Json<TransactionResponse>> {
    // Verify the wallet belongs to the user
    if wallet_id != user_id.0.to_string() {
        return Err(ApiError::from(EreborError::NotFound("Wallet not found".into())));
    }

    // For MVP, we'll just simulate transaction construction and signing
    // In production, you'd:
    // 1. Construct the transaction with the chain service
    // 2. Get nonce, gas estimates, etc.
    // 3. Sign the transaction hash
    // 4. Broadcast via the chain service

    // Simulate transaction hash
    use sha2::{Sha256, Digest};
    let mut hasher = Sha256::new();
    hasher.update(req.to.as_bytes());
    hasher.update(req.value.as_bytes());
    if let Some(ref data) = req.data {
        hasher.update(data.as_bytes());
    }
    hasher.update(user_id.0.as_bytes());
    let tx_hash = hasher.finalize();
    let hash_array: [u8; 32] = tx_hash.into();

    let signature = state
        .vault
        .sign_transaction(&user_id, &req.share_indices, &hash_array)
        .await
        .map_err(ApiError::from)?;

    let tx_hash_hex = hex::encode(&hash_array);

    // In production, you'd actually broadcast the transaction here
    tracing::info!("Simulated transaction broadcast for user {}: {}", user_id.0, tx_hash_hex);

    Ok(Json(TransactionResponse {
        transaction_hash: tx_hash_hex,
        signature: hex::encode(signature),
        broadcast: false, // Set to false since we're just simulating
    }))
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// Build the wallets router
pub fn wallets_router() -> Router<AppState> {
    Router::new()
        .route("/wallets", post(create_wallet))
        .route("/wallets", get(list_wallets))
        .route("/wallets/:id", get(get_wallet))
        .route("/wallets/:id/sign-message", post(sign_message))
        .route("/wallets/:id/sign-transaction", post(sign_transaction))
        .route("/wallets/:id/send-transaction", post(send_transaction))
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::util::ServiceExt;
    use crate::state::AppState;

    fn test_state() -> AppState {
        AppState::new().expect("Failed to create test state")
    }

    async fn create_test_user_with_wallet(state: &AppState) -> (UserId, WalletInfo) {
        let user_id = UserId::new();
        let wallet_info = state.vault.create_wallet(&user_id).await.unwrap();
        (user_id, wallet_info)
    }

    #[tokio::test]
    async fn test_create_wallet_requires_auth() {
        let state = test_state();
        let app = wallets_router().with_state(state);

        let req = Request::builder()
            .method("POST")
            .uri("/wallets")
            .header("content-type", "application/json")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_list_wallets_requires_auth() {
        let state = test_state();
        let app = wallets_router().with_state(state);

        let req = Request::builder()
            .method("GET")
            .uri("/wallets")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    // Note: Testing authenticated routes would require setting up JWT tokens
    // and the auth middleware, which is complex for unit tests
    // Integration tests would cover these scenarios better
}