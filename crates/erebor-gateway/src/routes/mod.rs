pub mod auth;
pub mod wallets;
pub mod mpc;
pub mod tee;
pub mod hsm;

use axum::Router;
use crate::state::AppState;

/// Build the complete API router
pub fn api_router() -> Router<AppState> {
    Router::new()
        .merge(auth::auth_router())
        .merge(wallets::wallets_router())
        .merge(mpc::mpc_router())
        .merge(tee::tee_router())
        .merge(hsm::hsm_router())
}