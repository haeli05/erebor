pub mod auth;
pub mod wallets;

use axum::Router;
use crate::state::AppState;

/// Build the complete API router
pub fn api_router() -> Router<AppState> {
    Router::new()
        .merge(auth::auth_router())
        .merge(wallets::wallets_router())
}