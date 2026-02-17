mod state;
mod error;
mod routes;
mod auth;

use axum::{routing::get, Json, Router, middleware};
use erebor_auth::middleware::{auth_middleware, rate_limit_middleware, RateLimiter};
use serde_json::json;
use std::sync::Arc;
use tower_http::cors::CorsLayer;

// CSRF Protection Notice:
// This API is designed for token-based authentication using Bearer tokens,
// which are inherently CSRF-resistant as they require explicit inclusion
// in request headers rather than being automatically sent by browsers.
// No session cookies are used, eliminating CSRF attack vectors.
use tracing_subscriber::EnvFilter;
use state::AppState;

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    // Initialize application state
    let state = AppState::new().expect("Failed to initialize app state");

    // Create rate limiter (100 requests per minute)
    let rate_limiter = Arc::new(RateLimiter::new(100.0, 1.67)); // 100/60 tokens per second

    // Build the application router
    let app = Router::new()
        // Health and info endpoints
        .route("/health", get(health))
        .route("/", get(root))
        // API routes
        .merge(routes::api_router())
        // Add middleware layers
        .layer(middleware::from_fn(auth_middleware))
        .layer(middleware::from_fn(rate_limit_middleware))
        .layer(CorsLayer::permissive())
        // Add shared state
        .layer(axum::Extension(state.jwt.clone()))
        .layer(axum::Extension(state.token_blacklist.clone() as Arc<dyn erebor_auth::middleware::TokenBlacklistTrait>))
        .layer(axum::Extension(rate_limiter))
        .with_state(state);

    let addr = "0.0.0.0:8080";
    tracing::info!("Erebor gateway listening on {addr}");
    let listener = tokio::net::TcpListener::bind(addr).await.unwrap();
    axum::serve(listener, app).await.unwrap();
}

async fn health() -> Json<serde_json::Value> {
    Json(json!({
        "status": "ok",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}

async fn root() -> Json<serde_json::Value> {
    Json(json!({
        "name": "erebor",
        "description": "Self-custodial wallet infrastructure",
        "version": env!("CARGO_PKG_VERSION"),
    }))
}
