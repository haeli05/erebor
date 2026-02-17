use axum::{routing::get, Json, Router};
use serde_json::json;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() {
    dotenvy::dotenv().ok();
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env())
        .init();

    let app = Router::new()
        .route("/health", get(health))
        .route("/", get(root));

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
