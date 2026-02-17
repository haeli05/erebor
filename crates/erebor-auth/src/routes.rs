use std::sync::Arc;

use axum::extract::{Extension, Path};
use axum::http::StatusCode;
use axum::response::IntoResponse;
use axum::routing::{delete, get, post};
use axum::{Json, Router};
use erebor_common::AuthProvider;
use serde::{Deserialize, Serialize};
use tracing::error;

use crate::jwt::JwtManager;
use crate::linking::LinkingManager;
use crate::middleware::AuthenticatedUser;
use crate::providers::{ProviderRegistry, SiweMessage};
use crate::session::SessionManager;
use crate::{deterministic_user_id};

// ---------------------------------------------------------------------------
// Shared app state
// ---------------------------------------------------------------------------

#[derive(Clone)]
pub struct AuthState {
    pub jwt: Arc<JwtManager>,
    pub sessions: Arc<SessionManager>,
    pub linking: Arc<LinkingManager>,
    pub providers: Arc<ProviderRegistry>,
}

// ---------------------------------------------------------------------------
// Request/Response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct GoogleAuthRequest {
    pub code: String,
}

#[derive(Deserialize)]
pub struct SendOtpRequest {
    pub email: String,
}

#[derive(Deserialize)]
pub struct VerifyOtpRequest {
    pub email: String,
    pub code: String,
}

#[derive(Deserialize)]
pub struct SiweVerifyRequest {
    pub message: SiweMessage,
    pub signature: String,
}

#[derive(Deserialize)]
pub struct RefreshRequest {
    pub refresh_token: String,
}

#[derive(Deserialize)]
pub struct LinkRequest {
    pub provider: AuthProvider,
    pub provider_user_id: String,
    pub email: Option<String>,
}

#[derive(Serialize)]
pub struct AuthResponse {
    pub access_token: String,
    pub refresh_token: String,
    pub user_id: String,
}

#[derive(Serialize)]
pub struct MessageResponse {
    pub message: String,
}

#[derive(Serialize)]
pub struct MeResponse {
    pub user_id: String,
    pub providers: Vec<String>,
    pub linked_identities: Vec<LinkedIdentityResponse>,
}

#[derive(Serialize)]
pub struct LinkedIdentityResponse {
    pub provider: AuthProvider,
    pub provider_user_id: String,
    pub email: Option<String>,
    pub linked_at: String,
}

// ---------------------------------------------------------------------------
// Helper
// ---------------------------------------------------------------------------

async fn issue_tokens_and_respond(
    state: &AuthState,
    user_id: &erebor_common::UserId,
    providers: Vec<String>,
) -> std::result::Result<Json<AuthResponse>, (StatusCode, String)> {
    let session = state
        .sessions
        .create_session(user_id, providers.clone())
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let access_token = state
        .jwt
        .issue_access_token(user_id, &providers)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(AuthResponse {
        access_token,
        refresh_token: session.refresh_token,
        user_id: user_id.0.to_string(),
    }))
}

// ---------------------------------------------------------------------------
// Route handlers
// ---------------------------------------------------------------------------

/// POST /auth/google — Exchange Google OAuth code for tokens
async fn google_auth(
    Extension(state): Extension<AuthState>,
    Json(req): Json<GoogleAuthRequest>,
) -> std::result::Result<impl IntoResponse, (StatusCode, String)> {
    let google = state
        .providers
        .google
        .as_ref()
        .ok_or((StatusCode::NOT_IMPLEMENTED, "Google OAuth not configured".into()))?;

    let provider_user = google
        .authenticate(&req.code)
        .await
        .map_err(|e| (StatusCode::UNAUTHORIZED, e.to_string()))?;

    let user_id = deterministic_user_id(&AuthProvider::Google, &provider_user.provider_user_id);

    // Link identity
    state
        .linking
        .link_identity(
            &user_id,
            AuthProvider::Google,
            provider_user.provider_user_id,
            provider_user.email,
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    issue_tokens_and_respond(&state, &user_id, vec!["google".into()]).await
}

/// POST /auth/email/send-otp — Send OTP to email
async fn send_otp(
    Extension(state): Extension<AuthState>,
    Json(req): Json<SendOtpRequest>,
) -> std::result::Result<impl IntoResponse, (StatusCode, String)> {
    state
        .providers
        .email_otp
        .send_otp(&req.email)
        .await
        .map_err(|e| match e {
            erebor_common::EreborError::RateLimited => {
                (StatusCode::TOO_MANY_REQUESTS, "Rate limited".into())
            }
            other => (StatusCode::INTERNAL_SERVER_ERROR, other.to_string()),
        })?;

    Ok(Json(MessageResponse {
        message: "OTP sent".into(),
    }))
}

/// POST /auth/email/verify — Verify email OTP and authenticate
async fn verify_otp(
    Extension(state): Extension<AuthState>,
    Json(req): Json<VerifyOtpRequest>,
) -> std::result::Result<impl IntoResponse, (StatusCode, String)> {
    let provider_user = state
        .providers
        .email_otp
        .verify_otp(&req.email, &req.code)
        .await
        .map_err(|e| (StatusCode::UNAUTHORIZED, e.to_string()))?;

    let user_id = deterministic_user_id(&AuthProvider::Email, &provider_user.provider_user_id);

    state
        .linking
        .link_identity(
            &user_id,
            AuthProvider::Email,
            provider_user.provider_user_id,
            provider_user.email,
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    issue_tokens_and_respond(&state, &user_id, vec!["email".into()]).await
}

/// POST /auth/siwe/verify — Verify SIWE message and authenticate
async fn siwe_verify(
    Extension(state): Extension<AuthState>,
    Json(req): Json<SiweVerifyRequest>,
) -> std::result::Result<impl IntoResponse, (StatusCode, String)> {
    let provider_user = state
        .providers
        .siwe
        .verify(&req.message, &req.signature)
        .await
        .map_err(|e| (StatusCode::UNAUTHORIZED, e.to_string()))?;

    let user_id = deterministic_user_id(&AuthProvider::Siwe, &provider_user.provider_user_id);

    state
        .linking
        .link_identity(
            &user_id,
            AuthProvider::Siwe,
            provider_user.provider_user_id,
            None,
        )
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    issue_tokens_and_respond(&state, &user_id, vec!["siwe".into()]).await
}

/// POST /auth/refresh — Refresh session tokens
async fn refresh(
    Extension(state): Extension<AuthState>,
    Json(req): Json<RefreshRequest>,
) -> std::result::Result<impl IntoResponse, (StatusCode, String)> {
    let session = state
        .sessions
        .refresh_session(&req.refresh_token)
        .await
        .map_err(|e| (StatusCode::UNAUTHORIZED, e.to_string()))?;

    let access_token = state
        .jwt
        .issue_access_token(&session.user_id, &session.providers)
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    Ok(Json(AuthResponse {
        access_token,
        refresh_token: session.refresh_token,
        user_id: session.user_id.0.to_string(),
    }))
}

/// GET /auth/me — Get current user info
async fn me(
    Extension(state): Extension<AuthState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
) -> std::result::Result<impl IntoResponse, (StatusCode, String)> {
    let links = state
        .linking
        .get_linked_identities(&auth_user.user_id)
        .await
        .map_err(|e| (StatusCode::INTERNAL_SERVER_ERROR, e.to_string()))?;

    let linked_identities = links
        .into_iter()
        .map(|l| LinkedIdentityResponse {
            provider: l.provider,
            provider_user_id: l.provider_user_id,
            email: l.email,
            linked_at: l.linked_at.to_rfc3339(),
        })
        .collect();

    Ok(Json(MeResponse {
        user_id: auth_user.user_id.0.to_string(),
        providers: auth_user.claims.providers,
        linked_identities,
    }))
}

/// POST /auth/link — Link a new auth method to current user
async fn link_provider(
    Extension(state): Extension<AuthState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    Json(req): Json<LinkRequest>,
) -> std::result::Result<impl IntoResponse, (StatusCode, String)> {
    state
        .linking
        .link_identity(
            &auth_user.user_id,
            req.provider,
            req.provider_user_id,
            req.email,
        )
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    Ok(Json(MessageResponse {
        message: "Identity linked".into(),
    }))
}

/// DELETE /auth/link/:provider — Unlink an auth method
async fn unlink_provider(
    Extension(state): Extension<AuthState>,
    Extension(auth_user): Extension<AuthenticatedUser>,
    Path(provider_str): Path<String>,
) -> std::result::Result<impl IntoResponse, (StatusCode, String)> {
    let provider: AuthProvider = serde_json::from_str(&format!("\"{provider_str}\""))
        .map_err(|_| (StatusCode::BAD_REQUEST, format!("Unknown provider: {provider_str}")))?;

    state
        .linking
        .unlink_identity(&auth_user.user_id, &provider)
        .await
        .map_err(|e| (StatusCode::BAD_REQUEST, e.to_string()))?;

    Ok(Json(MessageResponse {
        message: "Identity unlinked".into(),
    }))
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// Build the auth router. Public routes (no auth required) and protected routes.
pub fn auth_router() -> Router {
    // Public routes (no JWT required)
    let public = Router::new()
        .route("/auth/google", post(google_auth))
        .route("/auth/email/send-otp", post(send_otp))
        .route("/auth/email/verify", post(verify_otp))
        .route("/auth/siwe/verify", post(siwe_verify))
        .route("/auth/refresh", post(refresh));

    // Protected routes (JWT required via middleware applied externally)
    let protected = Router::new()
        .route("/auth/me", get(me))
        .route("/auth/link", post(link_provider))
        .route("/auth/link/:provider", delete(unlink_provider));

    public.merge(protected)
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;
    use crate::linking::{InMemoryLinkingStore, LinkingManager};
    use crate::providers::{EmailOtpProvider, ProviderRegistry, SiweProvider};
    use crate::session::{InMemorySessionStore, SessionManager};
    use axum::body::Body;
    use axum::http::Request;
    use tower::ServiceExt;

    fn test_state() -> AuthState {
        let jwt = Arc::new(JwtManager::new(b"test-secret-key-at-least-32-bytes!"));
        let sessions = Arc::new(SessionManager::new(Arc::new(InMemorySessionStore::new())));
        let linking = Arc::new(LinkingManager::new(Arc::new(InMemoryLinkingStore::new())));
        let providers = Arc::new(ProviderRegistry::new(
            EmailOtpProvider::new(),
            SiweProvider::new("localhost".into()),
            None,
        ));
        AuthState {
            jwt,
            sessions,
            linking,
            providers,
        }
    }

    fn test_app(state: AuthState) -> Router {
        auth_router().layer(Extension(state))
    }

    #[tokio::test]
    async fn test_send_otp_route() {
        let state = test_state();
        let app = test_app(state);

        let req = Request::builder()
            .method("POST")
            .uri("/auth/email/send-otp")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"email":"test@example.com"}"#))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_verify_otp_route() {
        let state = test_state();
        // Send OTP first
        let code = state
            .providers
            .email_otp
            .send_otp("test@example.com")
            .await
            .unwrap();

        let app = test_app(state);
        let body = serde_json::json!({
            "email": "test@example.com",
            "code": code
        });

        let req = Request::builder()
            .method("POST")
            .uri("/auth/email/verify")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);

        let body = axum::body::to_bytes(resp.into_body(), 1024 * 64)
            .await
            .unwrap();
        let auth_resp: AuthResponse = serde_json::from_slice(&body).unwrap();
        assert!(!auth_resp.access_token.is_empty());
        assert!(!auth_resp.refresh_token.is_empty());
    }

    #[tokio::test]
    async fn test_verify_otp_wrong_code() {
        let state = test_state();
        state
            .providers
            .email_otp
            .send_otp("test@example.com")
            .await
            .unwrap();

        let app = test_app(state);
        let body = serde_json::json!({
            "email": "test@example.com",
            "code": "000000"
        });

        let req = Request::builder()
            .method("POST")
            .uri("/auth/email/verify")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_refresh_route() {
        let state = test_state();
        // Create a session first
        let user_id = erebor_common::UserId::new();
        let session = state
            .sessions
            .create_session(&user_id, vec!["email".into()])
            .await
            .unwrap();

        let app = test_app(state);
        let body = serde_json::json!({
            "refresh_token": session.refresh_token
        });

        let req = Request::builder()
            .method("POST")
            .uri("/auth/refresh")
            .header("content-type", "application/json")
            .body(Body::from(serde_json::to_string(&body).unwrap()))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_google_not_configured() {
        let state = test_state();
        let app = test_app(state);

        let req = Request::builder()
            .method("POST")
            .uri("/auth/google")
            .header("content-type", "application/json")
            .body(Body::from(r#"{"code":"some-code"}"#))
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::NOT_IMPLEMENTED);
    }
}
