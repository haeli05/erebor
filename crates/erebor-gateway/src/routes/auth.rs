use axum::{
    extract::{Path, State},
    routing::{delete, get, post},
    Json, Router
};
use erebor_auth::{
    deterministic_user_id,
    providers::{SiweMessage, FarcasterMessage, TelegramAuthData, AuthProviderHandler}
};
use erebor_common::{AuthProvider, EreborError, UserId};
use serde::{Deserialize, Serialize};
use crate::state::AppState;
use crate::error::{ApiError, ApiResult};
use crate::auth::RequireAuth;

// ---------------------------------------------------------------------------
// Request/Response types
// ---------------------------------------------------------------------------

#[derive(Deserialize)]
pub struct GoogleAuthRequest {
    pub code: String,
    pub redirect_uri: String,
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

#[derive(Serialize)]
pub struct NonceResponse {
    pub nonce: String,
}

#[derive(Deserialize)]
pub struct SiweVerifyRequest {
    pub message: SiweMessage,
    pub signature: String,
}

#[derive(Deserialize)]
pub struct FarcasterVerifyRequest {
    pub message: FarcasterMessage,
    pub signature: String,
}

#[derive(Deserialize)]
pub struct TelegramVerifyRequest {
    pub auth_data: TelegramAuthData,
}

#[derive(Deserialize)]
pub struct AppleAuthRequest {
    pub code: String,
    pub redirect_uri: String,
}

#[derive(Deserialize)]
pub struct TwitterAuthRequest {
    pub code: String,
    pub redirect_uri: String,
}

#[derive(Deserialize)]
pub struct DiscordAuthRequest {
    pub code: String,
    pub redirect_uri: String,
}

#[derive(Deserialize)]
pub struct GitHubAuthRequest {
    pub code: String,
    pub redirect_uri: String,
}

#[derive(Deserialize)]
pub struct SendPhoneOtpRequest {
    pub phone: String,
}

#[derive(Deserialize)]
pub struct VerifyPhoneOtpRequest {
    pub phone: String,
    pub code: String,
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
    pub success: bool,
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
// Helper functions
// ---------------------------------------------------------------------------

async fn issue_tokens_and_respond(
    state: &AppState,
    user_id: &UserId,
    providers: Vec<String>,
) -> ApiResult<Json<AuthResponse>> {
    let session = state
        .sessions
        .create_session(user_id, providers.clone())
        .await
        .map_err(|e| ApiError::from(EreborError::AuthError(e.to_string())))?;

    let access_token = state
        .jwt
        .issue_access_token(user_id, &providers)
        .map_err(|e| ApiError::from(EreborError::AuthError(e.to_string())))?;

    Ok(Json(AuthResponse {
        access_token,
        refresh_token: session.refresh_token,
        user_id: user_id.0.to_string(),
    }))
}

// ---------------------------------------------------------------------------
// Route handlers
// ---------------------------------------------------------------------------

/// POST /auth/apple — Exchange Apple OAuth code for tokens
pub async fn apple_auth(
    State(state): State<AppState>,
    Json(req): Json<AppleAuthRequest>,
) -> ApiResult<Json<AuthResponse>> {
    let apple = state
        .providers
        .apple
        .as_ref()
        .ok_or_else(|| ApiError::from(EreborError::Internal("Apple OAuth not configured".into())))?;

    let provider_user = apple
        .authenticate(&req.code)
        .await
        .map_err(|e| ApiError::from(EreborError::AuthError(e.to_string())))?;

    let user_id = deterministic_user_id(&AuthProvider::Apple, &provider_user.provider_user_id);

    state
        .linking
        .link_identity(
            &user_id,
            AuthProvider::Apple,
            provider_user.provider_user_id,
            provider_user.email,
        )
        .await
        .map_err(|e| ApiError::from(EreborError::AuthError(e.to_string())))?;

    issue_tokens_and_respond(&state, &user_id, vec!["apple".into()]).await
}

/// POST /auth/twitter — Exchange Twitter OAuth code for tokens
pub async fn twitter_auth(
    State(state): State<AppState>,
    Json(req): Json<TwitterAuthRequest>,
) -> ApiResult<Json<AuthResponse>> {
    let twitter = state
        .providers
        .twitter
        .as_ref()
        .ok_or_else(|| ApiError::from(EreborError::Internal("Twitter OAuth not configured".into())))?;

    let provider_user = twitter
        .authenticate(&req.code)
        .await
        .map_err(|e| ApiError::from(EreborError::AuthError(e.to_string())))?;

    let user_id = deterministic_user_id(&AuthProvider::Twitter, &provider_user.provider_user_id);

    state
        .linking
        .link_identity(
            &user_id,
            AuthProvider::Twitter,
            provider_user.provider_user_id,
            provider_user.email,
        )
        .await
        .map_err(|e| ApiError::from(EreborError::AuthError(e.to_string())))?;

    issue_tokens_and_respond(&state, &user_id, vec!["twitter".into()]).await
}

/// POST /auth/discord — Exchange Discord OAuth code for tokens
pub async fn discord_auth(
    State(state): State<AppState>,
    Json(req): Json<DiscordAuthRequest>,
) -> ApiResult<Json<AuthResponse>> {
    let discord = state
        .providers
        .discord
        .as_ref()
        .ok_or_else(|| ApiError::from(EreborError::Internal("Discord OAuth not configured".into())))?;

    let provider_user = discord
        .authenticate(&req.code)
        .await
        .map_err(|e| ApiError::from(EreborError::AuthError(e.to_string())))?;

    let user_id = deterministic_user_id(&AuthProvider::Discord, &provider_user.provider_user_id);

    state
        .linking
        .link_identity(
            &user_id,
            AuthProvider::Discord,
            provider_user.provider_user_id,
            provider_user.email,
        )
        .await
        .map_err(|e| ApiError::from(EreborError::AuthError(e.to_string())))?;

    issue_tokens_and_respond(&state, &user_id, vec!["discord".into()]).await
}

/// POST /auth/github — Exchange GitHub OAuth code for tokens
pub async fn github_auth(
    State(state): State<AppState>,
    Json(req): Json<GitHubAuthRequest>,
) -> ApiResult<Json<AuthResponse>> {
    let github = state
        .providers
        .github
        .as_ref()
        .ok_or_else(|| ApiError::from(EreborError::Internal("GitHub OAuth not configured".into())))?;

    let provider_user = github
        .authenticate(&req.code)
        .await
        .map_err(|e| ApiError::from(EreborError::AuthError(e.to_string())))?;

    let user_id = deterministic_user_id(&AuthProvider::Github, &provider_user.provider_user_id);

    state
        .linking
        .link_identity(
            &user_id,
            AuthProvider::Github,
            provider_user.provider_user_id,
            provider_user.email,
        )
        .await
        .map_err(|e| ApiError::from(EreborError::AuthError(e.to_string())))?;

    issue_tokens_and_respond(&state, &user_id, vec!["github".into()]).await
}

/// POST /auth/farcaster/verify — Verify Farcaster message and authenticate
pub async fn farcaster_verify(
    State(state): State<AppState>,
    Json(req): Json<FarcasterVerifyRequest>,
) -> ApiResult<Json<AuthResponse>> {
    let provider_user = state
        .providers
        .farcaster
        .verify(&req.message, &req.signature)
        .await
        .map_err(|e| ApiError::from(EreborError::AuthError(e.to_string())))?;

    let user_id = deterministic_user_id(&AuthProvider::Farcaster, &provider_user.provider_user_id);

    state
        .linking
        .link_identity(
            &user_id,
            AuthProvider::Farcaster,
            provider_user.provider_user_id,
            None,
        )
        .await
        .map_err(|e| ApiError::from(EreborError::AuthError(e.to_string())))?;

    issue_tokens_and_respond(&state, &user_id, vec!["farcaster".into()]).await
}

/// POST /auth/telegram/verify — Verify Telegram auth data and authenticate
pub async fn telegram_verify(
    State(state): State<AppState>,
    Json(req): Json<TelegramVerifyRequest>,
) -> ApiResult<Json<AuthResponse>> {
    let provider_user = state
        .providers
        .telegram
        .verify(&req.auth_data)
        .await
        .map_err(|e| ApiError::from(EreborError::AuthError(e.to_string())))?;

    let user_id = deterministic_user_id(&AuthProvider::Telegram, &provider_user.provider_user_id);

    state
        .linking
        .link_identity(
            &user_id,
            AuthProvider::Telegram,
            provider_user.provider_user_id,
            None,
        )
        .await
        .map_err(|e| ApiError::from(EreborError::AuthError(e.to_string())))?;

    issue_tokens_and_respond(&state, &user_id, vec!["telegram".into()]).await
}

/// POST /auth/phone/send-otp — Send OTP to phone
pub async fn send_phone_otp(
    State(state): State<AppState>,
    Json(req): Json<SendPhoneOtpRequest>,
) -> ApiResult<Json<MessageResponse>> {
    state
        .providers
        .phone_otp
        .send_otp(&req.phone)
        .await
        .map_err(|e| ApiError::from(EreborError::AuthError(e.to_string())))?;

    Ok(Json(MessageResponse {
        message: "OTP sent".into(),
        success: true,
    }))
}

/// POST /auth/phone/verify — Verify phone OTP and authenticate
pub async fn verify_phone_otp(
    State(state): State<AppState>,
    Json(req): Json<VerifyPhoneOtpRequest>,
) -> ApiResult<Json<AuthResponse>> {
    let provider_user = state
        .providers
        .phone_otp
        .verify_otp(&req.phone, &req.code)
        .await
        .map_err(|e| ApiError::from(EreborError::AuthError(e.to_string())))?;

    let user_id = deterministic_user_id(&AuthProvider::Phone, &provider_user.provider_user_id);

    state
        .linking
        .link_identity(
            &user_id,
            AuthProvider::Phone,
            provider_user.provider_user_id,
            None,
        )
        .await
        .map_err(|e| ApiError::from(EreborError::AuthError(e.to_string())))?;

    issue_tokens_and_respond(&state, &user_id, vec!["phone".into()]).await
}

/// POST /auth/google — Exchange Google OAuth code for tokens
pub async fn google_auth(
    State(state): State<AppState>,
    Json(req): Json<GoogleAuthRequest>,
) -> ApiResult<Json<AuthResponse>> {
    let google = state
        .providers
        .google
        .as_ref()
        .ok_or_else(|| ApiError::from(EreborError::Internal("Google OAuth not configured".into())))?;

    let provider_user = google
        .authenticate(&req.code)
        .await
        .map_err(|e| ApiError::from(EreborError::AuthError(e.to_string())))?;

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
        .map_err(|e| ApiError::from(EreborError::AuthError(e.to_string())))?;

    issue_tokens_and_respond(&state, &user_id, vec!["google".into()]).await
}

/// POST /auth/email/send-otp — Send OTP to email
pub async fn send_otp(
    State(state): State<AppState>,
    Json(req): Json<SendOtpRequest>,
) -> ApiResult<Json<MessageResponse>> {
    state
        .providers
        .email_otp
        .send_otp(&req.email)
        .await
        .map_err(|e| ApiError::from(EreborError::AuthError(e.to_string())))?;

    Ok(Json(MessageResponse {
        message: "OTP sent".into(),
        success: true,
    }))
}

/// POST /auth/email/verify — Verify email OTP and authenticate
pub async fn verify_otp(
    State(state): State<AppState>,
    Json(req): Json<VerifyOtpRequest>,
) -> ApiResult<Json<AuthResponse>> {
    let provider_user = state
        .providers
        .email_otp
        .verify_otp(&req.email, &req.code)
        .await
        .map_err(|e| ApiError::from(EreborError::AuthError(e.to_string())))?;

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
        .map_err(|e| ApiError::from(EreborError::AuthError(e.to_string())))?;

    issue_tokens_and_respond(&state, &user_id, vec!["email".into()]).await
}

/// POST /auth/siwe/nonce — Return nonce for SIWE authentication
pub async fn siwe_nonce(
    State(state): State<AppState>,
) -> ApiResult<Json<NonceResponse>> {
    let nonce = state.providers.siwe.generate_nonce().await;
    Ok(Json(NonceResponse { nonce }))
}

/// POST /auth/farcaster/nonce — Return nonce for Farcaster authentication
pub async fn farcaster_nonce(
    State(state): State<AppState>,
) -> ApiResult<Json<NonceResponse>> {
    let nonce = state.providers.farcaster.generate_nonce().await;
    Ok(Json(NonceResponse { nonce }))
}

/// POST /auth/siwe/verify — Verify SIWE message and authenticate
pub async fn siwe_verify(
    State(state): State<AppState>,
    Json(req): Json<SiweVerifyRequest>,
) -> ApiResult<Json<AuthResponse>> {
    let provider_user = state
        .providers
        .siwe
        .verify(&req.message, &req.signature)
        .await
        .map_err(|e| ApiError::from(EreborError::AuthError(e.to_string())))?;

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
        .map_err(|e| ApiError::from(EreborError::AuthError(e.to_string())))?;

    issue_tokens_and_respond(&state, &user_id, vec!["siwe".into()]).await
}

/// POST /auth/refresh — Refresh session tokens
pub async fn refresh(
    State(state): State<AppState>,
    Json(req): Json<RefreshRequest>,
) -> ApiResult<Json<AuthResponse>> {
    let session = state
        .sessions
        .refresh_session(&req.refresh_token)
        .await
        .map_err(|e| ApiError::from(EreborError::AuthError(e.to_string())))?;

    let access_token = state
        .jwt
        .issue_access_token(&session.user_id, &session.providers)
        .map_err(|e| ApiError::from(EreborError::AuthError(e.to_string())))?;

    Ok(Json(AuthResponse {
        access_token,
        refresh_token: session.refresh_token,
        user_id: session.user_id.0.to_string(),
    }))
}

/// POST /auth/logout — Revoke session
pub async fn logout(
    State(_state): State<AppState>,
    RequireAuth(user_id): RequireAuth,
) -> ApiResult<Json<MessageResponse>> {
    // Note: In a production system, we'd revoke the specific session
    // For now, we just return success as the JWT will expire naturally
    tracing::info!("User {} logged out", user_id.0);

    Ok(Json(MessageResponse {
        message: "Logged out successfully".into(),
        success: true,
    }))
}

/// GET /auth/me — Get current user info
pub async fn me(
    State(state): State<AppState>,
    RequireAuth(user_id): RequireAuth,
) -> ApiResult<Json<MeResponse>> {
    let links = state
        .linking
        .get_linked_identities(&user_id)
        .await
        .map_err(|e| ApiError::from(EreborError::AuthError(e.to_string())))?;

    let providers: Vec<String> = links
        .iter()
        .map(|l| match &l.provider {
            AuthProvider::Google => "google".to_string(),
            AuthProvider::Apple => "apple".to_string(),
            AuthProvider::Twitter => "twitter".to_string(),
            AuthProvider::Discord => "discord".to_string(),
            AuthProvider::Github => "github".to_string(),
            AuthProvider::Email => "email".to_string(),
            AuthProvider::Phone => "phone".to_string(),
            AuthProvider::Siwe => "siwe".to_string(),
            AuthProvider::Passkey => "passkey".to_string(),
            AuthProvider::Farcaster => "farcaster".to_string(),
            AuthProvider::Telegram => "telegram".to_string(),
            AuthProvider::Custom(name) => name.clone(),
        })
        .collect();

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
        user_id: user_id.0.to_string(),
        providers,
        linked_identities,
    }))
}

/// POST /auth/link — Link additional provider to authenticated user
pub async fn link_provider(
    State(state): State<AppState>,
    RequireAuth(user_id): RequireAuth,
    Json(req): Json<LinkRequest>,
) -> ApiResult<Json<MessageResponse>> {
    state
        .linking
        .link_identity(
            &user_id,
            req.provider,
            req.provider_user_id,
            req.email,
        )
        .await
        .map_err(|e| ApiError::from(EreborError::AuthError(e.to_string())))?;

    Ok(Json(MessageResponse {
        message: "Identity linked".into(),
        success: true,
    }))
}

/// DELETE /auth/link/:provider — Unlink an auth method
pub async fn unlink_provider(
    State(state): State<AppState>,
    RequireAuth(user_id): RequireAuth,
    Path(provider_str): Path<String>,
) -> ApiResult<Json<MessageResponse>> {
    let provider: AuthProvider = match provider_str.as_str() {
        "google" => AuthProvider::Google,
        "apple" => AuthProvider::Apple,
        "twitter" => AuthProvider::Twitter,
        "discord" => AuthProvider::Discord,
        "github" => AuthProvider::Github,
        "email" => AuthProvider::Email,
        "phone" => AuthProvider::Phone,
        "siwe" => AuthProvider::Siwe,
        "passkey" => AuthProvider::Passkey,
        "farcaster" => AuthProvider::Farcaster,
        "telegram" => AuthProvider::Telegram,
        custom => AuthProvider::Custom(custom.to_string()),
    };

    state
        .linking
        .unlink_identity(&user_id, &provider)
        .await
        .map_err(|e| ApiError::from(EreborError::AuthError(e.to_string())))?;

    Ok(Json(MessageResponse {
        message: "Identity unlinked".into(),
        success: true,
    }))
}

// ---------------------------------------------------------------------------
// Router
// ---------------------------------------------------------------------------

/// Build the auth router
pub fn auth_router() -> Router<AppState> {
    // Public routes (no auth required)
    let public = Router::new()
        .route("/auth/google", post(google_auth))
        .route("/auth/apple", post(apple_auth))
        .route("/auth/twitter", post(twitter_auth))
        .route("/auth/discord", post(discord_auth))
        .route("/auth/github", post(github_auth))
        .route("/auth/email/send-otp", post(send_otp))
        .route("/auth/email/verify", post(verify_otp))
        .route("/auth/phone/send-otp", post(send_phone_otp))
        .route("/auth/phone/verify", post(verify_phone_otp))
        .route("/auth/siwe/nonce", post(siwe_nonce))
        .route("/auth/siwe/verify", post(siwe_verify))
        .route("/auth/farcaster/nonce", post(farcaster_nonce))
        .route("/auth/farcaster/verify", post(farcaster_verify))
        .route("/auth/telegram/verify", post(telegram_verify))
        .route("/auth/refresh", post(refresh));

    // Protected routes (JWT required)
    let protected = Router::new()
        .route("/auth/me", get(me))
        .route("/auth/logout", post(logout))
        .route("/auth/link", post(link_provider))
        .route("/auth/link/:provider", delete(unlink_provider));

    public.merge(protected)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::{
        body::Body,
        http::{Request, StatusCode},
    };
    use tower::util::ServiceExt;

    fn test_state() -> AppState {
        AppState::new().expect("Failed to create test state")
    }

    #[tokio::test]
    async fn test_send_otp_route() {
        let state = test_state();
        let app = auth_router().with_state(state);

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
    async fn test_siwe_nonce_route() {
        let state = test_state();
        let app = auth_router().with_state(state);

        let req = Request::builder()
            .method("POST")
            .uri("/auth/siwe/nonce")
            .header("content-type", "application/json")
            .body(Body::empty())
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

        let app = auth_router().with_state(state);
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
    }
}