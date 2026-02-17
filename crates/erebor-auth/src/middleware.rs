use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use axum::body::Body;
use axum::extract::Request;
use axum::http::{header, StatusCode};
use axum::middleware::Next;
use axum::response::{IntoResponse, Response};
use erebor_common::UserId;
use tokio::sync::RwLock;
use tracing::warn;

use crate::jwt::{Claims, JwtManager};

/// Authenticated user extracted from JWT
#[derive(Debug, Clone)]
pub struct AuthenticatedUser {
    pub user_id: UserId,
    pub claims: Claims,
}

/// Extract and validate JWT from Authorization header.
/// Inserts `AuthenticatedUser` as a request extension.
pub async fn auth_middleware(
    mut request: Request<Body>,
    next: Next,
) -> std::result::Result<Response, StatusCode> {
    let jwt_manager = request
        .extensions()
        .get::<Arc<JwtManager>>()
        .cloned()
        .ok_or(StatusCode::INTERNAL_SERVER_ERROR)?;

    let auth_header = request
        .headers()
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let token = auth_header
        .strip_prefix("Bearer ")
        .ok_or(StatusCode::UNAUTHORIZED)?;

    let token_data = jwt_manager.verify(token).map_err(|_| StatusCode::UNAUTHORIZED)?;

    let user_id = token_data
        .claims
        .sub
        .parse::<uuid::Uuid>()
        .map(UserId)
        .map_err(|_| StatusCode::UNAUTHORIZED)?;

    let auth_user = AuthenticatedUser {
        user_id,
        claims: token_data.claims,
    };

    request.extensions_mut().insert(auth_user);
    Ok(next.run(request).await)
}

/// Simple in-memory rate limiter (token bucket per key)
pub struct RateLimiter {
    /// key -> (tokens, last_refill)
    buckets: Arc<RwLock<HashMap<String, (f64, Instant)>>>,
    /// Max tokens in bucket
    max_tokens: f64,
    /// Tokens added per second
    refill_rate: f64,
}

impl RateLimiter {
    pub fn new(max_tokens: f64, refill_rate: f64) -> Self {
        Self {
            buckets: Arc::new(RwLock::new(HashMap::new())),
            max_tokens,
            refill_rate,
        }
    }

    /// Check if a request is allowed for the given key.
    /// Returns Ok(()) if allowed, Err if rate limited.
    pub async fn check(&self, key: &str) -> std::result::Result<(), ()> {
        let mut buckets = self.buckets.write().await;
        let now = Instant::now();

        let entry = buckets
            .entry(key.to_string())
            .or_insert((self.max_tokens, now));

        // Refill tokens based on elapsed time
        let elapsed = entry.1.elapsed().as_secs_f64();
        entry.0 = (entry.0 + elapsed * self.refill_rate).min(self.max_tokens);
        entry.1 = now;

        if entry.0 >= 1.0 {
            entry.0 -= 1.0;
            Ok(())
        } else {
            Err(())
        }
    }
}

/// Rate limiting middleware using client IP (or fallback)
pub async fn rate_limit_middleware(
    request: Request<Body>,
    next: Next,
) -> std::result::Result<Response, Response> {
    let limiter = request.extensions().get::<Arc<RateLimiter>>().cloned();

    if let Some(limiter) = limiter {
        // Use X-Forwarded-For, X-Real-IP, or "unknown" as key
        let key = request
            .headers()
            .get("x-forwarded-for")
            .or_else(|| request.headers().get("x-real-ip"))
            .and_then(|v| v.to_str().ok())
            .unwrap_or("unknown")
            .to_string();

        if limiter.check(&key).await.is_err() {
            warn!(key = %key, "Rate limited");
            return Err((StatusCode::TOO_MANY_REQUESTS, "Rate limited").into_response());
        }
    }

    Ok(next.run(request).await)
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::Body;
    use axum::http::Request;
    use axum::middleware;
    use axum::routing::get;
    use axum::Router;
    use tower::ServiceExt;

    fn test_jwt_manager() -> Arc<JwtManager> {
        Arc::new(JwtManager::new(b"test-secret-key-at-least-32-bytes!"))
    }

    async fn ok_handler() -> &'static str {
        "ok"
    }

    fn app_with_auth() -> Router {
        let jwt = test_jwt_manager();
        Router::new()
            .route("/protected", get(ok_handler))
            .layer(middleware::from_fn(auth_middleware))
            .layer(axum::Extension(jwt.clone()))
    }

    #[tokio::test]
    async fn test_auth_middleware_valid_token() {
        let jwt = test_jwt_manager();
        let user_id = UserId::new();
        let token = jwt
            .issue_access_token(&user_id, &["google".into()])
            .unwrap();

        let app = app_with_auth();
        let req = Request::builder()
            .uri("/protected")
            .header("Authorization", format!("Bearer {token}"))
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::OK);
    }

    #[tokio::test]
    async fn test_auth_middleware_no_header() {
        let app = app_with_auth();
        let req = Request::builder()
            .uri("/protected")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_auth_middleware_invalid_token() {
        let app = app_with_auth();
        let req = Request::builder()
            .uri("/protected")
            .header("Authorization", "Bearer invalid-token")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_auth_middleware_wrong_scheme() {
        let app = app_with_auth();
        let req = Request::builder()
            .uri("/protected")
            .header("Authorization", "Basic dXNlcjpwYXNz")
            .body(Body::empty())
            .unwrap();

        let resp = app.oneshot(req).await.unwrap();
        assert_eq!(resp.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_rate_limiter_allows_under_limit() {
        let limiter = RateLimiter::new(5.0, 1.0);
        for _ in 0..5 {
            assert!(limiter.check("test-key").await.is_ok());
        }
    }

    #[tokio::test]
    async fn test_rate_limiter_blocks_over_limit() {
        let limiter = RateLimiter::new(2.0, 0.0); // no refill
        assert!(limiter.check("key").await.is_ok());
        assert!(limiter.check("key").await.is_ok());
        assert!(limiter.check("key").await.is_err());
    }

    #[tokio::test]
    async fn test_rate_limiter_separate_keys() {
        let limiter = RateLimiter::new(1.0, 0.0);
        assert!(limiter.check("key-a").await.is_ok());
        assert!(limiter.check("key-b").await.is_ok());
        assert!(limiter.check("key-a").await.is_err());
    }

    #[tokio::test]
    async fn test_rate_limiter_refills() {
        let limiter = RateLimiter::new(1.0, 100.0); // fast refill
        assert!(limiter.check("key").await.is_ok());
        tokio::time::sleep(std::time::Duration::from_millis(50)).await;
        assert!(limiter.check("key").await.is_ok());
    }
}
