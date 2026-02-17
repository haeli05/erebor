use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;
use erebor_common::EreborError;
use serde_json::json;
use tracing;

/// Unified API error response that maps EreborError to HTTP responses
pub struct ApiError(EreborError);

impl From<EreborError> for ApiError {
    fn from(err: EreborError) -> Self {
        ApiError(err)
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        // Log internal details for debugging but don't expose to user
        tracing::error!("API Error: {:?}", self.0);
        
        let (status, error_message, error_code) = match &self.0 {
            // Sanitized error responses - no internal details exposed
            EreborError::AuthError(_) => (StatusCode::UNAUTHORIZED, "Authentication failed".to_string(), "AUTH_ERROR"),
            EreborError::InvalidToken(_) => (StatusCode::UNAUTHORIZED, "Invalid or expired token".to_string(), "INVALID_TOKEN"),
            EreborError::Unauthorized => (StatusCode::UNAUTHORIZED, "Unauthorized".to_string(), "UNAUTHORIZED"),
            EreborError::NotFound(_) => (StatusCode::NOT_FOUND, "Resource not found".to_string(), "NOT_FOUND"),
            EreborError::RateLimited => (StatusCode::TOO_MANY_REQUESTS, "Rate limit exceeded".to_string(), "RATE_LIMITED"),
            EreborError::VaultError(_) => (StatusCode::UNPROCESSABLE_ENTITY, "Vault operation failed".to_string(), "VAULT_ERROR"),
            EreborError::ShareError(_) => (StatusCode::UNPROCESSABLE_ENTITY, "Secret sharing operation failed".to_string(), "SHARE_ERROR"),
            EreborError::EncryptionError(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Encryption operation failed".to_string(), "ENCRYPTION_ERROR"),
            EreborError::DatabaseError(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Database operation failed".to_string(), "DATABASE_ERROR"),
            EreborError::ChainError(_) => (StatusCode::UNPROCESSABLE_ENTITY, "Blockchain operation failed".to_string(), "CHAIN_ERROR"),
            EreborError::Internal(_) => (StatusCode::INTERNAL_SERVER_ERROR, "Internal server error".to_string(), "INTERNAL_ERROR"),
        };

        let body = Json(json!({
            "error": {
                "code": error_code,
                "message": error_message,
                "status": status.as_u16()
            }
        }));

        (status, body).into_response()
    }
}

/// Result type for API handlers
pub type ApiResult<T> = Result<T, ApiError>;

/// Convenience macro for converting any EreborError to ApiError
#[macro_export]
macro_rules! api_error {
    ($err:expr) => {
        $crate::error::ApiError::from($err)
    };
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::body::to_bytes;

    #[tokio::test]
    async fn test_auth_error_response() {
        let err = ApiError::from(EreborError::AuthError("Invalid credentials".into()));
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::UNAUTHORIZED);
    }

    #[tokio::test]
    async fn test_not_found_response() {
        let err = ApiError::from(EreborError::NotFound("User not found".into()));
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::NOT_FOUND);
    }

    #[tokio::test]
    async fn test_rate_limited_response() {
        let err = ApiError::from(EreborError::RateLimited);
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::TOO_MANY_REQUESTS);
    }

    #[tokio::test]
    async fn test_internal_error_response() {
        let err = ApiError::from(EreborError::Internal("Something went wrong".into()));
        let response = err.into_response();
        assert_eq!(response.status(), StatusCode::INTERNAL_SERVER_ERROR);
    }

    #[tokio::test]
    async fn test_error_response_body() {
        let err = ApiError::from(EreborError::NotFound("Wallet not found".into()));
        let response = err.into_response();
        
        let (_, body) = response.into_parts();
        let bytes = to_bytes(body, usize::MAX).await.unwrap();
        let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
        
        assert_eq!(json["error"]["code"], "NOT_FOUND");
        assert_eq!(json["error"]["message"], "Wallet not found");
        assert_eq!(json["error"]["status"], 404);
    }
}