use axum::async_trait;
use axum::extract::FromRequestParts;
use axum::http::request::Parts;
use erebor_auth::middleware::AuthenticatedUser;
use erebor_common::UserId;
use crate::error::ApiError;
use erebor_common::EreborError;

/// Axum extractor that requires authentication
/// Extracts the authenticated user from request extensions
pub struct RequireAuth(pub UserId);

#[async_trait]
impl<S> FromRequestParts<S> for RequireAuth
where
    S: Send + Sync,
{
    type Rejection = ApiError;

    async fn from_request_parts(parts: &mut Parts, _state: &S) -> Result<Self, Self::Rejection> {
        let auth_user = parts
            .extensions
            .get::<AuthenticatedUser>()
            .ok_or_else(|| ApiError::from(EreborError::Unauthorized))?;

        Ok(RequireAuth(auth_user.user_id.clone()))
    }
}