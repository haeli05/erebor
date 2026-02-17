use std::collections::HashMap;
use std::sync::Arc;

use chrono::{DateTime, Duration, Utc};
use erebor_common::{EreborError, Result, UserId};
use rand::Rng;
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;
use tracing::{info, warn};

/// Session data stored in the session store
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Session {
    pub session_id: String,
    pub user_id: UserId,
    pub refresh_token: String,
    pub providers: Vec<String>,
    pub created_at: DateTime<Utc>,
    pub expires_at: DateTime<Utc>,
    pub last_refreshed_at: DateTime<Utc>,
    pub revoked: bool,
}

/// Trait for session storage backends
#[async_trait::async_trait]
pub trait SessionStore: Send + Sync {
    async fn create(&self, session: &Session) -> Result<()>;
    async fn get(&self, session_id: &str) -> Result<Option<Session>>;
    async fn get_by_refresh_token(&self, refresh_token: &str) -> Result<Option<Session>>;
    async fn update(&self, session: &Session) -> Result<()>;
    async fn revoke(&self, session_id: &str) -> Result<()>;
    async fn revoke_all_for_user(&self, user_id: &UserId) -> Result<u64>;
    async fn delete_expired(&self) -> Result<u64>;
}

/// In-memory session store (for development/testing)
pub struct InMemorySessionStore {
    sessions: Arc<RwLock<HashMap<String, Session>>>,
}

impl InMemorySessionStore {
    pub fn new() -> Self {
        Self {
            sessions: Arc::new(RwLock::new(HashMap::new())),
        }
    }
}

impl Default for InMemorySessionStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl SessionStore for InMemorySessionStore {
    async fn create(&self, session: &Session) -> Result<()> {
        self.sessions
            .write()
            .await
            .insert(session.session_id.clone(), session.clone());
        Ok(())
    }

    async fn get(&self, session_id: &str) -> Result<Option<Session>> {
        Ok(self.sessions.read().await.get(session_id).cloned())
    }

    async fn get_by_refresh_token(&self, refresh_token: &str) -> Result<Option<Session>> {
        Ok(self
            .sessions
            .read()
            .await
            .values()
            .find(|s| s.refresh_token == refresh_token)
            .cloned())
    }

    async fn update(&self, session: &Session) -> Result<()> {
        self.sessions
            .write()
            .await
            .insert(session.session_id.clone(), session.clone());
        Ok(())
    }

    async fn revoke(&self, session_id: &str) -> Result<()> {
        if let Some(s) = self.sessions.write().await.get_mut(session_id) {
            s.revoked = true;
        }
        Ok(())
    }

    async fn revoke_all_for_user(&self, user_id: &UserId) -> Result<u64> {
        let mut store = self.sessions.write().await;
        let mut count = 0u64;
        for session in store.values_mut() {
            if session.user_id == *user_id && !session.revoked {
                session.revoked = true;
                count += 1;
            }
        }
        Ok(count)
    }

    async fn delete_expired(&self) -> Result<u64> {
        let mut store = self.sessions.write().await;
        let now = Utc::now();
        let before = store.len();
        store.retain(|_, s| s.expires_at > now);
        Ok((before - store.len()) as u64)
    }
}

/// Session manager handles creation, validation, refresh, and revocation
pub struct SessionManager {
    store: Arc<dyn SessionStore>,
    session_ttl: Duration,
}

impl SessionManager {
    pub fn new(store: Arc<dyn SessionStore>) -> Self {
        Self {
            store,
            session_ttl: Duration::days(30),
        }
    }

    pub fn with_ttl(store: Arc<dyn SessionStore>, ttl: Duration) -> Self {
        Self {
            store,
            session_ttl: ttl,
        }
    }

    fn generate_token() -> String {
        let bytes: [u8; 32] = rand::thread_rng().gen();
        hex::encode(bytes)
    }

    /// Create a new session for a user
    pub async fn create_session(
        &self,
        user_id: &UserId,
        providers: Vec<String>,
    ) -> Result<Session> {
        let now = Utc::now();
        let session = Session {
            session_id: uuid::Uuid::new_v4().to_string(),
            user_id: user_id.clone(),
            refresh_token: Self::generate_token(),
            providers,
            created_at: now,
            expires_at: now + self.session_ttl,
            last_refreshed_at: now,
            revoked: false,
        };

        self.store.create(&session).await?;
        info!(session_id = %session.session_id, user_id = ?user_id, "Session created");
        Ok(session)
    }

    /// Validate a session by ID
    pub async fn validate_session(&self, session_id: &str) -> Result<Session> {
        let session = self
            .store
            .get(session_id)
            .await?
            .ok_or(EreborError::NotFound("Session not found".into()))?;

        if session.revoked {
            return Err(EreborError::Unauthorized);
        }

        if session.expires_at < Utc::now() {
            return Err(EreborError::InvalidToken("Session expired".into()));
        }

        Ok(session)
    }

    /// Refresh a session using a refresh token.
    /// Implements refresh token rotation: old token is invalidated, new one issued.
    pub async fn refresh_session(&self, refresh_token: &str) -> Result<Session> {
        let session = self
            .store
            .get_by_refresh_token(refresh_token)
            .await?
            .ok_or(EreborError::InvalidToken(
                "Invalid refresh token".into(),
            ))?;

        if session.revoked {
            // Possible token theft - revoke all sessions for this user
            warn!(
                user_id = ?session.user_id,
                "Attempted refresh with revoked token — revoking all sessions"
            );
            self.store.revoke_all_for_user(&session.user_id).await?;
            return Err(EreborError::Unauthorized);
        }

        if session.expires_at < Utc::now() {
            return Err(EreborError::InvalidToken("Session expired".into()));
        }

        // Rotate refresh token
        let now = Utc::now();
        let mut new_session = session.clone();
        new_session.refresh_token = Self::generate_token();
        new_session.last_refreshed_at = now;
        new_session.expires_at = now + self.session_ttl;

        // Revoke old session
        self.store.revoke(&session.session_id).await?;

        // Create new session
        new_session.session_id = uuid::Uuid::new_v4().to_string();
        self.store.create(&new_session).await?;

        info!(
            old_session = %session.session_id,
            new_session = %new_session.session_id,
            "Session refreshed with token rotation"
        );

        Ok(new_session)
    }

    /// Revoke a specific session
    pub async fn revoke_session(&self, session_id: &str) -> Result<()> {
        self.store.revoke(session_id).await?;
        info!(session_id = %session_id, "Session revoked");
        Ok(())
    }

    /// Revoke all sessions for a user
    pub async fn revoke_all(&self, user_id: &UserId) -> Result<u64> {
        let count = self.store.revoke_all_for_user(user_id).await?;
        info!(user_id = ?user_id, count = count, "All sessions revoked");
        Ok(count)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_manager() -> SessionManager {
        SessionManager::new(Arc::new(InMemorySessionStore::new()))
    }

    #[tokio::test]
    async fn test_create_and_validate_session() {
        let mgr = make_manager();
        let user_id = UserId::new();
        let session = mgr
            .create_session(&user_id, vec!["google".into()])
            .await
            .unwrap();

        assert!(!session.revoked);
        assert_eq!(session.user_id, user_id);

        let validated = mgr.validate_session(&session.session_id).await.unwrap();
        assert_eq!(validated.session_id, session.session_id);
    }

    #[tokio::test]
    async fn test_validate_nonexistent_session() {
        let mgr = make_manager();
        assert!(mgr.validate_session("nonexistent").await.is_err());
    }

    #[tokio::test]
    async fn test_revoke_session() {
        let mgr = make_manager();
        let user_id = UserId::new();
        let session = mgr
            .create_session(&user_id, vec![])
            .await
            .unwrap();

        mgr.revoke_session(&session.session_id).await.unwrap();
        assert!(mgr.validate_session(&session.session_id).await.is_err());
    }

    #[tokio::test]
    async fn test_refresh_token_rotation() {
        let mgr = make_manager();
        let user_id = UserId::new();
        let session = mgr
            .create_session(&user_id, vec!["email".into()])
            .await
            .unwrap();

        let old_refresh = session.refresh_token.clone();
        let new_session = mgr.refresh_session(&old_refresh).await.unwrap();

        // New session has different refresh token
        assert_ne!(new_session.refresh_token, old_refresh);
        assert_eq!(new_session.user_id, user_id);
        assert_ne!(new_session.session_id, session.session_id);

        // Old refresh token no longer works
        assert!(mgr.refresh_session(&old_refresh).await.is_err());
    }

    #[tokio::test]
    async fn test_revoked_refresh_revokes_all() {
        let mgr = make_manager();
        let user_id = UserId::new();

        let s1 = mgr
            .create_session(&user_id, vec![])
            .await
            .unwrap();
        let s2 = mgr
            .create_session(&user_id, vec![])
            .await
            .unwrap();

        // Revoke s1, then try to refresh it — should revoke all
        mgr.revoke_session(&s1.session_id).await.unwrap();
        let result = mgr.refresh_session(&s1.refresh_token).await;
        assert!(result.is_err());

        // s2 should also be revoked now
        assert!(mgr.validate_session(&s2.session_id).await.is_err());
    }

    #[tokio::test]
    async fn test_revoke_all_for_user() {
        let mgr = make_manager();
        let user_id = UserId::new();

        let s1 = mgr.create_session(&user_id, vec![]).await.unwrap();
        let s2 = mgr.create_session(&user_id, vec![]).await.unwrap();

        let count = mgr.revoke_all(&user_id).await.unwrap();
        assert_eq!(count, 2);

        assert!(mgr.validate_session(&s1.session_id).await.is_err());
        assert!(mgr.validate_session(&s2.session_id).await.is_err());
    }

    #[tokio::test]
    async fn test_expired_session() {
        let store = Arc::new(InMemorySessionStore::new());
        let mgr = SessionManager::with_ttl(store, Duration::seconds(-1));
        let user_id = UserId::new();

        let session = mgr.create_session(&user_id, vec![]).await.unwrap();
        assert!(mgr.validate_session(&session.session_id).await.is_err());
    }

    #[tokio::test]
    async fn test_delete_expired() {
        let store = Arc::new(InMemorySessionStore::new());
        let mgr = SessionManager::with_ttl(store.clone(), Duration::seconds(-1));
        let user_id = UserId::new();

        mgr.create_session(&user_id, vec![]).await.unwrap();
        mgr.create_session(&user_id, vec![]).await.unwrap();

        let deleted = store.delete_expired().await.unwrap();
        assert_eq!(deleted, 2);
    }
}
