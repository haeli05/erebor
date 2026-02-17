use std::collections::HashMap;
use std::sync::Arc;

use chrono::Utc;
use erebor_common::{AuthProvider, EreborError, LinkedIdentity, Result, UserId};
use tokio::sync::RwLock;
use tracing::info;

/// Trait for identity linking storage
#[async_trait::async_trait]
pub trait LinkingStore: Send + Sync {
    /// Store a linked identity
    async fn link(&self, identity: &LinkedIdentity) -> Result<()>;

    /// Remove a linked identity
    async fn unlink(&self, user_id: &UserId, provider: &AuthProvider) -> Result<()>;

    /// Get all linked identities for a user
    async fn get_links(&self, user_id: &UserId) -> Result<Vec<LinkedIdentity>>;

    /// Find user by provider + provider_user_id
    async fn find_by_provider(
        &self,
        provider: &AuthProvider,
        provider_user_id: &str,
    ) -> Result<Option<LinkedIdentity>>;

    /// Count linked identities for a user
    async fn count_links(&self, user_id: &UserId) -> Result<usize>;
}

/// In-memory linking store for development/testing
pub struct InMemoryLinkingStore {
    /// (user_id, provider) -> LinkedIdentity
    links: Arc<RwLock<HashMap<(String, String), LinkedIdentity>>>,
}

impl InMemoryLinkingStore {
    pub fn new() -> Self {
        Self {
            links: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    fn provider_key(provider: &AuthProvider) -> String {
        serde_json::to_string(provider).unwrap_or_default()
    }
}

impl Default for InMemoryLinkingStore {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl LinkingStore for InMemoryLinkingStore {
    async fn link(&self, identity: &LinkedIdentity) -> Result<()> {
        let key = (
            identity.user_id.0.to_string(),
            Self::provider_key(&identity.provider),
        );
        self.links.write().await.insert(key, identity.clone());
        Ok(())
    }

    async fn unlink(&self, user_id: &UserId, provider: &AuthProvider) -> Result<()> {
        let key = (user_id.0.to_string(), Self::provider_key(provider));
        self.links.write().await.remove(&key);
        Ok(())
    }

    async fn get_links(&self, user_id: &UserId) -> Result<Vec<LinkedIdentity>> {
        let uid = user_id.0.to_string();
        Ok(self
            .links
            .read()
            .await
            .values()
            .filter(|l| l.user_id.0.to_string() == uid)
            .cloned()
            .collect())
    }

    async fn find_by_provider(
        &self,
        provider: &AuthProvider,
        provider_user_id: &str,
    ) -> Result<Option<LinkedIdentity>> {
        Ok(self
            .links
            .read()
            .await
            .values()
            .find(|l| {
                l.provider == *provider && l.provider_user_id == provider_user_id
            })
            .cloned())
    }

    async fn count_links(&self, user_id: &UserId) -> Result<usize> {
        let uid = user_id.0.to_string();
        Ok(self
            .links
            .read()
            .await
            .values()
            .filter(|l| l.user_id.0.to_string() == uid)
            .count())
    }
}

/// Identity linking manager with safety checks
pub struct LinkingManager {
    store: Arc<dyn LinkingStore>,
}

impl LinkingManager {
    pub fn new(store: Arc<dyn LinkingStore>) -> Self {
        Self { store }
    }

    /// Link a new auth method to a user.
    /// If the provider+provider_user_id is already linked to a different user, error.
    pub async fn link_identity(
        &self,
        user_id: &UserId,
        provider: AuthProvider,
        provider_user_id: String,
        email: Option<String>,
    ) -> Result<LinkedIdentity> {
        // Check if this provider identity is already linked to someone else
        if let Some(existing) = self
            .store
            .find_by_provider(&provider, &provider_user_id)
            .await?
        {
            if existing.user_id != *user_id {
                return Err(EreborError::AuthError(
                    "This identity is already linked to another account".into(),
                ));
            }
            // Already linked to this user — return existing
            return Ok(existing);
        }

        let identity = LinkedIdentity {
            user_id: user_id.clone(),
            provider: provider.clone(),
            provider_user_id,
            email,
            linked_at: Utc::now(),
        };

        self.store.link(&identity).await?;
        info!(user_id = ?user_id, provider = ?provider, "Identity linked");
        Ok(identity)
    }

    /// Unlink an auth method from a user.
    /// Safety: must keep at least one linked identity.
    pub async fn unlink_identity(
        &self,
        user_id: &UserId,
        provider: &AuthProvider,
    ) -> Result<()> {
        let count = self.store.count_links(user_id).await?;
        if count <= 1 {
            return Err(EreborError::AuthError(
                "Cannot unlink last identity — must keep at least one auth method".into(),
            ));
        }

        self.store.unlink(user_id, provider).await?;
        info!(user_id = ?user_id, provider = ?provider, "Identity unlinked");
        Ok(())
    }

    /// Get all linked identities for a user
    pub async fn get_linked_identities(&self, user_id: &UserId) -> Result<Vec<LinkedIdentity>> {
        self.store.get_links(user_id).await
    }

    /// Find which user owns a given provider identity
    pub async fn find_user_by_provider(
        &self,
        provider: &AuthProvider,
        provider_user_id: &str,
    ) -> Result<Option<LinkedIdentity>> {
        self.store.find_by_provider(provider, provider_user_id).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn make_manager() -> LinkingManager {
        LinkingManager::new(Arc::new(InMemoryLinkingStore::new()))
    }

    #[tokio::test]
    async fn test_link_identity() {
        let mgr = make_manager();
        let user_id = UserId::new();

        let identity = mgr
            .link_identity(
                &user_id,
                AuthProvider::Google,
                "google-123".into(),
                Some("test@gmail.com".into()),
            )
            .await
            .unwrap();

        assert_eq!(identity.user_id, user_id);
        assert_eq!(identity.provider, AuthProvider::Google);
        assert_eq!(identity.provider_user_id, "google-123");
    }

    #[tokio::test]
    async fn test_link_multiple_providers() {
        let mgr = make_manager();
        let user_id = UserId::new();

        mgr.link_identity(&user_id, AuthProvider::Google, "g-123".into(), None)
            .await
            .unwrap();
        mgr.link_identity(&user_id, AuthProvider::Email, "e-abc".into(), Some("a@b.com".into()))
            .await
            .unwrap();

        let links = mgr.get_linked_identities(&user_id).await.unwrap();
        assert_eq!(links.len(), 2);
    }

    #[tokio::test]
    async fn test_link_idempotent() {
        let mgr = make_manager();
        let user_id = UserId::new();

        mgr.link_identity(&user_id, AuthProvider::Google, "g-123".into(), None)
            .await
            .unwrap();
        // Linking same identity again should succeed (idempotent)
        let result = mgr
            .link_identity(&user_id, AuthProvider::Google, "g-123".into(), None)
            .await;
        assert!(result.is_ok());
    }

    #[tokio::test]
    async fn test_link_already_linked_to_other_user() {
        let mgr = make_manager();
        let user1 = UserId::new();
        let user2 = UserId::new();

        mgr.link_identity(&user1, AuthProvider::Google, "g-123".into(), None)
            .await
            .unwrap();

        let result = mgr
            .link_identity(&user2, AuthProvider::Google, "g-123".into(), None)
            .await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_unlink_identity() {
        let mgr = make_manager();
        let user_id = UserId::new();

        mgr.link_identity(&user_id, AuthProvider::Google, "g-123".into(), None)
            .await
            .unwrap();
        mgr.link_identity(&user_id, AuthProvider::Email, "e-abc".into(), None)
            .await
            .unwrap();

        mgr.unlink_identity(&user_id, &AuthProvider::Google)
            .await
            .unwrap();

        let links = mgr.get_linked_identities(&user_id).await.unwrap();
        assert_eq!(links.len(), 1);
        assert_eq!(links[0].provider, AuthProvider::Email);
    }

    #[tokio::test]
    async fn test_cannot_unlink_last_identity() {
        let mgr = make_manager();
        let user_id = UserId::new();

        mgr.link_identity(&user_id, AuthProvider::Google, "g-123".into(), None)
            .await
            .unwrap();

        let result = mgr.unlink_identity(&user_id, &AuthProvider::Google).await;
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("Cannot unlink last identity"));
    }

    #[tokio::test]
    async fn test_find_user_by_provider() {
        let mgr = make_manager();
        let user_id = UserId::new();

        mgr.link_identity(&user_id, AuthProvider::Siwe, "0xabc".into(), None)
            .await
            .unwrap();

        let found = mgr
            .find_user_by_provider(&AuthProvider::Siwe, "0xabc")
            .await
            .unwrap();
        assert!(found.is_some());
        assert_eq!(found.unwrap().user_id, user_id);

        let not_found = mgr
            .find_user_by_provider(&AuthProvider::Siwe, "0xdef")
            .await
            .unwrap();
        assert!(not_found.is_none());
    }

    #[tokio::test]
    async fn test_get_linked_identities_empty() {
        let mgr = make_manager();
        let user_id = UserId::new();
        let links = mgr.get_linked_identities(&user_id).await.unwrap();
        assert!(links.is_empty());
    }
}
