pub mod jwt;
pub mod providers;
pub mod session;
pub mod linking;
pub mod middleware;
pub mod routes;

use erebor_common::{AuthProvider, UserId};
use sha2::{Sha256, Digest};

/// Deterministic user ID from provider + provider_user_id
/// Same auth always maps to the same internal user
pub fn deterministic_user_id(provider: &AuthProvider, provider_user_id: &str) -> UserId {
    let provider_str = serde_json::to_string(provider).unwrap_or_default();
    let mut hasher = Sha256::new();
    hasher.update(provider_str.as_bytes());
    hasher.update(b"||");
    hasher.update(provider_user_id.as_bytes());
    let hash = hasher.finalize();
    let uuid = uuid::Uuid::from_slice(&hash[..16]).unwrap_or(uuid::Uuid::new_v4());
    UserId(uuid)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_deterministic_user_id_consistency() {
        let id1 = deterministic_user_id(&AuthProvider::Google, "user123");
        let id2 = deterministic_user_id(&AuthProvider::Google, "user123");
        assert_eq!(id1, id2, "Same provider+user must produce same ID");
    }

    #[test]
    fn test_deterministic_user_id_different_providers() {
        let id1 = deterministic_user_id(&AuthProvider::Google, "user123");
        let id2 = deterministic_user_id(&AuthProvider::Apple, "user123");
        assert_ne!(id1, id2, "Different providers must produce different IDs");
    }

    #[test]
    fn test_deterministic_user_id_different_users() {
        let id1 = deterministic_user_id(&AuthProvider::Google, "user123");
        let id2 = deterministic_user_id(&AuthProvider::Google, "user456");
        assert_ne!(id1, id2, "Different users must produce different IDs");
    }
}
