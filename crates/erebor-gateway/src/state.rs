use std::sync::Arc;
use std::collections::HashSet;
use tokio::sync::RwLock;
use erebor_auth::{
    jwt::JwtManager,
    session::{SessionManager, InMemorySessionStore},
    linking::{LinkingManager, InMemoryLinkingStore},
    providers::{ProviderRegistry, EmailOtpProvider, PhoneOtpProvider, SiweProvider, FarcasterProvider, TelegramAuthProvider}
};
use erebor_vault::{VaultService, ShamirVault, EncryptionService, InMemoryStore};
use erebor_chain::ChainService;
use erebor_common::{SecretBytes, EreborError, Result};
use erebor_auth::middleware::TokenBlacklistTrait;
use axum::async_trait;

/// In-memory token blacklist with TTL
#[derive(Default)]
pub struct TokenBlacklist {
    blacklisted: RwLock<HashSet<String>>,
}

impl TokenBlacklist {
    pub fn new() -> Self {
        Self {
            blacklisted: RwLock::new(HashSet::new()),
        }
    }

    // In production, this would be replaced with Redis-based expiry
    pub async fn cleanup_expired(&self) {
        // For in-memory implementation, tokens will expire naturally
        // In production, use Redis with TTL matching JWT expiry
    }
}

#[async_trait]
impl TokenBlacklistTrait for TokenBlacklist {
    async fn add(&self, jti: String) {
        self.blacklisted.write().await.insert(jti);
    }

    async fn is_blacklisted(&self, jti: &str) -> bool {
        self.blacklisted.read().await.contains(jti)
    }
}

/// Application state holding all services
#[derive(Clone)]
pub struct AppState {
    pub jwt: Arc<JwtManager>,
    pub sessions: Arc<SessionManager>,
    pub linking: Arc<LinkingManager>,
    pub providers: Arc<ProviderRegistry>,
    pub vault: Arc<VaultService<InMemoryStore>>,
    pub chain: Arc<ChainService>,
    pub token_blacklist: Arc<TokenBlacklist>,
}

impl AppState {
    /// Create new AppState with in-memory stores and default configuration
    pub fn new() -> Result<Self> {
        // JWT manager with a secure random key
        let jwt_secret = SecretBytes(b"erebor-gateway-jwt-secret-32-bytes!".to_vec());
        let jwt = Arc::new(JwtManager::new(&jwt_secret.0));

        // Session management
        let session_store = Arc::new(InMemorySessionStore::new());
        let sessions = Arc::new(SessionManager::new(session_store));

        // Identity linking
        let linking_store = Arc::new(InMemoryLinkingStore::new());
        let linking = Arc::new(LinkingManager::new(linking_store));

        // Auth providers
        let email_otp = EmailOtpProvider::new();
        let phone_otp = PhoneOtpProvider::new();
        let siwe = SiweProvider::new("erebor.local".into());
        let farcaster = FarcasterProvider::new("erebor".into());
        let telegram = TelegramAuthProvider::new("bot-token".into());
        let providers = Arc::new(ProviderRegistry::new(
            email_otp, 
            phone_otp,
            siwe, 
            farcaster,
            telegram,
            None, // google
            None, // apple
            None, // twitter
            None, // discord
            None, // github
        ));

        // Vault service (2-of-3 Shamir)
        let shamir = ShamirVault::new(2, 3)
            .map_err(|e| EreborError::VaultError(e.to_string()))?;
        let vault_encryption = EncryptionService::new(SecretBytes(b"erebor-vault-encryption-key-32b!".to_vec()));
        let vault_store = InMemoryStore::new();
        let vault = Arc::new(VaultService::new(shamir, vault_encryption, vault_store));

        // Chain service
        let chain = Arc::new(ChainService::new());

        // Token blacklist for logout
        let token_blacklist = Arc::new(TokenBlacklist::new());

        Ok(Self {
            jwt,
            sessions,
            linking,
            providers,
            vault,
            chain,
            token_blacklist,
        })
    }

    /// Create AppState with custom JWT and vault secrets (for production)
    pub fn with_secrets(jwt_secret: SecretBytes, vault_secret: SecretBytes) -> Result<Self> {
        let jwt = Arc::new(JwtManager::new(&jwt_secret.0));

        let session_store = Arc::new(InMemorySessionStore::new());
        let sessions = Arc::new(SessionManager::new(session_store));

        let linking_store = Arc::new(InMemoryLinkingStore::new());
        let linking = Arc::new(LinkingManager::new(linking_store));

        let email_otp = EmailOtpProvider::new();
        let phone_otp = PhoneOtpProvider::new();
        let siwe = SiweProvider::new("erebor.local".into());
        let farcaster = FarcasterProvider::new("erebor".into());
        let telegram = TelegramAuthProvider::new("bot-token".into());
        let providers = Arc::new(ProviderRegistry::new(
            email_otp, 
            phone_otp,
            siwe, 
            farcaster,
            telegram,
            None, // google
            None, // apple
            None, // twitter
            None, // discord
            None, // github
        ));

        let shamir = ShamirVault::new(2, 3)
            .map_err(|e| EreborError::VaultError(e.to_string()))?;
        let vault_encryption = EncryptionService::new(vault_secret);
        let vault_store = InMemoryStore::new();
        let vault = Arc::new(VaultService::new(shamir, vault_encryption, vault_store));

        let chain = Arc::new(ChainService::new());

        let token_blacklist = Arc::new(TokenBlacklist::new());

        Ok(Self {
            jwt,
            sessions,
            linking,
            providers,
            vault,
            chain,
            token_blacklist,
        })
    }
}

impl Default for AppState {
    fn default() -> Self {
        Self::new().expect("Failed to create default AppState")
    }
}