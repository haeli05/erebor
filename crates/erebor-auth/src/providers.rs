use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use chrono::Utc;
use erebor_common::{AuthProvider, EreborError, Result};
use rand::Rng;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use tokio::sync::RwLock;
use tracing::{info, warn};

/// User info returned from a provider after authentication
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ProviderUser {
    pub provider: AuthProvider,
    pub provider_user_id: String,
    pub email: Option<String>,
    pub name: Option<String>,
    pub avatar_url: Option<String>,
}

/// Trait for authentication providers
#[async_trait::async_trait]
pub trait AuthProviderHandler: Send + Sync {
    /// Authenticate with provider-specific credentials and return user info
    async fn authenticate(&self, credential: &str) -> Result<ProviderUser>;
    /// Which provider this handler is for
    fn provider(&self) -> AuthProvider;
}

// ---------------------------------------------------------------------------
// Google OAuth
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct GoogleOAuthConfig {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
}

pub struct GoogleOAuthProvider {
    config: GoogleOAuthConfig,
    http: reqwest::Client,
}

#[derive(Deserialize)]
struct GoogleTokenResponse {
    access_token: String,
    #[allow(dead_code)]
    token_type: Option<String>,
    #[allow(dead_code)]
    expires_in: Option<u64>,
}

#[derive(Deserialize)]
struct GoogleUserInfo {
    sub: String,
    email: Option<String>,
    name: Option<String>,
    picture: Option<String>,
}

impl GoogleOAuthProvider {
    pub fn new(config: GoogleOAuthConfig) -> Self {
        Self {
            config,
            http: reqwest::Client::new(),
        }
    }
}

#[async_trait::async_trait]
impl AuthProviderHandler for GoogleOAuthProvider {
    async fn authenticate(&self, code: &str) -> Result<ProviderUser> {
        // Exchange authorization code for tokens
        let token_resp = self
            .http
            .post("https://oauth2.googleapis.com/token")
            .form(&[
                ("code", code),
                ("client_id", &self.config.client_id),
                ("client_secret", &self.config.client_secret),
                ("redirect_uri", &self.config.redirect_uri),
                ("grant_type", "authorization_code"),
            ])
            .send()
            .await
            .map_err(|e| EreborError::AuthError(format!("Google token exchange failed: {e}")))?;

        if !token_resp.status().is_success() {
            let body = token_resp.text().await.unwrap_or_default();
            return Err(EreborError::AuthError(format!(
                "Google token exchange error: {body}"
            )));
        }

        let tokens: GoogleTokenResponse = token_resp
            .json()
            .await
            .map_err(|e| EreborError::AuthError(format!("Failed to parse token response: {e}")))?;

        // Get user info
        let user_resp = self
            .http
            .get("https://www.googleapis.com/oauth2/v3/userinfo")
            .bearer_auth(&tokens.access_token)
            .send()
            .await
            .map_err(|e| EreborError::AuthError(format!("Google userinfo failed: {e}")))?;

        let user_info: GoogleUserInfo = user_resp
            .json()
            .await
            .map_err(|e| EreborError::AuthError(format!("Failed to parse userinfo: {e}")))?;

        info!(provider = "google", sub = %user_info.sub, "Google OAuth successful");

        Ok(ProviderUser {
            provider: AuthProvider::Google,
            provider_user_id: user_info.sub,
            email: user_info.email,
            name: user_info.name,
            avatar_url: user_info.picture,
        })
    }

    fn provider(&self) -> AuthProvider {
        AuthProvider::Google
    }
}

// ---------------------------------------------------------------------------
// Email OTP
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
struct OtpEntry {
    code: String,
    created_at: Instant,
    attempts: u32,
}

/// Email OTP provider with in-memory store (swap for Redis in production)
pub struct EmailOtpProvider {
    /// email -> OtpEntry
    otps: Arc<RwLock<HashMap<String, OtpEntry>>>,
    /// Rate limiting: email -> (count, window_start)
    rate_limits: Arc<RwLock<HashMap<String, (u32, Instant)>>>,
    /// OTP validity duration
    ttl: Duration,
    /// Max verification attempts per OTP
    max_attempts: u32,
    /// Max OTP sends per email per window
    max_sends_per_window: u32,
    /// Rate limit window
    rate_window: Duration,
}

impl EmailOtpProvider {
    pub fn new() -> Self {
        Self {
            otps: Arc::new(RwLock::new(HashMap::new())),
            rate_limits: Arc::new(RwLock::new(HashMap::new())),
            ttl: Duration::from_secs(600), // 10 minutes
            max_attempts: 3,
            max_sends_per_window: 5,
            rate_window: Duration::from_secs(3600), // 1 hour
        }
    }

    /// Generate and store a 6-digit OTP for the given email.
    /// In production, this would also send the email.
    pub async fn send_otp(&self, email: &str) -> Result<String> {
        let email = email.to_lowercase();

        // Rate limit check
        {
            let mut limits = self.rate_limits.write().await;
            let entry = limits.entry(email.clone()).or_insert((0, Instant::now()));
            if entry.1.elapsed() > self.rate_window {
                // Reset window
                *entry = (0, Instant::now());
            }
            if entry.0 >= self.max_sends_per_window {
                warn!(email = %email, "OTP rate limit exceeded");
                return Err(EreborError::RateLimited);
            }
            entry.0 += 1;
        }

        let code = format!("{:06}", rand::thread_rng().gen_range(0..1_000_000));

        {
            let mut otps = self.otps.write().await;
            otps.insert(
                email.clone(),
                OtpEntry {
                    code: code.clone(),
                    created_at: Instant::now(),
                    attempts: 0,
                },
            );
        }

        info!(email = %email, "OTP generated");
        // In production: send email via SMTP/SES/etc.
        Ok(code)
    }

    /// Verify an OTP code for the given email
    pub async fn verify_otp(&self, email: &str, code: &str) -> Result<ProviderUser> {
        let email = email.to_lowercase();
        let mut otps = self.otps.write().await;

        let entry = otps
            .get_mut(&email)
            .ok_or_else(|| EreborError::AuthError("No OTP found for this email".into()))?;

        // Check expiry
        if entry.created_at.elapsed() > self.ttl {
            otps.remove(&email);
            return Err(EreborError::AuthError("OTP expired".into()));
        }

        // Check attempts
        entry.attempts += 1;
        if entry.attempts > self.max_attempts {
            otps.remove(&email);
            return Err(EreborError::AuthError(
                "Too many attempts, OTP invalidated".into(),
            ));
        }

        // Constant-time comparison would be ideal, but for 6 digits it's fine
        if entry.code != code {
            return Err(EreborError::AuthError("Invalid OTP code".into()));
        }

        // Success - remove OTP
        otps.remove(&email);

        // Generate a deterministic provider_user_id from email
        let mut hasher = Sha256::new();
        hasher.update(b"email_otp:");
        hasher.update(email.as_bytes());
        let hash = hex::encode(hasher.finalize());

        Ok(ProviderUser {
            provider: AuthProvider::Email,
            provider_user_id: hash,
            email: Some(email),
            name: None,
            avatar_url: None,
        })
    }
}

impl Default for EmailOtpProvider {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// SIWE (Sign-In With Ethereum)
// ---------------------------------------------------------------------------

/// SIWE message fields (EIP-4361)
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SiweMessage {
    pub domain: String,
    pub address: String,
    pub statement: Option<String>,
    pub uri: String,
    pub version: String,
    pub chain_id: u64,
    pub nonce: String,
    pub issued_at: String,
    pub expiration_time: Option<String>,
}

pub struct SiweProvider {
    /// Valid nonces (in production, use Redis with TTL)
    nonces: Arc<RwLock<HashMap<String, Instant>>>,
    /// Expected domain
    expected_domain: String,
    nonce_ttl: Duration,
}

impl SiweProvider {
    pub fn new(expected_domain: String) -> Self {
        Self {
            nonces: Arc::new(RwLock::new(HashMap::new())),
            expected_domain,
            nonce_ttl: Duration::from_secs(600),
        }
    }

    /// Generate a nonce for SIWE
    pub async fn generate_nonce(&self) -> String {
        let nonce = hex::encode(rand::thread_rng().gen::<[u8; 16]>());
        self.nonces
            .write()
            .await
            .insert(nonce.clone(), Instant::now());
        nonce
    }

    /// Verify a SIWE message and signature
    /// `credential` is expected to be JSON: { "message": SiweMessage, "signature": "0x..." }
    pub async fn verify(&self, message: &SiweMessage, _signature: &str) -> Result<ProviderUser> {
        // Validate domain
        if message.domain != self.expected_domain {
            return Err(EreborError::AuthError(format!(
                "Domain mismatch: expected {}, got {}",
                self.expected_domain, message.domain
            )));
        }

        // Validate version
        if message.version != "1" {
            return Err(EreborError::AuthError("Unsupported SIWE version".into()));
        }

        // Validate nonce
        {
            let mut nonces = self.nonces.write().await;
            match nonces.remove(&message.nonce) {
                Some(created) if created.elapsed() <= self.nonce_ttl => {}
                Some(_) => return Err(EreborError::AuthError("Nonce expired".into())),
                None => return Err(EreborError::AuthError("Invalid nonce".into())),
            }
        }

        // Validate expiration
        if let Some(ref exp) = message.expiration_time {
            if let Ok(exp_time) = exp.parse::<chrono::DateTime<Utc>>() {
                if exp_time < Utc::now() {
                    return Err(EreborError::AuthError("SIWE message expired".into()));
                }
            }
        }

        // TODO: Actual EIP-191 signature verification with ecrecover
        // For now, trust the address from the message.
        // In production, use ethers/alloy to recover the signer address from signature.

        let address = message.address.to_lowercase();
        info!(address = %address, "SIWE authentication successful");

        Ok(ProviderUser {
            provider: AuthProvider::Siwe,
            provider_user_id: address.clone(),
            email: None,
            name: None,
            avatar_url: None,
        })
    }
}

// ---------------------------------------------------------------------------
// Passkey/WebAuthn (stub)
// ---------------------------------------------------------------------------

pub struct PasskeyProvider;

impl PasskeyProvider {
    pub fn new() -> Self {
        Self
    }
}

impl Default for PasskeyProvider {
    fn default() -> Self {
        Self::new()
    }
}

#[async_trait::async_trait]
impl AuthProviderHandler for PasskeyProvider {
    async fn authenticate(&self, _credential: &str) -> Result<ProviderUser> {
        // TODO: Implement WebAuthn/FIDO2 passkey verification
        Err(EreborError::AuthError(
            "Passkey authentication not yet implemented".into(),
        ))
    }

    fn provider(&self) -> AuthProvider {
        AuthProvider::Passkey
    }
}

// ---------------------------------------------------------------------------
// Provider Registry
// ---------------------------------------------------------------------------

/// Registry of all available auth providers
pub struct ProviderRegistry {
    pub email_otp: Arc<EmailOtpProvider>,
    pub siwe: Arc<SiweProvider>,
    pub google: Option<Arc<GoogleOAuthProvider>>,
    pub passkey: Arc<PasskeyProvider>,
}

impl ProviderRegistry {
    pub fn new(
        email_otp: EmailOtpProvider,
        siwe: SiweProvider,
        google: Option<GoogleOAuthProvider>,
    ) -> Self {
        Self {
            email_otp: Arc::new(email_otp),
            siwe: Arc::new(siwe),
            google: google.map(Arc::new),
            passkey: Arc::new(PasskeyProvider::new()),
        }
    }
}

// ---------------------------------------------------------------------------
// Tests
// ---------------------------------------------------------------------------

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn test_email_otp_send_and_verify() {
        let provider = EmailOtpProvider::new();
        let email = "test@example.com";

        let code = provider.send_otp(email).await.unwrap();
        assert_eq!(code.len(), 6);

        let user = provider.verify_otp(email, &code).await.unwrap();
        assert_eq!(user.provider, AuthProvider::Email);
        assert_eq!(user.email, Some("test@example.com".to_string()));
    }

    #[tokio::test]
    async fn test_email_otp_case_insensitive() {
        let provider = EmailOtpProvider::new();
        let code = provider.send_otp("Test@Example.COM").await.unwrap();
        let user = provider.verify_otp("test@example.com", &code).await.unwrap();
        assert_eq!(user.email, Some("test@example.com".to_string()));
    }

    #[tokio::test]
    async fn test_email_otp_wrong_code() {
        let provider = EmailOtpProvider::new();
        provider.send_otp("test@example.com").await.unwrap();
        let result = provider.verify_otp("test@example.com", "000000").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_email_otp_max_attempts() {
        let provider = EmailOtpProvider::new();
        provider.send_otp("test@example.com").await.unwrap();

        for _ in 0..3 {
            let _ = provider.verify_otp("test@example.com", "wrong!").await;
        }

        // 4th attempt should fail with "Too many attempts" or "No OTP found"
        let result = provider.verify_otp("test@example.com", "wrong!").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_email_otp_rate_limiting() {
        let mut provider = EmailOtpProvider::new();
        provider.max_sends_per_window = 2;

        provider.send_otp("test@example.com").await.unwrap();
        provider.send_otp("test@example.com").await.unwrap();
        let result = provider.send_otp("test@example.com").await;
        assert!(matches!(result, Err(EreborError::RateLimited)));
    }

    #[tokio::test]
    async fn test_email_otp_no_otp_found() {
        let provider = EmailOtpProvider::new();
        let result = provider.verify_otp("nobody@example.com", "123456").await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_email_otp_single_use() {
        let provider = EmailOtpProvider::new();
        let code = provider.send_otp("test@example.com").await.unwrap();
        provider.verify_otp("test@example.com", &code).await.unwrap();
        // Second use should fail
        let result = provider.verify_otp("test@example.com", &code).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_siwe_generate_nonce() {
        let provider = SiweProvider::new("example.com".into());
        let nonce = provider.generate_nonce().await;
        assert_eq!(nonce.len(), 32); // 16 bytes hex encoded
    }

    #[tokio::test]
    async fn test_siwe_verify_success() {
        let provider = SiweProvider::new("example.com".into());
        let nonce = provider.generate_nonce().await;

        let message = SiweMessage {
            domain: "example.com".into(),
            address: "0x1234567890abcdef1234567890abcdef12345678".into(),
            statement: Some("Sign in".into()),
            uri: "https://example.com".into(),
            version: "1".into(),
            chain_id: 1,
            nonce,
            issued_at: Utc::now().to_rfc3339(),
            expiration_time: None,
        };

        let user = provider.verify(&message, "0xfakesig").await.unwrap();
        assert_eq!(user.provider, AuthProvider::Siwe);
        assert_eq!(
            user.provider_user_id,
            "0x1234567890abcdef1234567890abcdef12345678"
        );
    }

    #[tokio::test]
    async fn test_siwe_wrong_domain() {
        let provider = SiweProvider::new("example.com".into());
        let nonce = provider.generate_nonce().await;

        let message = SiweMessage {
            domain: "evil.com".into(),
            address: "0x1234".into(),
            statement: None,
            uri: "https://evil.com".into(),
            version: "1".into(),
            chain_id: 1,
            nonce,
            issued_at: Utc::now().to_rfc3339(),
            expiration_time: None,
        };

        assert!(provider.verify(&message, "0xsig").await.is_err());
    }

    #[tokio::test]
    async fn test_siwe_invalid_nonce() {
        let provider = SiweProvider::new("example.com".into());

        let message = SiweMessage {
            domain: "example.com".into(),
            address: "0x1234".into(),
            statement: None,
            uri: "https://example.com".into(),
            version: "1".into(),
            chain_id: 1,
            nonce: "invalid_nonce".into(),
            issued_at: Utc::now().to_rfc3339(),
            expiration_time: None,
        };

        assert!(provider.verify(&message, "0xsig").await.is_err());
    }

    #[tokio::test]
    async fn test_siwe_nonce_single_use() {
        let provider = SiweProvider::new("example.com".into());
        let nonce = provider.generate_nonce().await;

        let message = SiweMessage {
            domain: "example.com".into(),
            address: "0x1234".into(),
            statement: None,
            uri: "https://example.com".into(),
            version: "1".into(),
            chain_id: 1,
            nonce,
            issued_at: Utc::now().to_rfc3339(),
            expiration_time: None,
        };

        provider.verify(&message, "0xsig").await.unwrap();
        // Nonce consumed, second use should fail
        assert!(provider.verify(&message, "0xsig").await.is_err());
    }

    #[tokio::test]
    async fn test_passkey_not_implemented() {
        let provider = PasskeyProvider::new();
        assert!(provider.authenticate("credential").await.is_err());
    }

    #[test]
    fn test_provider_user_serialization() {
        let user = ProviderUser {
            provider: AuthProvider::Google,
            provider_user_id: "12345".into(),
            email: Some("test@example.com".into()),
            name: Some("Test User".into()),
            avatar_url: None,
        };
        let json = serde_json::to_string(&user).unwrap();
        let deserialized: ProviderUser = serde_json::from_str(&json).unwrap();
        assert_eq!(deserialized.provider_user_id, "12345");
    }
}
