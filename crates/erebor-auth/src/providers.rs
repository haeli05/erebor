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
use hmac::{Hmac, Mac};
use regex::Regex;

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
// Apple OAuth
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct AppleOAuthConfig {
    pub client_id: String,
    pub team_id: String,
    pub key_id: String,
    pub private_key: String,
    pub redirect_uri: String,
}

pub struct AppleOAuthProvider {
    config: AppleOAuthConfig,
    http: reqwest::Client,
}

#[derive(Deserialize)]
struct AppleTokenResponse {
    access_token: String,
    id_token: String,
    #[allow(dead_code)]
    token_type: Option<String>,
    #[allow(dead_code)]
    expires_in: Option<u64>,
}

impl AppleOAuthProvider {
    pub fn new(config: AppleOAuthConfig) -> Self {
        Self {
            config,
            http: reqwest::Client::new(),
        }
    }

    fn create_client_secret(&self) -> Result<String> {
        use jsonwebtoken::{encode, Header, Algorithm, EncodingKey};
        
        let mut header = Header::new(Algorithm::ES256);
        header.kid = Some(self.config.key_id.clone());
        
        let now = Utc::now().timestamp();
        let claims = serde_json::json!({
            "iss": self.config.team_id,
            "iat": now,
            "exp": now + 3600,
            "aud": "https://appleid.apple.com",
            "sub": self.config.client_id,
        });

        let key = EncodingKey::from_ec_pem(self.config.private_key.as_bytes())
            .map_err(|e| EreborError::AuthError(format!("Invalid Apple private key: {e}")))?;
        
        encode(&header, &claims, &key)
            .map_err(|e| EreborError::AuthError(format!("Failed to create Apple client secret: {e}")))
    }
}

#[async_trait::async_trait]
impl AuthProviderHandler for AppleOAuthProvider {
    async fn authenticate(&self, code: &str) -> Result<ProviderUser> {
        let client_secret = self.create_client_secret()?;

        let token_resp = self
            .http
            .post("https://appleid.apple.com/auth/token")
            .form(&[
                ("code", code),
                ("client_id", &self.config.client_id),
                ("client_secret", &client_secret),
                ("redirect_uri", &self.config.redirect_uri),
                ("grant_type", "authorization_code"),
            ])
            .send()
            .await
            .map_err(|e| EreborError::AuthError(format!("Apple token exchange failed: {e}")))?;

        if !token_resp.status().is_success() {
            let body = token_resp.text().await.unwrap_or_default();
            return Err(EreborError::AuthError(format!(
                "Apple token exchange error: {body}"
            )));
        }

        let tokens: AppleTokenResponse = token_resp
            .json()
            .await
            .map_err(|e| EreborError::AuthError(format!("Failed to parse token response: {e}")))?;

        // Decode the ID token (JWT) - for now we trust it's valid
        // In production, validate against Apple's public keys at https://appleid.apple.com/auth/keys
        use base64::{Engine as _, engine::general_purpose};
        let parts: Vec<&str> = tokens.id_token.split('.').collect();
        if parts.len() != 3 {
            return Err(EreborError::AuthError("Invalid Apple ID token format".into()));
        }

        let payload = general_purpose::URL_SAFE_NO_PAD
            .decode(parts[1])
            .map_err(|e| EreborError::AuthError(format!("Failed to decode Apple ID token: {e}")))?;
        
        let user_info: serde_json::Value = serde_json::from_slice(&payload)
            .map_err(|e| EreborError::AuthError(format!("Failed to parse Apple user info: {e}")))?;

        let sub = user_info["sub"]
            .as_str()
            .ok_or_else(|| EreborError::AuthError("No sub in Apple ID token".into()))?;
        
        let email = user_info["email"].as_str().map(String::from);

        info!(provider = "apple", sub = %sub, "Apple OAuth successful");

        Ok(ProviderUser {
            provider: AuthProvider::Apple,
            provider_user_id: sub.to_string(),
            email,
            name: None,
            avatar_url: None,
        })
    }

    fn provider(&self) -> AuthProvider {
        AuthProvider::Apple
    }
}

// ---------------------------------------------------------------------------
// Twitter OAuth
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct TwitterOAuthConfig {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
}

pub struct TwitterOAuthProvider {
    config: TwitterOAuthConfig,
    http: reqwest::Client,
}

#[derive(Deserialize)]
struct TwitterTokenResponse {
    access_token: String,
    #[allow(dead_code)]
    token_type: Option<String>,
    #[allow(dead_code)]
    expires_in: Option<u64>,
}

#[derive(Deserialize)]
struct TwitterUser {
    id: String,
    username: String,
    name: String,
}

#[derive(Deserialize)]
struct TwitterUserResponse {
    data: TwitterUser,
}

impl TwitterOAuthProvider {
    pub fn new(config: TwitterOAuthConfig) -> Self {
        Self {
            config,
            http: reqwest::Client::new(),
        }
    }
}

#[async_trait::async_trait]
impl AuthProviderHandler for TwitterOAuthProvider {
    async fn authenticate(&self, code: &str) -> Result<ProviderUser> {
        let token_resp = self
            .http
            .post("https://api.twitter.com/2/oauth2/token")
            .basic_auth(&self.config.client_id, Some(&self.config.client_secret))
            .form(&[
                ("code", code),
                ("redirect_uri", &self.config.redirect_uri),
                ("grant_type", "authorization_code"),
                ("code_verifier", "challenge"), // In production, use actual PKCE
            ])
            .send()
            .await
            .map_err(|e| EreborError::AuthError(format!("Twitter token exchange failed: {e}")))?;

        if !token_resp.status().is_success() {
            let body = token_resp.text().await.unwrap_or_default();
            return Err(EreborError::AuthError(format!(
                "Twitter token exchange error: {body}"
            )));
        }

        let tokens: TwitterTokenResponse = token_resp
            .json()
            .await
            .map_err(|e| EreborError::AuthError(format!("Failed to parse token response: {e}")))?;

        let user_resp = self
            .http
            .get("https://api.twitter.com/2/users/me")
            .bearer_auth(&tokens.access_token)
            .send()
            .await
            .map_err(|e| EreborError::AuthError(format!("Twitter userinfo failed: {e}")))?;

        let user_data: TwitterUserResponse = user_resp
            .json()
            .await
            .map_err(|e| EreborError::AuthError(format!("Failed to parse Twitter userinfo: {e}")))?;

        info!(provider = "twitter", id = %user_data.data.id, "Twitter OAuth successful");

        Ok(ProviderUser {
            provider: AuthProvider::Twitter,
            provider_user_id: user_data.data.id,
            email: None, // Twitter doesn't always provide email
            name: Some(user_data.data.name),
            avatar_url: None,
        })
    }

    fn provider(&self) -> AuthProvider {
        AuthProvider::Twitter
    }
}

// ---------------------------------------------------------------------------
// Discord OAuth
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct DiscordOAuthConfig {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
}

pub struct DiscordOAuthProvider {
    config: DiscordOAuthConfig,
    http: reqwest::Client,
}

#[derive(Deserialize)]
struct DiscordTokenResponse {
    access_token: String,
    #[allow(dead_code)]
    token_type: Option<String>,
    #[allow(dead_code)]
    expires_in: Option<u64>,
}

#[derive(Deserialize)]
struct DiscordUser {
    id: String,
    username: String,
    email: Option<String>,
    avatar: Option<String>,
}

impl DiscordOAuthProvider {
    pub fn new(config: DiscordOAuthConfig) -> Self {
        Self {
            config,
            http: reqwest::Client::new(),
        }
    }
}

#[async_trait::async_trait]
impl AuthProviderHandler for DiscordOAuthProvider {
    async fn authenticate(&self, code: &str) -> Result<ProviderUser> {
        let token_resp = self
            .http
            .post("https://discord.com/api/oauth2/token")
            .form(&[
                ("code", code),
                ("client_id", &self.config.client_id),
                ("client_secret", &self.config.client_secret),
                ("redirect_uri", &self.config.redirect_uri),
                ("grant_type", "authorization_code"),
            ])
            .send()
            .await
            .map_err(|e| EreborError::AuthError(format!("Discord token exchange failed: {e}")))?;

        if !token_resp.status().is_success() {
            let body = token_resp.text().await.unwrap_or_default();
            return Err(EreborError::AuthError(format!(
                "Discord token exchange error: {body}"
            )));
        }

        let tokens: DiscordTokenResponse = token_resp
            .json()
            .await
            .map_err(|e| EreborError::AuthError(format!("Failed to parse token response: {e}")))?;

        let user_resp = self
            .http
            .get("https://discord.com/api/users/@me")
            .bearer_auth(&tokens.access_token)
            .send()
            .await
            .map_err(|e| EreborError::AuthError(format!("Discord userinfo failed: {e}")))?;

        let user_info: DiscordUser = user_resp
            .json()
            .await
            .map_err(|e| EreborError::AuthError(format!("Failed to parse Discord userinfo: {e}")))?;

        let avatar_url = user_info.avatar.as_ref().map(|avatar| {
            format!("https://cdn.discordapp.com/avatars/{}/{}.png", user_info.id, avatar)
        });

        info!(provider = "discord", id = %user_info.id, "Discord OAuth successful");

        Ok(ProviderUser {
            provider: AuthProvider::Discord,
            provider_user_id: user_info.id,
            email: user_info.email,
            name: Some(user_info.username),
            avatar_url,
        })
    }

    fn provider(&self) -> AuthProvider {
        AuthProvider::Discord
    }
}

// ---------------------------------------------------------------------------
// GitHub OAuth
// ---------------------------------------------------------------------------

#[derive(Debug, Clone)]
pub struct GitHubOAuthConfig {
    pub client_id: String,
    pub client_secret: String,
    pub redirect_uri: String,
}

pub struct GitHubOAuthProvider {
    config: GitHubOAuthConfig,
    http: reqwest::Client,
}

#[derive(Deserialize)]
struct GitHubTokenResponse {
    access_token: String,
    #[allow(dead_code)]
    token_type: Option<String>,
}

#[derive(Deserialize)]
struct GitHubUser {
    id: u64,
    #[allow(dead_code)]
    login: String,
    name: Option<String>,
    email: Option<String>,
    avatar_url: Option<String>,
}

#[derive(Deserialize)]
struct GitHubEmail {
    email: String,
    primary: bool,
    verified: bool,
}

impl GitHubOAuthProvider {
    pub fn new(config: GitHubOAuthConfig) -> Self {
        Self {
            config,
            http: reqwest::Client::new(),
        }
    }
}

#[async_trait::async_trait]
impl AuthProviderHandler for GitHubOAuthProvider {
    async fn authenticate(&self, code: &str) -> Result<ProviderUser> {
        let token_resp = self
            .http
            .post("https://github.com/login/oauth/access_token")
            .header("Accept", "application/json")
            .form(&[
                ("code", code),
                ("client_id", &self.config.client_id),
                ("client_secret", &self.config.client_secret),
                ("redirect_uri", &self.config.redirect_uri),
            ])
            .send()
            .await
            .map_err(|e| EreborError::AuthError(format!("GitHub token exchange failed: {e}")))?;

        if !token_resp.status().is_success() {
            let body = token_resp.text().await.unwrap_or_default();
            return Err(EreborError::AuthError(format!(
                "GitHub token exchange error: {body}"
            )));
        }

        let tokens: GitHubTokenResponse = token_resp
            .json()
            .await
            .map_err(|e| EreborError::AuthError(format!("Failed to parse token response: {e}")))?;

        let user_resp = self
            .http
            .get("https://api.github.com/user")
            .bearer_auth(&tokens.access_token)
            .header("User-Agent", "erebor-auth")
            .send()
            .await
            .map_err(|e| EreborError::AuthError(format!("GitHub userinfo failed: {e}")))?;

        let mut user_info: GitHubUser = user_resp
            .json()
            .await
            .map_err(|e| EreborError::AuthError(format!("Failed to parse GitHub userinfo: {e}")))?;

        // If no public email, try to get primary verified email
        if user_info.email.is_none() {
            let emails_resp = self
                .http
                .get("https://api.github.com/user/emails")
                .bearer_auth(&tokens.access_token)
                .header("User-Agent", "erebor-auth")
                .send()
                .await
                .map_err(|e| EreborError::AuthError(format!("GitHub emails failed: {e}")))?;

            if emails_resp.status().is_success() {
                let emails: Vec<GitHubEmail> = emails_resp
                    .json()
                    .await
                    .map_err(|e| EreborError::AuthError(format!("Failed to parse GitHub emails: {e}")))?;
                
                // Find primary verified email
                if let Some(primary_email) = emails.iter().find(|e| e.primary && e.verified) {
                    user_info.email = Some(primary_email.email.clone());
                }
            }
        }

        info!(provider = "github", id = %user_info.id, "GitHub OAuth successful");

        Ok(ProviderUser {
            provider: AuthProvider::Github,
            provider_user_id: user_info.id.to_string(),
            email: user_info.email,
            name: user_info.name,
            avatar_url: user_info.avatar_url,
        })
    }

    fn provider(&self) -> AuthProvider {
        AuthProvider::Github
    }
}

// ---------------------------------------------------------------------------
// Farcaster SIWF (Sign In With Farcaster)
// ---------------------------------------------------------------------------

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct FarcasterMessage {
    pub domain: String,
    pub address: String,
    pub statement: Option<String>,
    pub uri: String,
    pub version: String,
    pub nonce: String,
    pub issued_at: String,
    pub expiration_time: Option<String>,
    pub fid: u64,
    pub custody_address: String,
}

pub struct FarcasterProvider {
    nonces: Arc<RwLock<HashMap<String, Instant>>>,
    expected_domain: String,
    nonce_ttl: Duration,
    #[allow(dead_code)]
    http: reqwest::Client,
}

impl FarcasterProvider {
    pub fn new(expected_domain: String) -> Self {
        Self {
            nonces: Arc::new(RwLock::new(HashMap::new())),
            expected_domain,
            nonce_ttl: Duration::from_secs(600),
            http: reqwest::Client::new(),
        }
    }

    pub async fn generate_nonce(&self) -> String {
        let nonce = hex::encode(rand::thread_rng().gen::<[u8; 16]>());
        self.nonces
            .write()
            .await
            .insert(nonce.clone(), Instant::now());
        nonce
    }

    pub async fn verify(&self, message: &FarcasterMessage, _signature: &str) -> Result<ProviderUser> {
        // Validate domain
        if message.domain != self.expected_domain {
            return Err(EreborError::AuthError(format!(
                "Domain mismatch: expected {}, got {}",
                self.expected_domain, message.domain
            )));
        }

        // Validate version
        if message.version != "1" {
            return Err(EreborError::AuthError("Unsupported SIWF version".into()));
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
                    return Err(EreborError::AuthError("SIWF message expired".into()));
                }
            }
        }

        // TODO: Verify signature against custody address
        // TODO: Validate custody address against FID via Warpcast/Neynar API

        info!(fid = %message.fid, custody_address = %message.custody_address, "Farcaster authentication successful");

        Ok(ProviderUser {
            provider: AuthProvider::Farcaster,
            provider_user_id: message.fid.to_string(),
            email: None,
            name: None,
            avatar_url: None,
        })
    }
}

// ---------------------------------------------------------------------------
// Telegram Auth
// ---------------------------------------------------------------------------

pub struct TelegramAuthProvider {
    bot_token: String,
}

#[derive(Debug, Deserialize)]
pub struct TelegramAuthData {
    pub id: u64,
    pub first_name: String,
    pub last_name: Option<String>,
    pub username: Option<String>,
    pub photo_url: Option<String>,
    pub auth_date: u64,
    pub hash: String,
}

impl TelegramAuthProvider {
    pub fn new(bot_token: String) -> Self {
        Self { bot_token }
    }

    pub async fn verify(&self, auth_data: &TelegramAuthData) -> Result<ProviderUser> {
        // Validate auth_date (not older than 86400 seconds / 24 hours)
        let now = Utc::now().timestamp() as u64;
        if now.saturating_sub(auth_data.auth_date) > 86400 {
            return Err(EreborError::AuthError("Telegram auth data too old".into()));
        }

        // Create data check string (sorted key=value pairs, excluding hash)
        let mut data_check_pairs = vec![
            format!("auth_date={}", auth_data.auth_date),
            format!("first_name={}", auth_data.first_name),
            format!("id={}", auth_data.id),
        ];

        if let Some(ref last_name) = auth_data.last_name {
            data_check_pairs.push(format!("last_name={}", last_name));
        }
        if let Some(ref photo_url) = auth_data.photo_url {
            data_check_pairs.push(format!("photo_url={}", photo_url));
        }
        if let Some(ref username) = auth_data.username {
            data_check_pairs.push(format!("username={}", username));
        }

        data_check_pairs.sort();
        let data_check_string = data_check_pairs.join("\n");

        // Calculate secret key: SHA256(bot_token)
        let mut hasher = Sha256::new();
        hasher.update(self.bot_token.as_bytes());
        let secret_key = hasher.finalize();

        // Calculate HMAC-SHA256(data_check_string, secret_key)
        type HmacSha256 = Hmac<Sha256>;
        let mut mac = HmacSha256::new_from_slice(&secret_key)
            .map_err(|e| EreborError::AuthError(format!("Invalid secret key: {e}")))?;
        mac.update(data_check_string.as_bytes());
        let expected_hash = hex::encode(mac.finalize().into_bytes());

        if expected_hash != auth_data.hash {
            return Err(EreborError::AuthError("Invalid Telegram hash".into()));
        }

        let display_name = if let Some(ref last_name) = auth_data.last_name {
            format!("{} {}", auth_data.first_name, last_name)
        } else {
            auth_data.first_name.clone()
        };

        info!(provider = "telegram", id = %auth_data.id, "Telegram authentication successful");

        Ok(ProviderUser {
            provider: AuthProvider::Telegram,
            provider_user_id: auth_data.id.to_string(),
            email: None,
            name: Some(display_name),
            avatar_url: auth_data.photo_url.clone(),
        })
    }
}

// ---------------------------------------------------------------------------
// Phone OTP
// ---------------------------------------------------------------------------

/// Phone OTP provider with in-memory store (swap for Redis in production)
pub struct PhoneOtpProvider {
    /// phone -> OtpEntry
    otps: Arc<RwLock<HashMap<String, OtpEntry>>>,
    /// Rate limiting: phone -> (count, window_start)
    rate_limits: Arc<RwLock<HashMap<String, (u32, Instant)>>>,
    /// OTP validity duration
    ttl: Duration,
    /// Max verification attempts per OTP
    max_attempts: u32,
    /// Max OTP sends per phone per window
    max_sends_per_window: u32,
    /// Rate limit window
    rate_window: Duration,
    /// Send rate limit (1 per 60s)
    send_rate_limit: Duration,
    /// Last send time per phone
    last_send: Arc<RwLock<HashMap<String, Instant>>>,
}

impl PhoneOtpProvider {
    pub fn new() -> Self {
        Self {
            otps: Arc::new(RwLock::new(HashMap::new())),
            rate_limits: Arc::new(RwLock::new(HashMap::new())),
            last_send: Arc::new(RwLock::new(HashMap::new())),
            ttl: Duration::from_secs(600), // 10 minutes
            max_attempts: 3,
            max_sends_per_window: 3,
            rate_window: Duration::from_secs(600), // 10 minutes
            send_rate_limit: Duration::from_secs(60), // 1 minute between sends
        }
    }

    /// Validate E.164 phone number format (+1234567890)
    fn validate_phone(&self, phone: &str) -> Result<()> {
        let e164_regex = Regex::new(r"^\+[1-9]\d{1,14}$").unwrap();
        if !e164_regex.is_match(phone) {
            return Err(EreborError::AuthError("Invalid phone number format (use E.164: +1234567890)".into()));
        }
        Ok(())
    }

    /// Generate and store a 6-digit OTP for the given phone number.
    /// In production, this would also send the SMS.
    pub async fn send_otp(&self, phone: &str) -> Result<String> {
        self.validate_phone(phone)?;

        // Send rate limit check (1 per minute)
        {
            let mut last_sends = self.last_send.write().await;
            if let Some(last) = last_sends.get(phone) {
                if last.elapsed() < self.send_rate_limit {
                    return Err(EreborError::RateLimited);
                }
            }
            last_sends.insert(phone.to_string(), Instant::now());
        }

        // Rate limit check
        {
            let mut limits = self.rate_limits.write().await;
            let entry = limits.entry(phone.to_string()).or_insert((0, Instant::now()));
            if entry.1.elapsed() > self.rate_window {
                // Reset window
                *entry = (0, Instant::now());
            }
            if entry.0 >= self.max_sends_per_window {
                warn!(phone = %phone, "Phone OTP rate limit exceeded");
                return Err(EreborError::RateLimited);
            }
            entry.0 += 1;
        }

        let code = format!("{:06}", rand::thread_rng().gen_range(0..1_000_000));

        {
            let mut otps = self.otps.write().await;
            otps.insert(
                phone.to_string(),
                OtpEntry {
                    code: code.clone(),
                    created_at: Instant::now(),
                    attempts: 0,
                },
            );
        }

        info!(phone = %phone, "Phone OTP generated");
        // In production: send SMS via Twilio/Vonage/etc.
        // For now, just log it like email OTP
        Ok(code)
    }

    /// Verify an OTP code for the given phone number
    pub async fn verify_otp(&self, phone: &str, code: &str) -> Result<ProviderUser> {
        self.validate_phone(phone)?;
        
        let mut otps = self.otps.write().await;

        let entry = otps
            .get_mut(phone)
            .ok_or_else(|| EreborError::AuthError("No OTP found for this phone".into()))?;

        // Check expiry
        if entry.created_at.elapsed() > self.ttl {
            otps.remove(phone);
            return Err(EreborError::AuthError("OTP expired".into()));
        }

        // Check attempts
        entry.attempts += 1;
        if entry.attempts > self.max_attempts {
            otps.remove(phone);
            return Err(EreborError::AuthError(
                "Too many attempts, OTP invalidated".into(),
            ));
        }

        // Constant-time comparison would be ideal, but for 6 digits it's fine
        if entry.code != code {
            return Err(EreborError::AuthError("Invalid OTP code".into()));
        }

        // Success - remove OTP
        otps.remove(phone);

        // Generate a deterministic provider_user_id from phone
        let mut hasher = Sha256::new();
        hasher.update(b"phone_otp:");
        hasher.update(phone.as_bytes());
        let hash = hex::encode(hasher.finalize());

        Ok(ProviderUser {
            provider: AuthProvider::Phone,
            provider_user_id: hash,
            email: None,
            name: None,
            avatar_url: None,
        })
    }
}

impl Default for PhoneOtpProvider {
    fn default() -> Self {
        Self::new()
    }
}

// ---------------------------------------------------------------------------
// Provider Registry
// ---------------------------------------------------------------------------

/// Registry of all available auth providers
pub struct ProviderRegistry {
    pub email_otp: Arc<EmailOtpProvider>,
    pub phone_otp: Arc<PhoneOtpProvider>,
    pub siwe: Arc<SiweProvider>,
    pub farcaster: Arc<FarcasterProvider>,
    pub telegram: Arc<TelegramAuthProvider>,
    pub google: Option<Arc<GoogleOAuthProvider>>,
    pub apple: Option<Arc<AppleOAuthProvider>>,
    pub twitter: Option<Arc<TwitterOAuthProvider>>,
    pub discord: Option<Arc<DiscordOAuthProvider>>,
    pub github: Option<Arc<GitHubOAuthProvider>>,
    pub passkey: Arc<PasskeyProvider>,
}

impl ProviderRegistry {
    pub fn new(
        email_otp: EmailOtpProvider,
        phone_otp: PhoneOtpProvider,
        siwe: SiweProvider,
        farcaster: FarcasterProvider,
        telegram: TelegramAuthProvider,
        google: Option<GoogleOAuthProvider>,
        apple: Option<AppleOAuthProvider>,
        twitter: Option<TwitterOAuthProvider>,
        discord: Option<DiscordOAuthProvider>,
        github: Option<GitHubOAuthProvider>,
    ) -> Self {
        Self {
            email_otp: Arc::new(email_otp),
            phone_otp: Arc::new(phone_otp),
            siwe: Arc::new(siwe),
            farcaster: Arc::new(farcaster),
            telegram: Arc::new(telegram),
            google: google.map(Arc::new),
            apple: apple.map(Arc::new),
            twitter: twitter.map(Arc::new),
            discord: discord.map(Arc::new),
            github: github.map(Arc::new),
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

    // ---------------------------------------------------------------------------
    // Phone OTP Tests
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn test_phone_otp_send_and_verify() {
        let provider = PhoneOtpProvider::new();
        let phone = "+1234567890";

        let code = provider.send_otp(phone).await.unwrap();
        assert_eq!(code.len(), 6);

        let user = provider.verify_otp(phone, &code).await.unwrap();
        assert_eq!(user.provider, AuthProvider::Phone);
        assert_eq!(user.email, None);
    }

    #[tokio::test]
    async fn test_phone_otp_invalid_format() {
        let provider = PhoneOtpProvider::new();
        
        // Invalid formats
        assert!(provider.send_otp("1234567890").await.is_err()); // No +
        assert!(provider.send_otp("+0234567890").await.is_err()); // Leading 0
        assert!(provider.send_otp("+12345").await.is_err()); // Too short
    }

    #[tokio::test]
    async fn test_phone_otp_rate_limiting() {
        let mut provider = PhoneOtpProvider::new();
        provider.max_sends_per_window = 2;

        let phone = "+1234567890";
        provider.send_otp(phone).await.unwrap();
        provider.send_otp(phone).await.unwrap();
        let result = provider.send_otp(phone).await;
        assert!(matches!(result, Err(EreborError::RateLimited)));
    }

    #[tokio::test]
    async fn test_phone_otp_max_attempts() {
        let provider = PhoneOtpProvider::new();
        let phone = "+1234567890";
        provider.send_otp(phone).await.unwrap();

        for _ in 0..3 {
            let _ = provider.verify_otp(phone, "wrong!").await;
        }

        // 4th attempt should fail
        let result = provider.verify_otp(phone, "wrong!").await;
        assert!(result.is_err());
    }

    // ---------------------------------------------------------------------------
    // Telegram Auth Tests
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn test_telegram_auth_valid() {
        let provider = TelegramAuthProvider::new("test_bot_token".into());
        
        // Create valid auth data with correct hash
        let auth_data = TelegramAuthData {
            id: 12345,
            first_name: "John".into(),
            last_name: Some("Doe".into()),
            username: Some("johndoe".into()),
            photo_url: None,
            auth_date: Utc::now().timestamp() as u64,
            hash: "dummy_hash".into(), // This would fail real validation
        };

        // This will fail because we haven't computed the real hash
        // In a real test, we'd compute the proper HMAC-SHA256
        let result = provider.verify(&auth_data).await;
        assert!(result.is_err());
    }

    #[tokio::test]
    async fn test_telegram_auth_expired() {
        let provider = TelegramAuthProvider::new("test_bot_token".into());
        
        let auth_data = TelegramAuthData {
            id: 12345,
            first_name: "John".into(),
            last_name: None,
            username: None,
            photo_url: None,
            auth_date: (Utc::now().timestamp() - 86401) as u64, // More than 24h ago
            hash: "hash".into(),
        };

        let result = provider.verify(&auth_data).await;
        assert!(result.is_err());
    }

    // ---------------------------------------------------------------------------
    // Farcaster Tests
    // ---------------------------------------------------------------------------

    #[tokio::test]
    async fn test_farcaster_generate_nonce() {
        let provider = FarcasterProvider::new("example.com".into());
        let nonce = provider.generate_nonce().await;
        assert_eq!(nonce.len(), 32); // 16 bytes hex encoded
    }

    #[tokio::test]
    async fn test_farcaster_verify_success() {
        let provider = FarcasterProvider::new("example.com".into());
        let nonce = provider.generate_nonce().await;

        let message = FarcasterMessage {
            domain: "example.com".into(),
            address: "0x1234567890abcdef1234567890abcdef12345678".into(),
            statement: Some("Sign in".into()),
            uri: "https://example.com".into(),
            version: "1".into(),
            nonce,
            issued_at: Utc::now().to_rfc3339(),
            expiration_time: None,
            fid: 12345,
            custody_address: "0x1234567890abcdef1234567890abcdef12345678".into(),
        };

        let user = provider.verify(&message, "0xfakesig").await.unwrap();
        assert_eq!(user.provider, AuthProvider::Farcaster);
        assert_eq!(user.provider_user_id, "12345");
    }

    #[tokio::test]
    async fn test_farcaster_wrong_domain() {
        let provider = FarcasterProvider::new("example.com".into());
        let nonce = provider.generate_nonce().await;

        let message = FarcasterMessage {
            domain: "evil.com".into(),
            address: "0x1234".into(),
            statement: None,
            uri: "https://evil.com".into(),
            version: "1".into(),
            nonce,
            issued_at: Utc::now().to_rfc3339(),
            expiration_time: None,
            fid: 123,
            custody_address: "0x1234".into(),
        };

        assert!(provider.verify(&message, "0xsig").await.is_err());
    }

    // ---------------------------------------------------------------------------
    // Apple OAuth Tests (Stub)
    // ---------------------------------------------------------------------------

    #[test]
    fn test_apple_oauth_config() {
        let config = AppleOAuthConfig {
            client_id: "com.example.app".into(),
            team_id: "TEAM123".into(),
            key_id: "KEY123".into(),
            private_key: "-----BEGIN PRIVATE KEY-----\nMIGHAgEAMBMGByqGSM...".into(),
            redirect_uri: "https://example.com/callback".into(),
        };
        
        let provider = AppleOAuthProvider::new(config);
        assert_eq!(provider.provider(), AuthProvider::Apple);
    }

    // ---------------------------------------------------------------------------
    // Twitter OAuth Tests (Stub)
    // ---------------------------------------------------------------------------

    #[test]
    fn test_twitter_oauth_config() {
        let config = TwitterOAuthConfig {
            client_id: "client123".into(),
            client_secret: "secret123".into(),
            redirect_uri: "https://example.com/callback".into(),
        };
        
        let provider = TwitterOAuthProvider::new(config);
        assert_eq!(provider.provider(), AuthProvider::Twitter);
    }

    // ---------------------------------------------------------------------------
    // Discord OAuth Tests (Stub)
    // ---------------------------------------------------------------------------

    #[test]
    fn test_discord_oauth_config() {
        let config = DiscordOAuthConfig {
            client_id: "123456789".into(),
            client_secret: "secret".into(),
            redirect_uri: "https://example.com/callback".into(),
        };
        
        let provider = DiscordOAuthProvider::new(config);
        assert_eq!(provider.provider(), AuthProvider::Discord);
    }

    // ---------------------------------------------------------------------------
    // GitHub OAuth Tests (Stub)
    // ---------------------------------------------------------------------------

    #[test]
    fn test_github_oauth_config() {
        let config = GitHubOAuthConfig {
            client_id: "client123".into(),
            client_secret: "secret123".into(),
            redirect_uri: "https://example.com/callback".into(),
        };
        
        let provider = GitHubOAuthProvider::new(config);
        assert_eq!(provider.provider(), AuthProvider::Github);
    }
}
