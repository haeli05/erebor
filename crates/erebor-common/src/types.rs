use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;
use zeroize::Zeroize;

/// Unique user identifier
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq, Hash)]
pub struct UserId(pub Uuid);

impl UserId {
    pub fn new() -> Self {
        Self(Uuid::new_v4())
    }
}

impl Default for UserId {
    fn default() -> Self {
        Self::new()
    }
}

/// Authentication provider types
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum AuthProvider {
    Google,
    Apple,
    Twitter,
    Discord,
    Github,
    Email,
    Phone,
    Siwe,
    Passkey,
    Farcaster,
    Telegram,
    Custom(String),
}

/// Linked identity — maps external auth to internal user
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LinkedIdentity {
    pub user_id: UserId,
    pub provider: AuthProvider,
    pub provider_user_id: String,
    pub email: Option<String>,
    pub linked_at: DateTime<Utc>,
}

/// Key management strategy
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum KeyStrategy {
    /// Shamir Secret Sharing (2-of-3)
    Shamir,
    /// MPC Threshold Signature Scheme (CGGMP21)
    MpcTss,
    /// Trusted Execution Environment
    Tee,
}

/// Encrypted key share
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct EncryptedShare {
    pub share_id: Uuid,
    pub user_id: UserId,
    pub share_index: u8,
    pub ciphertext: Vec<u8>,
    pub nonce: Vec<u8>,
    pub created_at: DateTime<Utc>,
    pub rotated_at: Option<DateTime<Utc>>,
}

/// Wallet address with chain info
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct WalletAddress {
    pub address: String,
    pub chain: Chain,
    pub wallet_type: WalletType,
}

/// Supported chains
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum Chain {
    Ethereum,
    Base,
    Polygon,
    Arbitrum,
    Optimism,
    Solana,
    Custom { chain_id: u64, name: String },
}

/// Wallet type
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum WalletType {
    /// Raw EOA (externally owned account)
    Eoa,
    /// ERC-4337 smart contract wallet
    SmartAccount,
}

/// Sensitive bytes that auto-zero on drop
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct SecretBytes(pub Vec<u8>);

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretBytes([REDACTED; {} bytes])", self.0.len())
    }
}
