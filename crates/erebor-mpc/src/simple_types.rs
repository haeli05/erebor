use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;
use chrono::{DateTime, Utc};

/// Simplified request/response types for the API

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PartyInfo {
    pub id: String,
    pub public_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkgRequest {
    pub session_id: String,
    pub threshold: u32,
    pub parties: Vec<PartyInfo>,
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DkgResponse {
    pub session_id: String,
    pub public_key: String,
    pub key_share: String,
    pub success: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningRequest {
    pub session_id: String,
    pub message: Vec<u8>,
    pub key_share: String,
    pub signers: Vec<String>,
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SigningResponse {
    pub session_id: String,
    pub signature: String,
    pub signers: Vec<String>,
    pub success: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshRequest {
    pub session_id: String,
    pub old_key_share: String,
    pub parties: Vec<String>,
    pub threshold: u32,
    pub timeout_ms: Option<u64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RefreshResponse {
    pub session_id: String,
    pub new_key_share: String,
    pub success: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Guardian {
    pub id: String,
    pub guardian_type: GuardianType,
    pub contact: String,
    pub public_key: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum GuardianType {
    Email,
    Phone,
    WalletAddress,
    HardwareKey,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryRequest {
    pub wallet_id: String,
    pub user_id: String,
    pub guardians: Vec<Guardian>,
    pub threshold: u32,
    pub recovery_phrase: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RecoveryApprovalRequest {
    pub recovery_id: String,
    pub guardian_id: String,
    pub approval_code: String,
    pub signature: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum RecoveryStatus {
    Initiated,
    Pending,
    Approved,
    Rejected,
    Completed,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionData {
    pub amount: u64,
    pub recipient: String,
    pub chain_id: u64,
    pub timestamp: DateTime<Utc>,
    pub gas_price: Option<u64>,
    pub contract_address: Option<String>,
    pub is_contract_verified: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyRequest {
    pub wallet_id: String,
    pub transaction: TransactionData,
    pub historical_patterns: HashMap<String, f64>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnomalyResponse {
    pub risk_score: u32, // 0-100
    pub risk_factors: Vec<String>,
    pub action: String,
    pub details: HashMap<String, String>,
}