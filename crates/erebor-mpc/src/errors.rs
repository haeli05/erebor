use thiserror::Error;

/// MPC-related errors
#[derive(Error, Debug)]
pub enum MpcError {
    #[error("DKG failed: {0}")]
    DkgFailed(String),
    
    #[error("Signing failed: {0}")]
    SigningFailed(String),
    
    #[error("Key refresh failed: {0}")]
    KeyRefreshFailed(String),
    
    #[error("Invalid threshold: got {actual}, expected between 1 and {max}")]
    InvalidThreshold { actual: u32, max: u32 },
    
    #[error("Insufficient parties: got {actual}, need at least {required}")]
    InsufficientParties { actual: usize, required: usize },
    
    #[error("Party {party_id} not found")]
    PartyNotFound { party_id: u32 },
    
    #[error("Invalid party configuration")]
    InvalidPartyConfiguration,
    
    #[error("Session {session_id} not found")]
    SessionNotFound { session_id: uuid::Uuid },
    
    #[error("Session {session_id} expired")]
    SessionExpired { session_id: uuid::Uuid },
    
    #[error("Cryptographic error: {0}")]
    CryptographicError(String),
    
    #[error("Network error: {0}")]
    NetworkError(#[from] reqwest::Error),
    
    #[error("Serialization error: {0}")]
    SerializationError(#[from] serde_json::Error),
}

/// Social recovery related errors
#[derive(Error, Debug)]
pub enum RecoveryError {
    #[error("Recovery request {request_id} not found")]
    RequestNotFound { request_id: uuid::Uuid },
    
    #[error("Recovery request {request_id} has expired")]
    RequestExpired { request_id: uuid::Uuid },
    
    #[error("Guardian {guardian_id} not found")]
    GuardianNotFound { guardian_id: uuid::Uuid },
    
    #[error("Guardian {guardian_id} is not active")]
    GuardianInactive { guardian_id: uuid::Uuid },
    
    #[error("Insufficient guardian approvals: got {actual}, need {required}")]
    InsufficientApprovals { actual: u32, required: u32 },
    
    #[error("Recovery already in progress for user {user_id}")]
    RecoveryInProgress { user_id: uuid::Uuid },
    
    #[error("Recovery cooling period active until {cooldown_until}")]
    RecoveryCooldown { cooldown_until: chrono::DateTime<chrono::Utc> },
    
    #[error("Invalid guardian signature")]
    InvalidGuardianSignature,
    
    #[error("Recovery share reconstruction failed: {0}")]
    ShareReconstructionFailed(String),
    
    #[error("Guardian type {guardian_type:?} not supported")]
    UnsupportedGuardianType { guardian_type: crate::types::GuardianType },
}

/// Anomaly detection related errors
#[derive(Error, Debug)]
pub enum AnomalyError {
    #[error("User baseline not found for user {user_id}")]
    BaselineNotFound { user_id: uuid::Uuid },
    
    #[error("Insufficient transaction history for user {user_id}")]
    InsufficientHistory { user_id: uuid::Uuid },
    
    #[error("Invalid risk score: {score} (must be 0-100)")]
    InvalidRiskScore { score: u8 },
    
    #[error("Risk assessment failed: {0}")]
    RiskAssessmentFailed(String),
    
    #[error("Behavioral analysis failed: {0}")]
    BehavioralAnalysisFailed(String),
    
    #[error("Alert creation failed: {0}")]
    AlertCreationFailed(String),
}

/// General MPC system errors
#[derive(Error, Debug)]
pub enum SystemError {
    #[error("Database error: {0}")]
    DatabaseError(String),
    
    #[error("Configuration error: {0}")]
    ConfigurationError(String),
    
    #[error("Internal error: {0}")]
    InternalError(String),
    
    #[error("Timeout occurred: {operation}")]
    Timeout { operation: String },
    
    #[error("Rate limit exceeded for {resource}")]
    RateLimitExceeded { resource: String },
    
    #[error("Permission denied: {0}")]
    PermissionDenied(String),
    
    #[error("Resource not found: {resource}")]
    ResourceNotFound { resource: String },
    
    #[error("Invalid input: {0}")]
    InvalidInput(String),
}

/// Unified error type for the MPC system
#[derive(Error, Debug)]
pub enum EreborMpcError {
    #[error("MPC error: {0}")]
    Mpc(#[from] MpcError),
    
    #[error("Recovery error: {0}")]
    Recovery(#[from] RecoveryError),
    
    #[error("Anomaly detection error: {0}")]
    Anomaly(#[from] AnomalyError),
    
    #[error("System error: {0}")]
    System(#[from] SystemError),
}

pub type Result<T> = std::result::Result<T, EreborMpcError>;