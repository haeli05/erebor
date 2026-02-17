use thiserror::Error;

#[derive(Error, Debug)]
pub enum EreborError {
    #[error("Authentication failed: {0}")]
    AuthError(String),

    #[error("Invalid token: {0}")]
    InvalidToken(String),

    #[error("Key vault error: {0}")]
    VaultError(String),

    #[error("Share reconstruction failed: {0}")]
    ShareError(String),

    #[error("Encryption error: {0}")]
    EncryptionError(String),

    #[error("Database error: {0}")]
    DatabaseError(String),

    #[error("Chain error: {0}")]
    ChainError(String),

    #[error("Rate limited")]
    RateLimited,

    #[error("Not found: {0}")]
    NotFound(String),

    #[error("Unauthorized")]
    Unauthorized,

    #[error("Internal error: {0}")]
    Internal(String),
}

pub type Result<T> = std::result::Result<T, EreborError>;
