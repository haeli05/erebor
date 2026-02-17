use thiserror::Error;
use uuid::Uuid;

/// Policy engine error types
#[derive(Error, Debug)]
pub enum PolicyError {
    #[error("Rule not found: {rule_id}")]
    RuleNotFound { rule_id: Uuid },

    #[error("Condition set not found: {condition_set_id}")]
    ConditionSetNotFound { condition_set_id: Uuid },

    #[error("Quorum not found: {quorum_id}")]
    QuorumNotFound { quorum_id: Uuid },

    #[error("Approval request not found: {request_id}")]
    ApprovalRequestNotFound { request_id: Uuid },

    #[error("Aggregation not found: {aggregation_id}")]
    AggregationNotFound { aggregation_id: Uuid },

    #[error("Invalid rule configuration: {reason}")]
    InvalidRuleConfiguration { reason: String },

    #[error("Invalid condition configuration: {reason}")]
    InvalidConditionConfiguration { reason: String },

    #[error("Invalid quorum configuration: {reason}")]
    InvalidQuorumConfiguration { reason: String },

    #[error("Approval already submitted by user: {user_id}")]
    ApprovalAlreadySubmitted { user_id: String },

    #[error("User not authorized to approve: {user_id}")]
    UserNotAuthorized { user_id: String },

    #[error("Approval request expired: {request_id}")]
    ApprovalRequestExpired { request_id: Uuid },

    #[error("Serialization error: {0}")]
    Serialization(#[from] serde_json::Error),

    #[error("Internal error: {message}")]
    Internal { message: String },
}

pub type PolicyResult<T> = Result<T, PolicyError>;