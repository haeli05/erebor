use chrono::{DateTime, Duration, Utc};
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Different types of policy rules that can be enforced
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "type", rename_all = "snake_case")]
pub enum RuleKind {
    /// Enforce spending limits over time periods
    SpendingLimit {
        max_amount: u128,
        period: Duration,
        currency: String,
    },
    /// Only allow transactions to specific recipients
    AllowedRecipients { addresses: Vec<String> },
    /// Block transactions to specific recipients
    BlockedRecipients { addresses: Vec<String> },
    /// Only allow transactions on specific chains
    AllowedChains { chain_ids: Vec<u64> },
    /// Only allow transactions within specific time windows
    TimeWindow {
        allowed_hours: (u8, u8), // e.g. (9, 17) for 9 AM - 5 PM
        timezone: String,        // e.g. "UTC", "America/New_York"
    },
    /// Restrict transactions based on geographic location
    GeoRestriction { allowed_countries: Vec<String> },
    /// Set maximum transaction value
    MaxTransactionValue { max_wei: u128 },
    /// Require multi-signature approval
    RequireMultiSig {
        threshold: u32,
        signers: Vec<String>,
    },
    /// Rate limiting - max transactions per period
    RateLimit {
        max_transactions: u32,
        period: Duration,
    },
    /// Only allow interactions with specific contracts
    ContractAllowlist { addresses: Vec<String> },
    /// Custom webhook for external validation
    CustomWebhook {
        url: String,
        timeout_ms: u64,
    },
}

/// Actions that can be taken when a rule is triggered
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "action", rename_all = "snake_case")]
pub enum RuleAction {
    /// Allow the transaction
    Allow,
    /// Deny the transaction with a reason
    Deny { reason: String },
    /// Require approval from a quorum
    RequireApproval { quorum_id: Uuid },
}

/// A policy rule configuration
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub kind: RuleKind,
    pub action: RuleAction,
    pub priority: u32, // Lower number = higher priority
    pub enabled: bool,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

impl Rule {
    /// Create a new rule with default values
    pub fn new(name: String, kind: RuleKind, action: RuleAction, priority: u32) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            name,
            description: None,
            kind,
            action,
            priority,
            enabled: true,
            created_at: now,
            updated_at: now,
        }
    }

    /// Update the rule and set the updated_at timestamp
    pub fn update(&mut self) {
        self.updated_at = Utc::now();
    }
}