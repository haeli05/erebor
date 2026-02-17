use chrono::{DateTime, Utc};
use erebor_common::UserId;
use serde::{Deserialize, Serialize};
use uuid::Uuid;

/// Types of conditions that can be checked
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ConditionKind {
    WalletAddress,
    ContractAddress,
    ChainId,
    TokenAddress,
    IpAddress,
    Country,
    UserId,
}

/// A single condition item within a condition set
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConditionItem {
    pub id: Uuid,
    pub kind: ConditionKind,
    pub operator: ConditionOperator,
    pub value: serde_json::Value,
    pub enabled: bool,
}

/// Operators for condition evaluation
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ConditionOperator {
    Equals,
    NotEquals,
    In,
    NotIn,
    Contains,
    NotContains,
    GreaterThan,
    LessThan,
    GreaterThanOrEqual,
    LessThanOrEqual,
    StartsWith,
    EndsWith,
    Regex,
}

/// A set of conditions that can be evaluated together
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ConditionSet {
    pub id: Uuid,
    pub name: String,
    pub description: Option<String>,
    pub owner_id: UserId,
    pub items: Vec<ConditionItem>,
    pub logic: ConditionLogic,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
}

/// Logic for combining multiple conditions
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(rename_all = "snake_case")]
pub enum ConditionLogic {
    /// All conditions must match
    And,
    /// At least one condition must match
    Or,
    /// Custom logic expression (e.g., "(A AND B) OR C")
    Custom(String),
}

impl ConditionSet {
    /// Create a new condition set
    pub fn new(name: String, owner_id: UserId, logic: ConditionLogic) -> Self {
        let now = Utc::now();
        Self {
            id: Uuid::new_v4(),
            name,
            description: None,
            owner_id,
            items: Vec::new(),
            logic,
            created_at: now,
            updated_at: now,
        }
    }

    /// Add a condition item to the set
    pub fn add_condition(&mut self, kind: ConditionKind, operator: ConditionOperator, value: serde_json::Value) {
        let condition_item = ConditionItem {
            id: Uuid::new_v4(),
            kind,
            operator,
            value,
            enabled: true,
        };
        self.items.push(condition_item);
        self.updated_at = Utc::now();
    }

    /// Remove a condition item by ID
    pub fn remove_condition(&mut self, condition_id: &Uuid) -> bool {
        let initial_len = self.items.len();
        self.items.retain(|item| &item.id != condition_id);
        if self.items.len() != initial_len {
            self.updated_at = Utc::now();
            true
        } else {
            false
        }
    }

    /// Update the condition set timestamp
    pub fn update(&mut self) {
        self.updated_at = Utc::now();
    }
}