use chrono::{DateTime, Utc, Timelike};
use erebor_common::UserId;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use uuid::Uuid;

use crate::{
    aggregation::{AggregationStore, TransactionEvent},
    condition::{ConditionSet, ConditionKind, ConditionOperator},
    error::{PolicyError, PolicyResult},
    quorum::{ApprovalContext, ApprovalRequest, ApprovalStore, KeyQuorum},
    rule::{Rule, RuleAction, RuleKind},
};

/// Context for a transaction being evaluated
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionContext {
    pub user_id: UserId,
    pub wallet_id: String,
    pub to: String,
    pub value: u128,
    pub chain_id: u64,
    pub data: Vec<u8>,
    pub ip_address: Option<String>,
    pub country: Option<String>,
    pub timestamp: DateTime<Utc>,
}

/// Decision made by the policy engine
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
#[serde(tag = "decision", rename_all = "snake_case")]
pub enum PolicyDecision {
    /// Allow the transaction
    Allow,
    /// Deny the transaction
    Deny { rule_id: Uuid, reason: String },
    /// Require approval before allowing
    RequireApproval { quorum_id: Uuid, request_id: Uuid },
}

/// The main policy evaluation engine
#[derive(Debug, Clone)]
pub struct PolicyEngine {
    rules: Vec<Rule>,
    condition_sets: HashMap<Uuid, ConditionSet>,
    aggregations: AggregationStore,
    quorums: HashMap<Uuid, KeyQuorum>,
    approval_store: ApprovalStore,
}

impl PolicyEngine {
    /// Create a new policy engine
    pub fn new() -> Self {
        Self {
            rules: Vec::new(),
            condition_sets: HashMap::new(),
            aggregations: AggregationStore::new(),
            quorums: HashMap::new(),
            approval_store: ApprovalStore::new(),
        }
    }

    /// Evaluate a transaction against all policies
    pub fn evaluate(&mut self, ctx: &TransactionContext) -> PolicyDecision {
        // Record the transaction event for aggregations
        let event = TransactionEvent {
            id: Uuid::new_v4(),
            user_id: ctx.user_id.clone(),
            wallet_id: ctx.wallet_id.clone(),
            from: ctx.wallet_id.clone(), // Simplified - would need actual from address
            to: ctx.to.clone(),
            value: ctx.value,
            chain_id: ctx.chain_id,
            gas_used: None,
            gas_price: None,
            success: true, // We assume success for evaluation purposes
            timestamp: ctx.timestamp,
            ip_address: ctx.ip_address.clone(),
            country: ctx.country.clone(),
        };
        self.aggregations.record(&event);

        // Sort rules by priority (lower number = higher priority)
        let mut rules = self.rules.clone();
        rules.sort_by_key(|rule| rule.priority);

        // Evaluate each enabled rule
        for rule in &rules {
            if !rule.enabled {
                continue;
            }

            if self.evaluate_rule(rule, ctx) {
                match &rule.action {
                    RuleAction::Allow => return PolicyDecision::Allow,
                    RuleAction::Deny { reason } => {
                        return PolicyDecision::Deny {
                            rule_id: rule.id,
                            reason: reason.clone(),
                        };
                    }
                    RuleAction::RequireApproval { quorum_id } => {
                        let approval_context = ApprovalContext {
                            transaction_id: None,
                            user_id: ctx.user_id.clone(),
                            wallet_id: ctx.wallet_id.clone(),
                            to: ctx.to.clone(),
                            value: ctx.value,
                            chain_id: ctx.chain_id,
                            data: ctx.data.clone(),
                            ip_address: ctx.ip_address.clone(),
                            country: ctx.country.clone(),
                            timestamp: ctx.timestamp,
                        };

                        let approval_request = ApprovalRequest::new(*quorum_id, approval_context, 24); // 24 hour expiry
                        let request_id = approval_request.id;
                        self.approval_store.add_request(approval_request);

                        return PolicyDecision::RequireApproval {
                            quorum_id: *quorum_id,
                            request_id,
                        };
                    }
                }
            }
        }

        // If no rules triggered, allow the transaction
        PolicyDecision::Allow
    }

    /// Evaluate a single rule against the transaction context
    fn evaluate_rule(&self, rule: &Rule, ctx: &TransactionContext) -> bool {
        match &rule.kind {
            RuleKind::SpendingLimit { max_amount, period: _, currency: _ } => {
                // For simplicity, using user_id as group key
                let _group_key = ctx.user_id.0.to_string();
                
                // Check if there's a spending limit aggregation
                // In a real implementation, we'd need to create aggregations dynamically
                // or have a more sophisticated way to track spending
                
                // For now, we'll assume spending is tracked elsewhere
                // and implement a simple value check
                ctx.value > *max_amount
            }
            RuleKind::AllowedRecipients { addresses } => {
                !addresses.contains(&ctx.to)
            }
            RuleKind::BlockedRecipients { addresses } => {
                addresses.contains(&ctx.to)
            }
            RuleKind::AllowedChains { chain_ids } => {
                !chain_ids.contains(&ctx.chain_id)
            }
            RuleKind::TimeWindow { allowed_hours, timezone: _ } => {
                // Simplified timezone handling - using UTC
                let hour = ctx.timestamp.hour();
                let (start, end) = *allowed_hours;
                !(start as u32..=end as u32).contains(&hour)
            }
            RuleKind::GeoRestriction { allowed_countries } => {
                if let Some(country) = &ctx.country {
                    !allowed_countries.contains(country)
                } else {
                    true // No country info - restrict
                }
            }
            RuleKind::MaxTransactionValue { max_wei } => {
                ctx.value > *max_wei
            }
            RuleKind::RequireMultiSig { threshold: _, signers: _ } => {
                // Always trigger for multi-sig rules - approval logic handles threshold
                true
            }
            RuleKind::RateLimit { max_transactions: _, period: _ } => {
                // Simplified rate limiting - would need proper aggregation
                // For now, just allow
                false
            }
            RuleKind::ContractAllowlist { addresses } => {
                !addresses.contains(&ctx.to)
            }
            RuleKind::CustomWebhook { url: _, timeout_ms: _ } => {
                // Would make HTTP request to webhook
                // For now, just allow
                false
            }
        }
    }

    /// Add a new rule to the engine
    pub fn add_rule(&mut self, rule: Rule) {
        self.rules.push(rule);
    }

    /// Remove a rule by ID
    pub fn remove_rule(&mut self, rule_id: &Uuid) -> bool {
        let initial_len = self.rules.len();
        self.rules.retain(|rule| &rule.id != rule_id);
        self.rules.len() != initial_len
    }

    /// Get a rule by ID
    pub fn get_rule(&self, rule_id: &Uuid) -> Option<&Rule> {
        self.rules.iter().find(|rule| &rule.id == rule_id)
    }

    /// Get all rules
    pub fn get_rules(&self) -> &[Rule] {
        &self.rules
    }

    /// Create a new condition set
    pub fn create_condition_set(&mut self, condition_set: ConditionSet) {
        self.condition_sets.insert(condition_set.id, condition_set);
    }

    /// Get a condition set by ID
    pub fn get_condition_set(&self, condition_set_id: &Uuid) -> Option<&ConditionSet> {
        self.condition_sets.get(condition_set_id)
    }

    /// Create a new quorum
    pub fn create_quorum(&mut self, quorum: KeyQuorum) {
        self.quorums.insert(quorum.id, quorum);
    }

    /// Get a quorum by ID
    pub fn get_quorum(&self, quorum_id: &Uuid) -> Option<&KeyQuorum> {
        self.quorums.get(quorum_id)
    }

    /// Get a mutable quorum by ID
    pub fn get_quorum_mut(&mut self, quorum_id: &Uuid) -> Option<&mut KeyQuorum> {
        self.quorums.get_mut(quorum_id)
    }

    /// Submit an approval for a request
    pub fn submit_approval(
        &mut self,
        request_id: &Uuid,
        user_id: &UserId,
        approved: bool,
        reason: Option<String>,
    ) -> PolicyResult<crate::quorum::ApprovalStatus> {
        let request = self
            .approval_store
            .get_request_mut(request_id)
            .ok_or(PolicyError::ApprovalRequestNotFound {
                request_id: *request_id,
            })?;

        if request.is_expired() {
            return Err(PolicyError::ApprovalRequestExpired {
                request_id: *request_id,
            });
        }

        // Check if user already submitted approval
        if request.approvals.iter().any(|a| &a.user_id == user_id) {
            return Err(PolicyError::ApprovalAlreadySubmitted {
                user_id: user_id.0.to_string(),
            });
        }

        let quorum = self
            .quorums
            .get(&request.quorum_id)
            .ok_or(PolicyError::QuorumNotFound {
                quorum_id: request.quorum_id,
            })?;

        // Check if user can approve
        if !quorum.can_approve(user_id) {
            return Err(PolicyError::UserNotAuthorized {
                user_id: user_id.0.to_string(),
            });
        }

        // Submit the approval
        request.submit_approval(user_id.clone(), approved, reason);
        
        // Update status
        request.update_status(quorum);

        Ok(request.status.clone())
    }

    /// Get an approval request by ID
    pub fn get_approval_request(&self, request_id: &Uuid) -> Option<&ApprovalRequest> {
        self.approval_store.get_request(request_id)
    }

    /// Get all pending approval requests for a quorum
    pub fn get_pending_approvals(&self, quorum_id: &Uuid) -> Vec<&ApprovalRequest> {
        self.approval_store.get_pending_requests_for_quorum(quorum_id)
    }

    /// Clean up expired approval requests
    pub fn cleanup_expired_approvals(&mut self) {
        self.approval_store.cleanup_expired();
    }

    /// Get a reference to the aggregation store
    pub fn aggregations(&self) -> &AggregationStore {
        &self.aggregations
    }

    /// Get a mutable reference to the aggregation store
    pub fn aggregations_mut(&mut self) -> &mut AggregationStore {
        &mut self.aggregations
    }

    /// Evaluate a condition set against transaction context
    pub fn evaluate_condition_set(&self, condition_set_id: &Uuid, ctx: &TransactionContext) -> bool {
        let condition_set = match self.condition_sets.get(condition_set_id) {
            Some(cs) => cs,
            None => return false,
        };

        let mut results = Vec::new();
        
        for item in &condition_set.items {
            if !item.enabled {
                continue;
            }

            let value = match item.kind {
                ConditionKind::WalletAddress => serde_json::Value::String(ctx.wallet_id.clone()),
                ConditionKind::ContractAddress => serde_json::Value::String(ctx.to.clone()),
                ConditionKind::ChainId => serde_json::Value::Number(ctx.chain_id.into()),
                ConditionKind::TokenAddress => serde_json::Value::String(ctx.to.clone()),
                ConditionKind::IpAddress => ctx.ip_address.clone()
                    .map(serde_json::Value::String)
                    .unwrap_or(serde_json::Value::Null),
                ConditionKind::Country => ctx.country.clone()
                    .map(serde_json::Value::String)
                    .unwrap_or(serde_json::Value::Null),
                ConditionKind::UserId => serde_json::Value::String(ctx.user_id.0.to_string()),
            };

            let result = self.evaluate_condition_operator(&item.operator, &value, &item.value);
            results.push(result);
        }

        // Apply condition logic
        match condition_set.logic {
            crate::condition::ConditionLogic::And => results.iter().all(|&r| r),
            crate::condition::ConditionLogic::Or => results.iter().any(|&r| r),
            crate::condition::ConditionLogic::Custom(_) => {
                // Simplified - just treat as AND for now
                results.iter().all(|&r| r)
            }
        }
    }

    /// Evaluate a condition operator
    fn evaluate_condition_operator(
        &self,
        operator: &ConditionOperator,
        actual: &serde_json::Value,
        expected: &serde_json::Value,
    ) -> bool {
        match operator {
            ConditionOperator::Equals => actual == expected,
            ConditionOperator::NotEquals => actual != expected,
            ConditionOperator::In => {
                if let serde_json::Value::Array(arr) = expected {
                    arr.contains(actual)
                } else {
                    false
                }
            }
            ConditionOperator::NotIn => {
                if let serde_json::Value::Array(arr) = expected {
                    !arr.contains(actual)
                } else {
                    true
                }
            }
            ConditionOperator::Contains => {
                if let (serde_json::Value::String(actual_str), serde_json::Value::String(expected_str)) = (actual, expected) {
                    actual_str.contains(expected_str)
                } else {
                    false
                }
            }
            ConditionOperator::NotContains => {
                if let (serde_json::Value::String(actual_str), serde_json::Value::String(expected_str)) = (actual, expected) {
                    !actual_str.contains(expected_str)
                } else {
                    true
                }
            }
            ConditionOperator::GreaterThan => {
                self.compare_numbers(actual, expected, |a, b| a > b)
            }
            ConditionOperator::LessThan => {
                self.compare_numbers(actual, expected, |a, b| a < b)
            }
            ConditionOperator::GreaterThanOrEqual => {
                self.compare_numbers(actual, expected, |a, b| a >= b)
            }
            ConditionOperator::LessThanOrEqual => {
                self.compare_numbers(actual, expected, |a, b| a <= b)
            }
            ConditionOperator::StartsWith => {
                if let (serde_json::Value::String(actual_str), serde_json::Value::String(expected_str)) = (actual, expected) {
                    actual_str.starts_with(expected_str)
                } else {
                    false
                }
            }
            ConditionOperator::EndsWith => {
                if let (serde_json::Value::String(actual_str), serde_json::Value::String(expected_str)) = (actual, expected) {
                    actual_str.ends_with(expected_str)
                } else {
                    false
                }
            }
            ConditionOperator::Regex => {
                // Would need regex crate for full implementation
                false
            }
        }
    }

    /// Compare numbers for condition evaluation
    fn compare_numbers<F>(&self, actual: &serde_json::Value, expected: &serde_json::Value, compare: F) -> bool
    where
        F: Fn(f64, f64) -> bool,
    {
        if let (Some(actual_num), Some(expected_num)) = (actual.as_f64(), expected.as_f64()) {
            compare(actual_num, expected_num)
        } else {
            false
        }
    }
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}