use chrono::{Duration, Utc};
use erebor_common::UserId;
use uuid::Uuid;

use crate::{
    aggregation::{Aggregation, AggregationMetric, TransactionEvent},
    condition::{ConditionKind, ConditionLogic, ConditionOperator, ConditionSet},
    engine::{PolicyEngine, TransactionContext},
    quorum::{KeyQuorum, QuorumRole},
    rule::{Rule, RuleAction, RuleKind},
    PolicyDecision,
};

fn create_test_context() -> TransactionContext {
    TransactionContext {
        user_id: UserId::new(),
        wallet_id: "0x1234567890abcdef".to_string(),
        to: "0xabcdef1234567890".to_string(),
        value: 1_000_000_000_000_000_000, // 1 ETH in wei
        chain_id: 1, // Ethereum mainnet
        data: vec![],
        ip_address: Some("192.168.1.1".to_string()),
        country: Some("US".to_string()),
        timestamp: Utc::now(),
    }
}

#[test]
fn test_policy_engine_creation() {
    let engine = PolicyEngine::new();
    assert_eq!(engine.get_rules().len(), 0);
}

#[test]
fn test_add_and_remove_rule() {
    let mut engine = PolicyEngine::new();
    
    let rule = Rule::new(
        "Test Rule".to_string(),
        RuleKind::MaxTransactionValue { max_wei: 500_000_000_000_000_000 }, // 0.5 ETH
        RuleAction::Deny { reason: "Transaction too large".to_string() },
        100,
    );
    
    let rule_id = rule.id;
    engine.add_rule(rule);
    
    assert_eq!(engine.get_rules().len(), 1);
    assert!(engine.get_rule(&rule_id).is_some());
    
    assert!(engine.remove_rule(&rule_id));
    assert_eq!(engine.get_rules().len(), 0);
    assert!(engine.get_rule(&rule_id).is_none());
}

#[test]
fn test_max_transaction_value_rule_triggers() {
    let mut engine = PolicyEngine::new();
    let ctx = create_test_context(); // 1 ETH transaction
    
    let rule = Rule::new(
        "Max Value Rule".to_string(),
        RuleKind::MaxTransactionValue { max_wei: 500_000_000_000_000_000 }, // 0.5 ETH limit
        RuleAction::Deny { reason: "Transaction exceeds maximum value".to_string() },
        100,
    );
    
    let rule_id = rule.id;
    engine.add_rule(rule);
    
    let decision = engine.evaluate(&ctx);
    match decision {
        PolicyDecision::Deny { rule_id: triggered_rule_id, reason } => {
            assert_eq!(rule_id, triggered_rule_id);
            assert_eq!(reason, "Transaction exceeds maximum value");
        }
        _ => panic!("Expected Deny decision"),
    }
}

#[test]
fn test_max_transaction_value_rule_allows_smaller_amounts() {
    let mut engine = PolicyEngine::new();
    let mut ctx = create_test_context();
    ctx.value = 250_000_000_000_000_000; // 0.25 ETH
    
    let rule = Rule::new(
        "Max Value Rule".to_string(),
        RuleKind::MaxTransactionValue { max_wei: 500_000_000_000_000_000 }, // 0.5 ETH limit
        RuleAction::Deny { reason: "Transaction exceeds maximum value".to_string() },
        100,
    );
    
    engine.add_rule(rule);
    
    let decision = engine.evaluate(&ctx);
    assert_eq!(decision, PolicyDecision::Allow);
}

#[test]
fn test_allowed_recipients_rule() {
    let mut engine = PolicyEngine::new();
    let ctx = create_test_context();
    
    let rule = Rule::new(
        "Allowed Recipients".to_string(),
        RuleKind::AllowedRecipients {
            addresses: vec!["0xfeedface".to_string(), "0xdeadbeef".to_string()],
        },
        RuleAction::Deny { reason: "Recipient not allowed".to_string() },
        100,
    );
    
    engine.add_rule(rule);
    
    let decision = engine.evaluate(&ctx);
    match decision {
        PolicyDecision::Deny { reason, .. } => {
            assert_eq!(reason, "Recipient not allowed");
        }
        _ => panic!("Expected Deny decision"),
    }
}

#[test]
fn test_allowed_recipients_rule_allows_whitelisted() {
    let mut engine = PolicyEngine::new();
    let mut ctx = create_test_context();
    ctx.to = "0xfeedface".to_string();
    
    let rule = Rule::new(
        "Allowed Recipients".to_string(),
        RuleKind::AllowedRecipients {
            addresses: vec!["0xfeedface".to_string(), "0xdeadbeef".to_string()],
        },
        RuleAction::Deny { reason: "Recipient not allowed".to_string() },
        100,
    );
    
    engine.add_rule(rule);
    
    let decision = engine.evaluate(&ctx);
    assert_eq!(decision, PolicyDecision::Allow);
}

#[test]
fn test_blocked_recipients_rule() {
    let mut engine = PolicyEngine::new();
    let mut ctx = create_test_context();
    ctx.to = "0xbadactor".to_string();
    
    let rule = Rule::new(
        "Blocked Recipients".to_string(),
        RuleKind::BlockedRecipients {
            addresses: vec!["0xbadactor".to_string(), "0xscammer".to_string()],
        },
        RuleAction::Deny { reason: "Recipient is blocked".to_string() },
        100,
    );
    
    engine.add_rule(rule);
    
    let decision = engine.evaluate(&ctx);
    match decision {
        PolicyDecision::Deny { reason, .. } => {
            assert_eq!(reason, "Recipient is blocked");
        }
        _ => panic!("Expected Deny decision"),
    }
}

#[test]
fn test_blocked_recipients_rule_allows_others() {
    let mut engine = PolicyEngine::new();
    let ctx = create_test_context();
    
    let rule = Rule::new(
        "Blocked Recipients".to_string(),
        RuleKind::BlockedRecipients {
            addresses: vec!["0xbadactor".to_string(), "0xscammer".to_string()],
        },
        RuleAction::Deny { reason: "Recipient is blocked".to_string() },
        100,
    );
    
    engine.add_rule(rule);
    
    let decision = engine.evaluate(&ctx);
    assert_eq!(decision, PolicyDecision::Allow);
}

#[test]
fn test_allowed_chains_rule() {
    let mut engine = PolicyEngine::new();
    let mut ctx = create_test_context();
    ctx.chain_id = 137; // Polygon
    
    let rule = Rule::new(
        "Allowed Chains".to_string(),
        RuleKind::AllowedChains {
            chain_ids: vec![1, 42161], // Ethereum and Arbitrum only
        },
        RuleAction::Deny { reason: "Chain not allowed".to_string() },
        100,
    );
    
    engine.add_rule(rule);
    
    let decision = engine.evaluate(&ctx);
    match decision {
        PolicyDecision::Deny { reason, .. } => {
            assert_eq!(reason, "Chain not allowed");
        }
        _ => panic!("Expected Deny decision"),
    }
}

#[test]
fn test_allowed_chains_rule_allows_whitelisted() {
    let mut engine = PolicyEngine::new();
    let ctx = create_test_context(); // Chain ID 1 (Ethereum)
    
    let rule = Rule::new(
        "Allowed Chains".to_string(),
        RuleKind::AllowedChains {
            chain_ids: vec![1, 42161], // Ethereum and Arbitrum
        },
        RuleAction::Deny { reason: "Chain not allowed".to_string() },
        100,
    );
    
    engine.add_rule(rule);
    
    let decision = engine.evaluate(&ctx);
    assert_eq!(decision, PolicyDecision::Allow);
}

#[test]
fn test_time_window_rule_outside_hours() {
    let mut engine = PolicyEngine::new();
    let mut ctx = create_test_context();
    
    // Set time to 3 AM UTC (outside 9-17 window)
    ctx.timestamp = Utc::now().with_hour(3).unwrap().with_minute(0).unwrap().with_second(0).unwrap();
    
    let rule = Rule::new(
        "Business Hours Only".to_string(),
        RuleKind::TimeWindow {
            allowed_hours: (9, 17), // 9 AM - 5 PM
            timezone: "UTC".to_string(),
        },
        RuleAction::Deny { reason: "Transactions only allowed during business hours".to_string() },
        100,
    );
    
    engine.add_rule(rule);
    
    let decision = engine.evaluate(&ctx);
    match decision {
        PolicyDecision::Deny { reason, .. } => {
            assert_eq!(reason, "Transactions only allowed during business hours");
        }
        _ => panic!("Expected Deny decision"),
    }
}

#[test]
fn test_time_window_rule_inside_hours() {
    let mut engine = PolicyEngine::new();
    let mut ctx = create_test_context();
    
    // Set time to 2 PM UTC (inside 9-17 window)
    ctx.timestamp = Utc::now().with_hour(14).unwrap().with_minute(0).unwrap().with_second(0).unwrap();
    
    let rule = Rule::new(
        "Business Hours Only".to_string(),
        RuleKind::TimeWindow {
            allowed_hours: (9, 17),
            timezone: "UTC".to_string(),
        },
        RuleAction::Deny { reason: "Transactions only allowed during business hours".to_string() },
        100,
    );
    
    engine.add_rule(rule);
    
    let decision = engine.evaluate(&ctx);
    assert_eq!(decision, PolicyDecision::Allow);
}

#[test]
fn test_geo_restriction_rule() {
    let mut engine = PolicyEngine::new();
    let mut ctx = create_test_context();
    ctx.country = Some("CN".to_string()); // China
    
    let rule = Rule::new(
        "Geo Restriction".to_string(),
        RuleKind::GeoRestriction {
            allowed_countries: vec!["US".to_string(), "CA".to_string(), "GB".to_string()],
        },
        RuleAction::Deny { reason: "Country not allowed".to_string() },
        100,
    );
    
    engine.add_rule(rule);
    
    let decision = engine.evaluate(&ctx);
    match decision {
        PolicyDecision::Deny { reason, .. } => {
            assert_eq!(reason, "Country not allowed");
        }
        _ => panic!("Expected Deny decision"),
    }
}

#[test]
fn test_geo_restriction_rule_allows_whitelisted() {
    let mut engine = PolicyEngine::new();
    let ctx = create_test_context(); // US by default
    
    let rule = Rule::new(
        "Geo Restriction".to_string(),
        RuleKind::GeoRestriction {
            allowed_countries: vec!["US".to_string(), "CA".to_string(), "GB".to_string()],
        },
        RuleAction::Deny { reason: "Country not allowed".to_string() },
        100,
    );
    
    engine.add_rule(rule);
    
    let decision = engine.evaluate(&ctx);
    assert_eq!(decision, PolicyDecision::Allow);
}

#[test]
fn test_rule_priority_ordering() {
    let mut engine = PolicyEngine::new();
    let ctx = create_test_context();
    
    // Add high priority allow rule
    let allow_rule = Rule::new(
        "Allow Rule".to_string(),
        RuleKind::MaxTransactionValue { max_wei: u128::MAX },
        RuleAction::Allow,
        1, // Higher priority (lower number)
    );
    
    // Add low priority deny rule
    let deny_rule = Rule::new(
        "Deny Rule".to_string(),
        RuleKind::MaxTransactionValue { max_wei: 500_000_000_000_000_000 },
        RuleAction::Deny { reason: "Should not trigger".to_string() },
        100, // Lower priority (higher number)
    );
    
    engine.add_rule(deny_rule);
    engine.add_rule(allow_rule);
    
    let decision = engine.evaluate(&ctx);
    assert_eq!(decision, PolicyDecision::Allow);
}

#[test]
fn test_multisig_approval_requirement() {
    let mut engine = PolicyEngine::new();
    let ctx = create_test_context();
    
    // Create a quorum
    let mut quorum = KeyQuorum::new("Test Quorum".to_string(), 2);
    quorum.add_member(UserId::new(), QuorumRole::Admin);
    quorum.add_member(UserId::new(), QuorumRole::Approver);
    quorum.add_member(UserId::new(), QuorumRole::Approver);
    let quorum_id = quorum.id;
    engine.create_quorum(quorum);
    
    let rule = Rule::new(
        "Multi-sig Rule".to_string(),
        RuleKind::RequireMultiSig {
            threshold: 2,
            signers: vec!["signer1".to_string(), "signer2".to_string(), "signer3".to_string()],
        },
        RuleAction::RequireApproval { quorum_id },
        100,
    );
    
    engine.add_rule(rule);
    
    let decision = engine.evaluate(&ctx);
    match decision {
        PolicyDecision::RequireApproval { quorum_id: returned_quorum_id, request_id } => {
            assert_eq!(quorum_id, returned_quorum_id);
            assert!(engine.get_approval_request(&request_id).is_some());
        }
        _ => panic!("Expected RequireApproval decision"),
    }
}

#[test]
fn test_approval_workflow() {
    let mut engine = PolicyEngine::new();
    let ctx = create_test_context();
    
    // Create users
    let admin_user = UserId::new();
    let approver_user = UserId::new();
    let viewer_user = UserId::new();
    
    // Create a quorum
    let mut quorum = KeyQuorum::new("Test Quorum".to_string(), 2);
    quorum.add_member(admin_user.clone(), QuorumRole::Admin);
    quorum.add_member(approver_user.clone(), QuorumRole::Approver);
    quorum.add_member(viewer_user.clone(), QuorumRole::Viewer);
    let quorum_id = quorum.id;
    engine.create_quorum(quorum);
    
    let rule = Rule::new(
        "Approval Rule".to_string(),
        RuleKind::MaxTransactionValue { max_wei: 0 }, // Always trigger
        RuleAction::RequireApproval { quorum_id },
        100,
    );
    
    engine.add_rule(rule);
    
    // Evaluate to create approval request
    let decision = engine.evaluate(&ctx);
    let request_id = match decision {
        PolicyDecision::RequireApproval { request_id, .. } => request_id,
        _ => panic!("Expected RequireApproval decision"),
    };
    
    // Try approval from viewer (should fail)
    let result = engine.submit_approval(&request_id, &viewer_user, true, None);
    assert!(result.is_err());
    
    // Submit approval from admin
    let result = engine.submit_approval(&request_id, &admin_user, true, None);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), crate::quorum::ApprovalStatus::Pending);
    
    // Submit approval from approver (should reach threshold)
    let result = engine.submit_approval(&request_id, &approver_user, true, None);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), crate::quorum::ApprovalStatus::Approved);
}

#[test]
fn test_approval_denial() {
    let mut engine = PolicyEngine::new();
    let ctx = create_test_context();
    
    // Create users
    let admin_user = UserId::new();
    let approver1 = UserId::new();
    let approver2 = UserId::new();
    
    // Create a quorum with threshold 2
    let mut quorum = KeyQuorum::new("Test Quorum".to_string(), 2);
    quorum.add_member(admin_user.clone(), QuorumRole::Admin);
    quorum.add_member(approver1.clone(), QuorumRole::Approver);
    quorum.add_member(approver2.clone(), QuorumRole::Approver);
    let quorum_id = quorum.id;
    engine.create_quorum(quorum);
    
    let rule = Rule::new(
        "Approval Rule".to_string(),
        RuleKind::MaxTransactionValue { max_wei: 0 }, // Always trigger
        RuleAction::RequireApproval { quorum_id },
        100,
    );
    
    engine.add_rule(rule);
    
    // Evaluate to create approval request
    let decision = engine.evaluate(&ctx);
    let request_id = match decision {
        PolicyDecision::RequireApproval { request_id, .. } => request_id,
        _ => panic!("Expected RequireApproval decision"),
    };
    
    // Submit denial from admin
    let result = engine.submit_approval(&request_id, &admin_user, false, Some("Not approved".to_string()));
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), crate::quorum::ApprovalStatus::Pending);
    
    // Submit denial from approver1 (should deny the request since 2 denials > (3 approvers - 2 threshold))
    let result = engine.submit_approval(&request_id, &approver1, false, None);
    assert!(result.is_ok());
    assert_eq!(result.unwrap(), crate::quorum::ApprovalStatus::Denied);
}

#[test]
fn test_condition_set_creation_and_evaluation() {
    let mut engine = PolicyEngine::new();
    let ctx = create_test_context();
    
    let user_id = UserId::new();
    let mut condition_set = ConditionSet::new("Test Conditions".to_string(), user_id, ConditionLogic::And);
    
    // Add condition for chain ID
    condition_set.add_condition(
        ConditionKind::ChainId,
        ConditionOperator::Equals,
        serde_json::json!(1),
    );
    
    // Add condition for country
    condition_set.add_condition(
        ConditionKind::Country,
        ConditionOperator::Equals,
        serde_json::json!("US"),
    );
    
    let condition_set_id = condition_set.id;
    engine.create_condition_set(condition_set);
    
    // Should match (chain ID 1 AND country US)
    assert!(engine.evaluate_condition_set(&condition_set_id, &ctx));
    
    // Test with different country
    let mut ctx2 = ctx.clone();
    ctx2.country = Some("CA".to_string());
    assert!(!engine.evaluate_condition_set(&condition_set_id, &ctx2));
}

#[test]
fn test_condition_set_or_logic() {
    let mut engine = PolicyEngine::new();
    let ctx = create_test_context();
    
    let user_id = UserId::new();
    let mut condition_set = ConditionSet::new("Test OR Conditions".to_string(), user_id, ConditionLogic::Or);
    
    // Add condition for chain ID 42161 (Arbitrum)
    condition_set.add_condition(
        ConditionKind::ChainId,
        ConditionOperator::Equals,
        serde_json::json!(42161),
    );
    
    // Add condition for country US
    condition_set.add_condition(
        ConditionKind::Country,
        ConditionOperator::Equals,
        serde_json::json!("US"),
    );
    
    let condition_set_id = condition_set.id;
    engine.create_condition_set(condition_set);
    
    // Should match (chain ID 1 != 42161 BUT country == US)
    assert!(engine.evaluate_condition_set(&condition_set_id, &ctx));
}

#[test]
fn test_aggregation_recording() {
    let mut engine = PolicyEngine::new();
    let ctx = create_test_context();
    
    // Create transaction count aggregation
    let aggregation = Aggregation {
        id: Uuid::new_v4(),
        name: "Transaction Count".to_string(),
        description: None,
        metric: AggregationMetric::TransactionCount,
        window: Duration::hours(24),
        group_by: vec!["user_id".to_string()],
        enabled: true,
        created_at: Utc::now(),
        updated_at: Utc::now(),
    };
    
    engine.aggregations.add_aggregation(aggregation.clone());
    
    // Record some transactions
    engine.evaluate(&ctx);
    engine.evaluate(&ctx);
    engine.evaluate(&ctx);
    
    // Query the aggregation
    let group_key = ctx.user_id.0.to_string();
    let count = engine.aggregations.query(&aggregation.id, &group_key);
    assert_eq!(count, 3);
}

#[test]
fn test_combined_rules_evaluation() {
    let mut engine = PolicyEngine::new();
    let mut ctx = create_test_context();
    ctx.value = 2_000_000_000_000_000_000; // 2 ETH
    ctx.to = "0xbadactor".to_string();
    ctx.chain_id = 137; // Polygon
    
    // Add multiple rules with different priorities
    
    // High priority: Block bad actors
    let block_rule = Rule::new(
        "Block Bad Actors".to_string(),
        RuleKind::BlockedRecipients {
            addresses: vec!["0xbadactor".to_string()],
        },
        RuleAction::Deny { reason: "Recipient blocked".to_string() },
        1, // Highest priority
    );
    
    // Medium priority: Chain restriction
    let chain_rule = Rule::new(
        "Allowed Chains".to_string(),
        RuleKind::AllowedChains {
            chain_ids: vec![1, 42161], // Ethereum and Arbitrum only
        },
        RuleAction::Deny { reason: "Chain not allowed".to_string() },
        50,
    );
    
    // Low priority: Amount limit
    let amount_rule = Rule::new(
        "Amount Limit".to_string(),
        RuleKind::MaxTransactionValue { max_wei: 1_500_000_000_000_000_000 }, // 1.5 ETH
        RuleAction::Deny { reason: "Amount too high".to_string() },
        100,
    );
    
    engine.add_rule(amount_rule);
    engine.add_rule(chain_rule);
    engine.add_rule(block_rule);
    
    let decision = engine.evaluate(&ctx);
    
    // Should be blocked by the highest priority rule (blocked recipient)
    match decision {
        PolicyDecision::Deny { reason, .. } => {
            assert_eq!(reason, "Recipient blocked");
        }
        _ => panic!("Expected Deny decision for blocked recipient"),
    }
}

#[test]
fn test_disabled_rule_ignored() {
    let mut engine = PolicyEngine::new();
    let ctx = create_test_context();
    
    let mut rule = Rule::new(
        "Disabled Rule".to_string(),
        RuleKind::MaxTransactionValue { max_wei: 0 }, // Would always trigger
        RuleAction::Deny { reason: "Should not trigger".to_string() },
        100,
    );
    
    rule.enabled = false; // Disable the rule
    engine.add_rule(rule);
    
    let decision = engine.evaluate(&ctx);
    assert_eq!(decision, PolicyDecision::Allow);
}

#[test]
fn test_quorum_member_management() {
    let mut quorum = KeyQuorum::new("Test Quorum".to_string(), 2);
    
    let user1 = UserId::new();
    let user2 = UserId::new();
    let user3 = UserId::new();
    
    // Add members
    assert!(quorum.add_member(user1.clone(), QuorumRole::Admin));
    assert!(quorum.add_member(user2.clone(), QuorumRole::Approver));
    assert!(quorum.add_member(user3.clone(), QuorumRole::Viewer));
    
    assert_eq!(quorum.members.len(), 3);
    
    // Try to add duplicate member
    assert!(!quorum.add_member(user1.clone(), QuorumRole::Approver));
    assert_eq!(quorum.members.len(), 3);
    
    // Check approver permissions
    assert!(quorum.can_approve(&user1)); // Admin can approve
    assert!(quorum.can_approve(&user2)); // Approver can approve
    assert!(!quorum.can_approve(&user3)); // Viewer cannot approve
    
    let approvers = quorum.get_approvers();
    assert_eq!(approvers.len(), 2); // Admin and Approver
    
    // Remove member
    assert!(quorum.remove_member(&user2));
    assert_eq!(quorum.members.len(), 2);
    assert!(!quorum.can_approve(&user2)); // No longer can approve
}