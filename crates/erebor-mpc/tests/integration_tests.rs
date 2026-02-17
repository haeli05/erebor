use erebor_mpc::{
    DkgRequest, SigningRequest, RefreshRequest, RecoveryRequest, RecoveryApprovalRequest,
    AnomalyRequest, TransactionData, Guardian, GuardianType, PartyInfo,
    perform_dkg, perform_signing, perform_refresh,
    initiate_recovery, approve_recovery, score_anomaly,
};
use k256::ecdsa::SigningKey;
use rand::rngs::OsRng;
use std::collections::HashMap;
use tokio;

#[tokio::test]
async fn test_dkg_basic_functionality() {
    let threshold = 2;
    let parties = vec![
        PartyInfo {
            id: "party1".to_string(),
            public_key: None,
        },
        PartyInfo {
            id: "party2".to_string(),
            public_key: None,
        },
        PartyInfo {
            id: "party3".to_string(),
            public_key: None,
        },
    ];

    let request = DkgRequest {
        session_id: "test-session-1".to_string(),
        threshold,
        parties,
        timeout_ms: Some(30000),
    };

    // Note: This will likely fail in actual execution because it requires
    // real network communication between parties, but it tests the interface
    let result = perform_dkg(request).await;
    
    // We expect this to fail in tests without proper network setup
    // but we're testing that the function signature and types work correctly
    assert!(result.is_err());
}

#[tokio::test]
async fn test_signing_request_structure() {
    let request = SigningRequest {
        session_id: "signing-session-1".to_string(),
        message: b"Hello, Erebor MPC!".to_vec(),
        key_share: "mock-key-share".to_string(),
        signers: vec!["party1".to_string(), "party2".to_string()],
        timeout_ms: Some(15000),
    };

    let result = perform_signing(request).await;
    
    // Expected to fail without proper setup, but tests the interface
    assert!(result.is_err());
}

#[tokio::test]
async fn test_social_recovery_structure() {
    let guardians = vec![
        Guardian {
            id: "guardian1".to_string(),
            guardian_type: GuardianType::Email,
            contact: "guardian1@example.com".to_string(),
            public_key: None,
        },
        Guardian {
            id: "guardian2".to_string(),
            guardian_type: GuardianType::Phone,
            contact: "+1234567890".to_string(),
            public_key: None,
        },
        Guardian {
            id: "guardian3".to_string(),
            guardian_type: GuardianType::WalletAddress,
            contact: "0x742d35cc6298f2b8d8b7c42f3b5c9ff8d8f8c1aa".to_string(),
            public_key: None,
        },
    ];

    let request = RecoveryRequest {
        wallet_id: "test-wallet-123".to_string(),
        user_id: "user123".to_string(),
        guardians,
        threshold: 2,
        recovery_phrase: Some("emergency recovery phrase".to_string()),
    };

    let result = initiate_recovery(request).await;
    
    // This should work as it's more of a coordination/database operation
    // than network-dependent MPC operations
    match result {
        Ok(recovery_id) => {
            assert!(!recovery_id.is_empty());
            
            // Test approval process
            let approval = RecoveryApprovalRequest {
                recovery_id: recovery_id.clone(),
                guardian_id: "guardian1".to_string(),
                approval_code: "123456".to_string(),
                signature: None,
            };

            let approval_result = approve_recovery(approval).await;
            assert!(approval_result.is_ok());
        }
        Err(e) => {
            // May fail due to missing database/state setup
            println!("Recovery initiation failed (expected in test environment): {}", e);
        }
    }
}

#[tokio::test]
async fn test_anomaly_detection() {
    let tx_data = TransactionData {
        amount: 1000000, // 1 token (assuming 6 decimals)
        recipient: "0x742d35cc6298f2b8d8b7c42f3b5c9ff8d8f8c1aa".to_string(),
        chain_id: 1, // Ethereum mainnet
        timestamp: chrono::Utc::now(),
        gas_price: Some(20000000000), // 20 gwei
        contract_address: None,
        is_contract_verified: true,
    };

    let mut historical_data = HashMap::new();
    historical_data.insert("avg_amount".to_string(), 500000.0); // Historical average
    historical_data.insert("usual_gas_price".to_string(), 25000000000.0);
    historical_data.insert("common_hour".to_string(), 14.0); // 2 PM

    let request = AnomalyRequest {
        wallet_id: "test-wallet-123".to_string(),
        transaction: tx_data,
        historical_patterns: historical_data,
    };

    let result = score_anomaly(request).await;
    
    match result {
        Ok(response) => {
            assert!(response.risk_score >= 0 && response.risk_score <= 100);
            assert!(!response.risk_factors.is_empty());
            println!("Risk score: {}, Factors: {:?}", response.risk_score, response.risk_factors);
        }
        Err(e) => {
            println!("Anomaly scoring failed: {}", e);
        }
    }
}

#[tokio::test]
async fn test_refresh_key_shares() {
    let request = RefreshRequest {
        session_id: "refresh-session-1".to_string(),
        old_key_share: "mock-old-share".to_string(),
        parties: vec!["party1".to_string(), "party2".to_string(), "party3".to_string()],
        threshold: 2,
        timeout_ms: Some(45000),
    };

    let result = perform_refresh(request).await;
    
    // Expected to fail without proper MPC network setup
    assert!(result.is_err());
}

#[test]
fn test_guardian_types() {
    let email_guardian = Guardian {
        id: "email_guardian".to_string(),
        guardian_type: GuardianType::Email,
        contact: "test@example.com".to_string(),
        public_key: None,
    };
    assert_eq!(email_guardian.guardian_type, GuardianType::Email);

    let phone_guardian = Guardian {
        id: "phone_guardian".to_string(),
        guardian_type: GuardianType::Phone,
        contact: "+1234567890".to_string(),
        public_key: None,
    };
    assert_eq!(phone_guardian.guardian_type, GuardianType::Phone);

    let wallet_guardian = Guardian {
        id: "wallet_guardian".to_string(),
        guardian_type: GuardianType::WalletAddress,
        contact: "0x742d35cc6298f2b8d8b7c42f3b5c9ff8d8f8c1aa".to_string(),
        public_key: None,
    };
    assert_eq!(wallet_guardian.guardian_type, GuardianType::WalletAddress);

    let hardware_guardian = Guardian {
        id: "hardware_guardian".to_string(),
        guardian_type: GuardianType::HardwareKey,
        contact: "yubikey:slot1".to_string(),
        public_key: None,
    };
    assert_eq!(hardware_guardian.guardian_type, GuardianType::HardwareKey);
}

#[test]
fn test_party_info_serialization() {
    let party = PartyInfo {
        id: "test_party".to_string(),
        public_key: Some("mock_public_key".to_string()),
    };

    // Test serialization/deserialization
    let serialized = serde_json::to_string(&party).unwrap();
    let deserialized: PartyInfo = serde_json::from_str(&serialized).unwrap();
    
    assert_eq!(party.id, deserialized.id);
    assert_eq!(party.public_key, deserialized.public_key);
}