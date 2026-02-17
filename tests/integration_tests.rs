use erebor_common::{AuthProvider, SecretBytes, UserId};
use erebor_vault::shamir::ShamirVault;
use erebor_vault::EncryptionService;
use erebor_auth::{deterministic_user_id, jwt::JwtManager};
use rand::RngCore;

/// Full wallet creation flow:
/// generate key -> split -> encrypt shares -> reconstruct -> verify
#[test]
fn full_wallet_creation_flow() {
    // 1. Generate a random 32-byte private key
    let mut private_key = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut private_key);

    // 2. Split into 2-of-3 shares
    let vault = ShamirVault::new(2, 3).unwrap();
    let shares = vault.split(&private_key).unwrap();
    assert_eq!(shares.len(), 3);

    // 3. Encrypt each share with per-user context
    let master_key = SecretBytes(vec![0x42; 32]);
    let enc = EncryptionService::new(master_key);
    let user_ctx = b"user:wallet-creation-test";

    let encrypted_shares: Vec<(Vec<u8>, Vec<u8>)> = shares
        .iter()
        .map(|s| enc.encrypt(&s.data, user_ctx).unwrap())
        .collect();

    // 4. Decrypt shares back
    let decrypted_shares: Vec<erebor_vault::shamir::Share> = encrypted_shares
        .iter()
        .enumerate()
        .map(|(i, (ct, nonce))| {
            let data = enc.decrypt(ct, nonce, user_ctx).unwrap();
            erebor_vault::shamir::Share {
                index: shares[i].index,
                data: data.0,
            }
        })
        .collect();

    // 5. Reconstruct from any 2 shares
    let recovered = vault
        .reconstruct(&[decrypted_shares[0].clone(), decrypted_shares[2].clone()])
        .unwrap();

    assert_eq!(recovered.0, private_key, "Reconstructed key must match original");
}

/// Auth flow: deterministic user ID -> JWT issue -> verify -> refresh
#[test]
fn auth_flow_end_to_end() {
    // 1. Create deterministic user ID
    let user_id = deterministic_user_id(&AuthProvider::Google, "oauth-user-42");

    // Verify determinism
    let user_id2 = deterministic_user_id(&AuthProvider::Google, "oauth-user-42");
    assert_eq!(user_id, user_id2);

    // 2. Issue access token
    let jwt_mgr = JwtManager::new(b"production-secret-at-least-32-bytes!");
    let access_token = jwt_mgr
        .issue_access_token(&user_id, &["google".into()])
        .unwrap();

    // 3. Verify access token
    let claims = jwt_mgr.verify(&access_token).unwrap();
    assert_eq!(claims.claims.sub, user_id.0.to_string());
    assert_eq!(claims.claims.providers, vec!["google"]);

    // 4. Issue and verify refresh token
    let refresh_token = jwt_mgr.issue_refresh_token(&user_id).unwrap();
    let refresh_claims = jwt_mgr.verify(&refresh_token).unwrap();
    assert_eq!(refresh_claims.claims.sub, user_id.0.to_string());

    // 5. Simulate token refresh: issue new access token from refresh token's user
    let refreshed_user_id = UserId(uuid::Uuid::parse_str(&refresh_claims.claims.sub).unwrap());
    let new_access = jwt_mgr
        .issue_access_token(&refreshed_user_id, &["google".into()])
        .unwrap();
    let new_claims = jwt_mgr.verify(&new_access).unwrap();
    assert_eq!(new_claims.claims.sub, user_id.0.to_string());
}

/// Key rotation: create wallet -> re-split -> old shares invalid, new shares work
#[test]
fn key_rotation_flow() {
    let mut private_key = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut private_key);

    let vault = ShamirVault::new(2, 3).unwrap();

    // Original split
    let old_shares = vault.split(&private_key).unwrap();
    let old_recovered = vault
        .reconstruct(&[old_shares[0].clone(), old_shares[1].clone()])
        .unwrap();
    assert_eq!(old_recovered.0, private_key);

    // Rotate: re-split the same secret with new random coefficients
    let new_shares = vault.split(&private_key).unwrap();

    // New shares reconstruct correctly
    let new_recovered = vault
        .reconstruct(&[new_shares[0].clone(), new_shares[1].clone()])
        .unwrap();
    assert_eq!(new_recovered.0, private_key);

    // Mixing old and new shares should NOT reconstruct correctly
    // (different polynomials, share indices may overlap but data differs)
    let mixed_recovered = vault
        .reconstruct(&[old_shares[0].clone(), new_shares[1].clone()])
        .unwrap(); // reconstruction succeeds but produces wrong result
    assert_ne!(
        mixed_recovered.0, private_key,
        "Mixed old/new shares should NOT produce correct key"
    );
}

/// Multi-user isolation: two users' encrypted shares cannot cross-decrypt
#[test]
fn multi_user_isolation() {
    let master_key = SecretBytes(vec![0x42; 32]);
    let enc = EncryptionService::new(master_key);
    let vault = ShamirVault::new(2, 3).unwrap();

    // User A
    let mut key_a = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut key_a);
    let shares_a = vault.split(&key_a).unwrap();
    let ctx_a = b"user:alice-uuid-1234";
    let (ct_a, nonce_a) = enc.encrypt(&shares_a[0].data, ctx_a).unwrap();

    // User B
    let mut key_b = vec![0u8; 32];
    rand::thread_rng().fill_bytes(&mut key_b);
    let shares_b = vault.split(&key_b).unwrap();
    let ctx_b = b"user:bob-uuid-5678";
    let (ct_b, nonce_b) = enc.encrypt(&shares_b[0].data, ctx_b).unwrap();

    // Each user can decrypt their own
    assert!(enc.decrypt(&ct_a, &nonce_a, ctx_a).is_ok());
    assert!(enc.decrypt(&ct_b, &nonce_b, ctx_b).is_ok());

    // Cross-decryption fails
    assert!(enc.decrypt(&ct_a, &nonce_a, ctx_b).is_err(), "Alice's share decrypted with Bob's context!");
    assert!(enc.decrypt(&ct_b, &nonce_b, ctx_a).is_err(), "Bob's share decrypted with Alice's context!");

    // Swapping ciphertexts also fails
    assert!(enc.decrypt(&ct_a, &nonce_b, ctx_a).is_err());
    assert!(enc.decrypt(&ct_b, &nonce_a, ctx_b).is_err());
}

/// Multiple wallets per user should be independently reconstructable
#[test]
fn multiple_wallets_per_user() {
    let vault = ShamirVault::new(2, 3).unwrap();
    let enc = EncryptionService::new(SecretBytes(vec![0x42; 32]));
    let ctx = b"user:multi-wallet-user";

    let mut keys = Vec::new();
    let mut all_encrypted = Vec::new();
    let mut all_shares = Vec::new();

    for _ in 0..3 {
        let mut key = vec![0u8; 32];
        rand::thread_rng().fill_bytes(&mut key);
        let shares = vault.split(&key).unwrap();
        let encrypted: Vec<_> = shares
            .iter()
            .map(|s| enc.encrypt(&s.data, ctx).unwrap())
            .collect();
        keys.push(key);
        all_shares.push(shares);
        all_encrypted.push(encrypted);
    }

    // Reconstruct each wallet independently
    for (i, encrypted) in all_encrypted.iter().enumerate() {
        let dec_shares: Vec<_> = encrypted
            .iter()
            .enumerate()
            .map(|(j, (ct, nonce))| erebor_vault::shamir::Share {
                index: all_shares[i][j].index,
                data: enc.decrypt(ct, nonce, ctx).unwrap().0,
            })
            .collect();
        let recovered = vault
            .reconstruct(&[dec_shares[0].clone(), dec_shares[1].clone()])
            .unwrap();
        assert_eq!(recovered.0, keys[i]);
    }
}
