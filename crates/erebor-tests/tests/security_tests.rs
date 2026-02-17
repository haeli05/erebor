use erebor_common::{AuthProvider, SecretBytes};
use erebor_vault::shamir::ShamirVault;
use erebor_vault::EncryptionService;
use erebor_auth::{deterministic_user_id, jwt::JwtManager};
use std::collections::HashSet;

#[test]
fn secret_bytes_zeroed_on_drop() {
    let ptr: *const u8;
    let len: usize;
    {
        let secret = SecretBytes(vec![0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE]);
        len = secret.0.len();
        ptr = secret.0.as_ptr();
        // secret drops here
    }
    // After drop, the zeroize crate should have written zeros
    unsafe {
        let slice = std::slice::from_raw_parts(ptr, len);
        let all_original = slice == &[0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE];
        assert!(!all_original, "SecretBytes was NOT zeroed on drop");
    }
}

#[test]
fn single_share_reveals_nothing_about_secret() {
    let vault = ShamirVault::new(2, 3).unwrap();

    let mut share_bytes_for_zero = vec![0u32; 256];
    let mut share_bytes_for_ff = vec![0u32; 256];

    for _ in 0..500 {
        let shares_zero = vault.split(&[0x00]).unwrap();
        let shares_ff = vault.split(&[0xFF]).unwrap();
        share_bytes_for_zero[shares_zero[0].data[0] as usize] += 1;
        share_bytes_for_ff[shares_ff[0].data[0] as usize] += 1;
    }

    // Both distributions should look uniform — max difference should be small
    let n = 500.0;
    let mut max_diff = 0.0f64;
    for i in 0..256 {
        let p1 = share_bytes_for_zero[i] as f64 / n;
        let p2 = share_bytes_for_ff[i] as f64 / n;
        max_diff = max_diff.max((p1 - p2).abs());
    }
    assert!(
        max_diff < 0.1,
        "Share distributions differ too much (max_diff={max_diff}), information may be leaking"
    );
}

#[test]
fn brute_force_wrong_key_never_decrypts() {
    let svc = EncryptionService::new(SecretBytes(vec![0x42; 32]));
    let plaintext = b"sensitive key material";
    let ctx = b"user:brute-force-test";
    let (ct, nonce) = svc.encrypt(plaintext, ctx).unwrap();

    for i in 0u8..100 {
        if i == 0x42 { continue; }
        let wrong_svc = EncryptionService::new(SecretBytes(vec![i; 32]));
        assert!(wrong_svc.decrypt(&ct, &nonce, ctx).is_err(), "Wrong key {i} decrypted!");
    }
}

#[test]
fn brute_force_wrong_context_never_decrypts() {
    let svc = EncryptionService::new(SecretBytes(vec![0x42; 32]));
    let (ct, nonce) = svc.encrypt(b"sensitive data", b"user:correct").unwrap();

    for i in 0..100 {
        let wrong_ctx = format!("user:wrong-{i}");
        assert!(svc.decrypt(&ct, &nonce, wrong_ctx.as_bytes()).is_err());
    }
}

#[test]
fn jwt_tampered_token_rejected() {
    let mgr = JwtManager::new(b"test-secret-key-at-least-32-bytes!");
    let user_id = erebor_common::UserId::new();
    let token = mgr.issue_access_token(&user_id, &["google".into()]).unwrap();

    // Valid token works
    assert!(mgr.verify(&token).is_ok());

    // Tamper the signature (last segment)
    let parts: Vec<&str> = token.split('.').collect();
    assert_eq!(parts.len(), 3);
    let tampered = format!("{}.{}.{}X", parts[0], parts[1], parts[2]);
    assert!(mgr.verify(&tampered).is_err());

    // Tamper the payload
    let tampered2 = format!("{}.{}X.{}", parts[0], parts[1], parts[2]);
    assert!(mgr.verify(&tampered2).is_err());
}

#[test]
fn jwt_wrong_secret_rejected() {
    let mgr1 = JwtManager::new(b"correct-secret-at-least-32-bytes!");
    let mgr2 = JwtManager::new(b"wrong-secret-definitely-32-bytes!");
    let user_id = erebor_common::UserId::new();
    let token = mgr1.issue_access_token(&user_id, &[]).unwrap();
    assert!(mgr2.verify(&token).is_err());
}

#[test]
fn deterministic_user_id_collision_resistance() {
    let mut ids = HashSet::new();
    for i in 0..10_000 {
        let id = deterministic_user_id(&AuthProvider::Google, &format!("user-{i}"));
        assert!(ids.insert(id), "Collision at user-{i}!");
    }
    assert_eq!(ids.len(), 10_000);
}

#[test]
fn deterministic_user_id_cross_provider_uniqueness() {
    let providers = vec![
        AuthProvider::Google,
        AuthProvider::Apple,
        AuthProvider::Twitter,
        AuthProvider::Discord,
        AuthProvider::Github,
        AuthProvider::Email,
        AuthProvider::Phone,
    ];
    let mut ids = HashSet::new();
    for provider in &providers {
        let id = deterministic_user_id(provider, "same-user-id-123");
        assert!(ids.insert(id), "Cross-provider collision for {provider:?}");
    }
}
