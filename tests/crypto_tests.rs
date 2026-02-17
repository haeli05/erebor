use erebor_common::SecretBytes;
use erebor_vault::shamir::{ShamirVault, Share};
use erebor_vault::EncryptionService;
use rand::RngCore;
use std::collections::HashSet;

/// Helper: all C(n, t) combinations
fn combinations(shares: &[Share], t: usize) -> Vec<Vec<Share>> {
    let n = shares.len();
    let mut result = Vec::new();
    let mut indices = (0..t).collect::<Vec<_>>();
    loop {
        result.push(indices.iter().map(|&i| shares[i].clone()).collect());
        // Next combination
        let mut i = t;
        while i > 0 {
            i -= 1;
            indices[i] += 1;
            if indices[i] <= n - t + i {
                break;
            }
            if i == 0 {
                return result;
            }
        }
        for j in (i + 1)..t {
            indices[j] = indices[j - 1] + 1;
        }
    }
}

#[test]
fn shamir_fuzz_random_secrets() {
    let mut rng = rand::thread_rng();
    let vault = ShamirVault::new(2, 3).unwrap();

    for size in [1, 2, 7, 16, 31, 32, 64, 128, 256, 512, 1024] {
        let mut secret = vec![0u8; size];
        rng.fill_bytes(&mut secret);

        let shares = vault.split(&secret).unwrap();
        let recovered = vault
            .reconstruct(&[shares[0].clone(), shares[1].clone()])
            .unwrap();
        assert_eq!(recovered.0, secret, "Failed for secret size {size}");
    }
}

#[test]
fn shamir_all_combinations_reconstruct_2_of_3() {
    let vault = ShamirVault::new(2, 3).unwrap();
    let secret = b"all-combos-test-secret-key-32byt";
    let shares = vault.split(secret).unwrap();

    let combos = combinations(&shares, 2);
    assert_eq!(combos.len(), 3); // C(3,2) = 3
    for combo in &combos {
        let recovered = vault.reconstruct(combo).unwrap();
        assert_eq!(&recovered.0, secret);
    }
}

#[test]
fn shamir_all_combinations_reconstruct_3_of_5() {
    let vault = ShamirVault::new(3, 5).unwrap();
    let secret = b"three-of-five-secret-material!!!";
    let shares = vault.split(secret).unwrap();

    let combos = combinations(&shares, 3);
    assert_eq!(combos.len(), 10); // C(5,3) = 10
    for combo in &combos {
        let recovered = vault.reconstruct(combo).unwrap();
        assert_eq!(&recovered.0, secret);
    }
}

#[test]
fn shamir_t_minus_1_shares_reveal_nothing() {
    // Statistical test: with t=2, a single share should reveal no information about the secret.
    // For each byte position, across many splits of the same secret, the share byte values
    // should be approximately uniformly distributed over GF(256).
    let vault = ShamirVault::new(2, 3).unwrap();
    let secret = vec![0xAA; 4]; // fixed secret
    let trials = 1000;
    let mut byte_counts = vec![[0u32; 256]; 4]; // per byte position

    for _ in 0..trials {
        let shares = vault.split(&secret).unwrap();
        for (pos, counts) in byte_counts.iter_mut().enumerate() {
            counts[shares[0].data[pos] as usize] += 1;
        }
    }

    // Chi-squared test: expected = trials/256 ≈ 3.9
    // For uniform distribution, chi-squared should be < ~300 (df=255, p=0.05 → ~293)
    for (pos, counts) in byte_counts.iter().enumerate() {
        let expected = trials as f64 / 256.0;
        let chi_sq: f64 = counts
            .iter()
            .map(|&c| {
                let diff = c as f64 - expected;
                diff * diff / expected
            })
            .sum();
        assert!(
            chi_sq < 350.0,
            "Byte position {pos}: chi-squared {chi_sq} too high, share may leak information"
        );
    }
}

#[test]
fn encryption_various_payload_sizes() {
    let svc = EncryptionService::new(SecretBytes(vec![0x42; 32]));
    let context = b"user:test";

    for size in [0, 1, 15, 16, 31, 32, 100, 1024, 4096] {
        let plaintext = vec![0xBB; size];
        let (ct, nonce) = svc.encrypt(&plaintext, context).unwrap();
        let recovered = svc.decrypt(&ct, &nonce, context).unwrap();
        assert_eq!(recovered.0, plaintext, "Failed for payload size {size}");
    }
}

#[test]
fn encryption_tampered_ciphertext_fails() {
    let svc = EncryptionService::new(SecretBytes(vec![0x42; 32]));
    let ctx = b"user:tamper-test";
    let (mut ct, nonce) = svc.encrypt(b"hello world", ctx).unwrap();

    // Tamper each byte position
    for i in 0..ct.len() {
        ct[i] ^= 0xFF;
        assert!(svc.decrypt(&ct, &nonce, ctx).is_err());
        ct[i] ^= 0xFF; // restore
    }
}

#[test]
fn encryption_tampered_nonce_fails() {
    let svc = EncryptionService::new(SecretBytes(vec![0x42; 32]));
    let ctx = b"user:nonce-test";
    let (ct, mut nonce) = svc.encrypt(b"hello world", ctx).unwrap();
    nonce[0] ^= 0xFF;
    assert!(svc.decrypt(&ct, &nonce, ctx).is_err());
}

#[test]
fn encryption_wrong_context_fails() {
    let svc = EncryptionService::new(SecretBytes(vec![0x42; 32]));
    let (ct, nonce) = svc.encrypt(b"secret data", b"user:alice").unwrap();
    assert!(svc.decrypt(&ct, &nonce, b"user:bob").is_err());
    assert!(svc.decrypt(&ct, &nonce, b"user:alice2").is_err());
    assert!(svc.decrypt(&ct, &nonce, b"").is_err());
}

#[test]
fn encryption_unique_nonces() {
    let svc = EncryptionService::new(SecretBytes(vec![0x42; 32]));
    let ctx = b"user:nonce-unique";
    let mut nonces = HashSet::new();
    for _ in 0..1000 {
        let (_, nonce) = svc.encrypt(b"data", ctx).unwrap();
        assert!(nonces.insert(nonce), "Nonce collision detected!");
    }
}
