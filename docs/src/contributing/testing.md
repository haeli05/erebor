# Testing

Erebor has comprehensive tests across all implemented crates. This guide covers the testing approach and how to write good tests.

## Running Tests

```bash
# All tests
cargo test --workspace

# Specific crate
cargo test -p erebor-vault
cargo test -p erebor-auth

# Specific test
cargo test -p erebor-vault test_shamir
cargo test -p erebor-auth test_jwt_roundtrip

# With output (see println! in tests)
cargo test --workspace -- --nocapture

# Integration tests only
cargo test --test '*'
```

## Test Organization

### Unit Tests

Located in `#[cfg(test)]` modules alongside the code they test:

```rust
// In src/shamir.rs
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_split_reconstruct_2_of_3() {
        let vault = ShamirVault::new(2, 3).unwrap();
        let secret = b"this is a 32-byte private key!!";
        let shares = vault.split(secret).unwrap();

        let recovered = vault.reconstruct(&[shares[0].clone(), shares[1].clone()]).unwrap();
        assert_eq!(&recovered.0, secret);
    }
}
```

### Integration Tests

Located in `tests/` directory, testing cross-crate interactions:

```rust
// tests/integration_tests.rs
#[tokio::test]
async fn test_full_auth_flow() {
    // Set up auth service
    // Send OTP → Verify OTP → Get tokens → Access protected route
}
```

## What to Test

### Success Paths

Every public function should have at least one test demonstrating correct usage.

### Error Paths

Test that errors are returned correctly:

```rust
#[test]
fn test_single_share_insufficient() {
    let vault = ShamirVault::new(2, 3).unwrap();
    let shares = vault.split(b"secret").unwrap();
    let result = vault.reconstruct(&[shares[0].clone()]);
    assert!(result.is_err());
}
```

### Edge Cases

```rust
#[test]
fn test_empty_secret() {
    let vault = ShamirVault::new(2, 3).unwrap();
    assert!(vault.split(b"").is_err());
}

#[test]
fn test_invalid_threshold() {
    assert!(ShamirVault::new(1, 3).is_err()); // threshold < 2
    assert!(ShamirVault::new(5, 3).is_err()); // threshold > total
}
```

### Security-Specific Tests

For cryptographic code, test adversarial scenarios:

```rust
#[test]
fn test_tampered_ciphertext_fails() {
    let svc = test_service();
    let (mut ciphertext, nonce) = svc.encrypt(b"secret", b"user:alice").unwrap();
    ciphertext[0] ^= 0xFF; // flip a byte
    assert!(svc.decrypt(&ciphertext, &nonce, b"user:alice").is_err());
}

#[test]
fn test_wrong_context_fails() {
    let svc = test_service();
    let (ciphertext, nonce) = svc.encrypt(b"secret", b"user:alice").unwrap();
    assert!(svc.decrypt(&ciphertext, &nonce, b"user:bob").is_err());
}
```

### Cryptographic Correctness

Test against known vectors:

```rust
#[test]
fn test_bip32_vector1_master() {
    // BIP-32 test vector 1
    let seed = hex::decode("000102030405060708090a0b0c0d0e0f").unwrap();
    let master = master_key_from_seed(&seed).unwrap();
    assert_eq!(
        hex::encode(&master.secret_key),
        "e8f32e723decf4051aefac8e2c93c9c5b214313817cdb01a1494b917c8436b35"
    );
}

#[test]
fn test_ethereum_address_known() {
    let pk = hex::decode("0000000000000000000000000000000000000000000000000000000000000001").unwrap();
    let addr = ethereum_address(&pk).unwrap();
    assert_eq!(addr.to_lowercase(), "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf");
}
```

### Property Tests

For Shamir, verify that any valid combination of threshold shares produces the same secret:

```rust
#[test]
fn test_sign_with_different_share_pairs() {
    let vault = test_vault();
    let user = UserId::new();
    let info = vault.create_wallet(&user).await.unwrap();
    let tx_hash = [0xCD_u8; 32];

    let sig1 = vault.sign_transaction(&user, &[indices[0], indices[1]], &tx_hash).await.unwrap();
    let sig2 = vault.sign_transaction(&user, &[indices[0], indices[2]], &tx_hash).await.unwrap();
    let sig3 = vault.sign_transaction(&user, &[indices[1], indices[2]], &tx_hash).await.unwrap();
    assert_eq!(sig1, sig2);
    assert_eq!(sig2, sig3);
}
```

## Current Test Coverage

| Crate | Tests | Coverage Areas |
|-------|-------|---------------|
| `erebor-common` | Types compilation | Type definitions, error variants |
| `erebor-auth` | ~30 tests | JWT round-trip, providers (OTP, SIWE), sessions, linking, middleware, routes |
| `erebor-vault` | ~30 tests | Shamir (GF256, split/reconstruct), encryption (roundtrip, tampering), BIP-32 vectors, vault lifecycle |
| `erebor-gateway` | — | Health endpoint |

## Writing Good Tests

1. **Test names describe the scenario**: `test_cannot_unlink_last_identity` not `test_unlink_3`
2. **One assertion per concept**: Test one behavior, not five
3. **Use helper functions**: `fn test_vault()`, `fn test_state()` for common setup
4. **Test the public API**: Don't test private implementation details
5. **Async tests use `#[tokio::test]`**: For anything involving the vault or session stores
