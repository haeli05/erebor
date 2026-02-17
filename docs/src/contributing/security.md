# Security Contributing Guide

Erebor handles private key material. Security contributions are especially valuable and must follow strict guidelines.

## Reporting Vulnerabilities

**Do not open public GitHub issues for security vulnerabilities.**

Email: **security@erebor.dev**

See [SECURITY.md](https://github.com/haeli05/erebor/blob/main/SECURITY.md) for the full disclosure policy.

## Security Requirements for Code

### All Secret Types Must Use `zeroize`

```rust
use zeroize::Zeroize;

#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct MySecretType(Vec<u8>);
```

The `#[zeroize(drop)]` attribute ensures memory is zeroed when the value is dropped.

### No Logging of Key Material

```rust
// ❌ NEVER do this
tracing::debug!("Key: {:?}", secret_key);

// ✅ Do this instead
tracing::debug!("Key operation completed for user {}", user_id);
```

The `SecretBytes` type has a custom `Debug` implementation that prints `[REDACTED]`.

### Input Validation at API Boundaries

```rust
// ✅ Validate before processing
if email.is_empty() || !email.contains('@') {
    return Err(EreborError::AuthError("Invalid email".into()));
}
```

### Rate Limiting on Sensitive Endpoints

All authentication and signing endpoints must be rate-limited. Add rate limit checks when implementing new endpoints.

### Constant-Time Comparisons

For security-sensitive comparisons (tokens, signatures), prefer constant-time operations:

```rust
use subtle::ConstantTimeEq;

fn verify_hmac(expected: &[u8], actual: &[u8]) -> bool {
    expected.ct_eq(actual).into()
}
```

## Security Review Checklist

Before submitting security-sensitive PRs, verify:

- [ ] All new secret types implement `Zeroize` with drop
- [ ] No key material appears in logs (search for `debug!`, `info!`, `println!`)
- [ ] New endpoints have rate limiting
- [ ] Error messages don't leak sensitive information
- [ ] Nonces are single-use with TTL
- [ ] Token/session validation rejects expired/revoked credentials
- [ ] Tests include adversarial cases (tampered data, wrong keys, expired tokens)
- [ ] No `unsafe` code without a `// SAFETY:` comment
- [ ] Dependencies audited: `cargo audit`

## Cryptographic Changes

Changes to cryptographic code require extra scrutiny:

1. **Reference a standard** — Link to the RFC, NIST publication, or academic paper
2. **Test against known vectors** — Use official test vectors from the specification
3. **Property tests** — Verify mathematical properties (e.g., all valid share combinations reconstruct correctly)
4. **Peer review** — Crypto changes need at least two reviewers

## Running Security Checks

```bash
# Audit dependencies for known vulnerabilities
cargo install cargo-audit
cargo audit

# Check for unsafe code
cargo clippy -- -D warnings -W clippy::pedantic

# Run all tests including security-specific ones
cargo test --workspace

# Check for secret leaks in git history
# (use tools like gitleaks or trufflehog)
```

## Dependency Policy

- Minimize the dependency tree for security-critical crates
- Prefer well-audited, widely-used crates (e.g., `aes-gcm`, `k256`, `ed25519-dalek`)
- Pin dependency versions in `Cargo.lock`
- Run `cargo audit` in CI
- New dependencies in `erebor-vault` require justification
