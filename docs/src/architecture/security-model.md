# Security Model

Erebor handles private key material. This document describes the threat model, security architecture, and cryptographic choices.

## Threat Model

| Threat | Impact | Mitigation |
|--------|--------|-----------|
| **Server DB breach** | Encrypted key shares exposed | Envelope encryption — shares encrypted with per-user DEK, DEK derived from master key via HKDF |
| **Server compromise (root)** | Active signing capability | Shamir: server share alone can't sign (need 2-of-3). Rate limiting + anomaly detection flags unusual activity. |
| **Device theft** | One key share exposed | Share alone is useless (below threshold). Biometric lock on device share. Remote share invalidation via rotation. |
| **Master key compromise** | Can decrypt all server-side shares | Each share alone is useless. Use KMS (AWS/GCP) to protect master key in production. |
| **Insider attack** | Full system access | Audit log is append-only. Share threshold means no single operator can sign. TEE option removes even operator access. |
| **Social engineering** | Account takeover | Multi-factor required for recovery. Time-lock on recovery. Cannot unlink last auth method. |
| **Replay attack** | Duplicate transactions | Nonces on all OTPs, SIWE messages, and on-chain operations. Single-use refresh tokens. |
| **Token theft** | Session hijack | Refresh token rotation — using a revoked token triggers revocation of ALL sessions for that user. |

## Cryptographic Primitives

| Purpose | Algorithm | Standard |
|---------|-----------|----------|
| Share encryption at rest | **AES-256-GCM** | NIST SP 800-38D |
| Per-user key derivation | **HKDF-SHA256** | RFC 5869 |
| Secret sharing | **Shamir SSS over GF(2^8)** | Shamir 1979 |
| HD wallet derivation | **BIP-32/BIP-44** | Bitcoin standards |
| Ethereum signatures | **ECDSA secp256k1** | SEC 2 |
| Solana signatures | **EdDSA Ed25519** | RFC 8032 |
| JWT signing | **HMAC-SHA256** | RFC 7519 |
| User ID derivation | **SHA-256** | FIPS 180-4 |
| Password hashing | **Argon2id** | RFC 9106 (planned) |

## Key Security Architecture

### Envelope Encryption

```
Environment/KMS
      │
      │  Master Key (32 bytes)
      │
      ▼
   ┌──────┐  HKDF(master_key, user_id)
   │ HKDF │──────────────────────────────► Per-User DEK
   └──────┘
                                                │
                                                ▼
                                          ┌───────────┐
                                          │ AES-256-  │
                                          │ GCM       │
                                          │ encrypt   │
                                          └─────┬─────┘
                                                │
                                    ┌───────────┴───────────┐
                                    │ ciphertext + nonce    │
                                    │ (stored in database)  │
                                    └───────────────────────┘
```

An attacker needs **both** the master key **and** database access to decrypt shares. And even then, each individual share is useless without meeting the Shamir threshold.

### Memory Safety

All secret types use the `zeroize` crate:

```rust
#[derive(Clone, Zeroize)]
#[zeroize(drop)]
pub struct SecretBytes(pub Vec<u8>);

impl std::fmt::Debug for SecretBytes {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "SecretBytes([REDACTED; {} bytes])", self.0.len())
    }
}
```

- **Drop semantics:** Memory is zeroed when `SecretBytes` goes out of scope
- **Debug redaction:** Printing a `SecretBytes` never reveals the contents
- **Rust's ownership model:** Prevents use-after-free and double-free on secret data

### Rate Limiting

Token bucket rate limiter on all endpoints:

- Per-IP tracking (supports `X-Forwarded-For` behind proxies)
- Configurable max tokens and refill rate
- Auth-specific limits: 3 OTP attempts, 5 sends per email per hour
- SIWE nonces are single-use with TTL

### Session Security

1. **Short-lived access tokens** (15 min) — Limits window of exploitation
2. **Refresh token rotation** — Each refresh invalidates the previous token
3. **Theft detection** — Using a revoked refresh token revokes ALL sessions for that user
4. **Session expiry cleanup** — Expired sessions are periodically purged

## GF(2^8) Implementation

The Shamir implementation uses Galois Field arithmetic with the AES irreducible polynomial (x^8 + x^4 + x^3 + x + 1):

```rust
fn gf256_mul(mut a: u8, mut b: u8) -> u8 {
    let mut result: u8 = 0;
    for _ in 0..8 {
        if b & 1 != 0 { result ^= a; }
        let hi = a & 0x80;
        a <<= 1;
        if hi != 0 { a ^= 0x1b; } // AES polynomial
        b >>= 1;
    }
    result
}
```

Field inversion uses Fermat's little theorem: a^(254) = a^(-1) in GF(256).

The implementation is tested with:
- Identity and zero properties
- Inverse verification for all 255 non-zero elements
- BIP-32 test vectors from the specification
- Round-trip split/reconstruct with different share combinations
- Cross-pair consistency (all valid share pairs produce the same secret)

## Production Hardening Checklist

- [ ] Store `VAULT_MASTER_KEY` in a KMS (AWS KMS, GCP KMS, HashiCorp Vault)
- [ ] Enable TLS termination at the reverse proxy
- [ ] Set `RUST_LOG=warn` in production (avoid verbose logging)
- [ ] Run behind a WAF with DDoS protection
- [ ] Enable PostgreSQL SSL mode
- [ ] Restrict database user permissions (no DROP, no schema changes)
- [ ] Enable Redis AUTH and TLS
- [ ] Set up monitoring for anomalous signing patterns
- [ ] Regular key rotation schedule
- [ ] Automated backup of encrypted share storage
