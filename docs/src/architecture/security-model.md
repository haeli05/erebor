# Security Model

Security is non-negotiable in wallet infrastructure. This document describes Erebor's threat model, cryptographic choices, and security invariants.

## Threat Model

| Threat | Impact | Mitigation |
|--------|--------|-----------|
| **Server DB breach** | Encrypted shares exposed | Envelope encryption — shares encrypted with per-user DEK, DEK derived via HKDF from master key |
| **Server compromise (root)** | Active signing abuse | Server alone holds 1 of 3 shares — cannot reconstruct. Rate limiting + anomaly detection. |
| **Device theft** | One key share exposed | Share alone is useless without server share. Biometric lock on device share. |
| **Insider attack** | Full system access | Operator holds infra, not keys. Audit log is immutable. MPC-TSS mode: operator holds 1 of N shares. |
| **Social engineering** | Account takeover | Multi-factor auth for recovery. Time-lock delays. Guardian-based recovery requires M-of-N. |
| **Supply chain attack** | Malicious dependency | Minimal dependencies. `cargo audit`. Reproducible builds. |
| **Replay attack** | Duplicate transactions | Nonces on all operations. Session-scoped tokens. |
| **Token theft** | Session hijack | Refresh token rotation. Revoked token triggers all-session revocation. |

## Cryptographic Choices

| Purpose | Algorithm | Standard |
|---------|-----------|----------|
| Signing (EVM) | ECDSA on secp256k1 | SEC 2 |
| Signing (Solana) | EdDSA on Ed25519 | RFC 8032 |
| Share encryption | AES-256-GCM | NIST SP 800-38D |
| Key derivation | HKDF-SHA256 | RFC 5869 |
| HD wallets | BIP-32 / BIP-44 | Bitcoin standards |
| Secret sharing | Shamir SSS over GF(2⁸) | Shamir 1979 |
| Hashing | SHA-256, Keccak-256 | FIPS 180-4 / Ethereum |
| JWT signing | HMAC-SHA256 | RFC 7519 |

## Key Material Lifecycle

```
  Generate          Split            Encrypt           Store
 ┌────────┐     ┌──────────┐     ┌───────────┐     ┌────────┐
 │ Random │────►│  Shamir  │────►│ AES-256   │────►│ DB     │
 │ Seed   │     │  2-of-3  │     │ GCM       │     │(encr.) │
 └────────┘     └──────────┘     └───────────┘     └────────┘
     │                                                  │
     ▼ (zeroize)                                        │
                                                        │
  Sign              Reconstruct       Decrypt           │
 ┌────────┐     ┌──────────┐     ┌───────────┐     ┌───┘
 │ ECDSA  │◄────│  Lagrange│◄────│ AES-256   │◄────┤
 │ sign   │     │  interp. │     │ GCM       │     │
 └────────┘     └──────────┘     └───────────┘     │
     │                │                             │
     ▼ (zeroize)      ▼ (zeroize)                   │
```

At every stage, secret material is zeroed after use via the `zeroize` crate:

```rust
#[derive(Zeroize)]
#[zeroize(drop)]
pub struct SecretBytes(pub Vec<u8>);

// When SecretBytes is dropped, memory is overwritten with zeros
// Debug output: "SecretBytes([REDACTED; 32 bytes])"
```

## Defence in Depth

### Layer 1: Authentication
- JWT with short-lived access tokens (15 min)
- Refresh token rotation (detect theft)
- Rate limiting per IP (token bucket)
- OTP: 6 digits, 3 max attempts, 10-min expiry
- SIWE: domain validation, nonce management, expiration

### Layer 2: Key Splitting
- Shamir 2-of-3 — no single party holds the full key
- Server holds 1 share (encrypted), device holds 1, recovery backup holds 1
- Share rotation without changing the underlying key

### Layer 3: Encryption at Rest
- Envelope encryption with HKDF-derived per-user keys
- AES-256-GCM (authenticated encryption — detects tampering)
- Random nonce per encryption operation

### Layer 4: Memory Safety
- Rust — no buffer overflows, use-after-free, or data races
- `zeroize` on all secret types — memory scrubbed on drop
- `SecretBytes` redacts debug output

### Layer 5: Audit Trail
- Every key operation logged with timestamp, user ID, operation type
- Append-only log — entries are never modified or deleted
- Operations: CreateWallet, SignTransaction, RotateShares, ExportRecoveryShare

## Recovery Flows

### Lost Device

```
1. User authenticates via remaining method (email, Google)
2. Server releases server share (1 of 3)
3. Recovery share retrieved (backup password)
4. Seed reconstructed → new device share generated
5. Old device share invalidated via rotation
```

### Lost Server (Self-Hosted Server Destroyed)

```
1. Device share + recovery share = 2 of 3 → reconstruct seed
2. Export raw private key or re-derive addresses
3. Re-deploy server, re-split key with new shares
```

### Planned: Social Recovery

```
1. User designates 5 guardians
2. 3-of-5 guardians must approve recovery
3. 48-hour time lock after approval (anti-social-engineering)
4. Guardian approval via signed message or email confirmation
```

## Future: Key Management Strategies

Erebor is designed to support three strategies (operator chooses):

| Strategy | Key Exists in Full? | Signing Latency | Complexity |
|----------|-------------------|-----------------|------------|
| **Shamir SSS** (current) | Briefly, in memory | Low | Low |
| **MPC-TSS** (planned) | Never | Higher (network rounds) | High |
| **TEE** (planned) | Inside enclave only | Lowest | Medium |

### MPC-TSS (CGGMP21)

The key **never exists in full anywhere**. Each party holds a share and participates in a distributed signing protocol:

```
Device ◄────► Server ◄────► Recovery
   │              │
   └──── MPC ─────┘
        Protocol
           │
      Signature
   (key never assembled)
```

### TEE (Trusted Execution Environment)

Key operations run inside a hardware enclave (AWS Nitro, Intel SGX):
- Key generated and stored inside TEE
- Even the server operator with root access cannot extract keys
- TEE attestation proves code integrity
