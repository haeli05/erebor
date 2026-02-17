<p align="center">
  <h1 align="center">⛰️ Erebor</h1>
  <p align="center"><strong>Self-custodial wallet infrastructure. Open source. Self-hosted.</strong></p>
  <p align="center">An open-source alternative to Privy — auth, embedded wallets, and account abstraction in one stack you own.</p>
</p>

<p align="center">
  <a href="https://github.com/haeli05/erebor/actions"><img src="https://img.shields.io/github/actions/workflow/status/haeli05/erebor/ci.yml?branch=main&style=flat-square" alt="Build Status"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/license-MIT-blue?style=flat-square" alt="MIT License"></a>
  <a href="https://www.rust-lang.org/"><img src="https://img.shields.io/badge/rust-1.75%2B-orange?style=flat-square&logo=rust" alt="Rust"></a>
  <a href="https://github.com/haeli05/erebor/issues"><img src="https://img.shields.io/github/issues/haeli05/erebor?style=flat-square" alt="Issues"></a>
</p>

---

## What is Erebor?

Erebor is a modular, self-hosted wallet infrastructure stack written in Rust. It provides the same capabilities as [Privy](https://privy.io) — social login → embedded wallets → smart accounts — but you run it yourself, audit every line, and pay nothing per MAU.

Privy bundles three commodity pieces (OAuth, key splitting, smart contract wallets) into a SaaS with per-user pricing. Erebor unbundles them into four swappable Rust crates you compose however you want.

### Why Erebor?

| | **Erebor** | **Privy** | **Web3Auth** | **Magic** |
|---|---|---|---|---|
| **Self-hosted** | ✅ Full control | ❌ SaaS only | ⚠️ Partial | ❌ SaaS only |
| **Open source** | ✅ MIT | ❌ Proprietary | ⚠️ Partial | ❌ Proprietary |
| **Key custody** | ✅ Non-custodial (Shamir 2-of-3) | ⚠️ MPC (Privy holds shares) | ⚠️ MPC (nodes distributed) | ❌ Delegated |
| **Pricing** | ✅ Free | 💰 Per MAU | 💰 Per MAU | 💰 Per MAU |
| **Audit** | ✅ Full source | ❌ Trust us | ⚠️ Partial | ❌ Trust us |
| **Auth methods** | OAuth, Email OTP, SIWE, Passkeys | OAuth, Email, Phone, SIWE | OAuth, Email, Phone | Email, Phone, OAuth |
| **Account abstraction** | ✅ ERC-4337 | ✅ ERC-4337 | ⚠️ Limited | ❌ No |
| **Multi-chain** | EVM + Solana | EVM + Solana | EVM + Solana | EVM |
| **Language** | Rust | Node.js | Node.js | Node.js |

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        CLIENT SDKs                          │
│     React  │  React Native  │  Swift  │  Kotlin  │  REST   │
└──────────────────────────┬──────────────────────────────────┘
                           │ HTTPS / WSS
┌──────────────────────────▼──────────────────────────────────┐
│                    API GATEWAY (axum)                        │
│          Rate limiting · JWT validation · Routing            │
└────┬──────────┬──────────┬──────────┬───────────────────────┘
     │          │          │          │
     ▼          ▼          ▼          ▼
┌─────────┐┌─────────┐┌─────────┐┌──────────┐
│  AUTH   ││  KEY    ││  AA     ││  CHAIN   │
│ SERVICE ││ VAULT   ││ SERVICE ││ SERVICE  │
│         ││         ││         ││          │
│ OAuth   ││ Shamir  ││ ERC-4337││ RPC pool │
│ Email   ││ 2-of-3  ││ Bundler ││ Gas est. │
│ SIWE    ││ AES-GCM ││Paymastr ││ Multi-   │
│ Passkey ││ BIP-32  ││Sessions ││ chain    │
└────┬────┘└────┬────┘└────┬────┘└────┬─────┘
     │          │          │          │
     ▼          ▼          ▼          ▼
┌─────────────────────────────────────────────────────────────┐
│                       DATA LAYER                            │
│   PostgreSQL (users, sessions) · Redis (cache, nonces)      │
│   Encrypted KV (key shares — never plaintext)               │
└─────────────────────────────────────────────────────────────┘
```

## Modules

| Crate | Status | Description |
|-------|--------|-------------|
| `erebor-common` | ✅ Implemented | Shared types, errors, `SecretBytes` with zeroize |
| `erebor-auth` | ✅ Implemented | OAuth (Google), Email OTP, SIWE, Passkey stub. JWT sessions, identity linking, rate limiting, auth middleware |
| `erebor-vault` | ✅ Implemented | Shamir 2-of-3 over GF(2^8), AES-256-GCM envelope encryption, BIP-32/44 HD derivation (ETH + Solana), secp256k1/Ed25519 signing, share rotation, recovery export, audit trail |
| `erebor-gateway` | ✅ Implemented | axum API gateway with health check |
| `erebor-aa` | 🚧 Planned | ERC-4337 bundler, paymaster, smart contract wallets, session keys |
| `erebor-chain` | 🚧 Planned | Multi-chain RPC pooling, gas estimation, event indexing |

## Quick Start

### Docker Compose

```bash
git clone https://github.com/haeli05/erebor.git
cd erebor
docker compose up
```

The gateway will be available at `http://localhost:8080`.

### From Source

```bash
# Prerequisites: Rust 1.75+
git clone https://github.com/haeli05/erebor.git
cd erebor

# Build all crates
cargo build --release

# Run tests
cargo test --workspace

# Start the gateway
RUST_LOG=info cargo run -p erebor-gateway
```

### Verify it works

```bash
curl http://localhost:8080/health
# {"status":"ok","version":"0.1.0"}
```

### API Examples

```bash
# Send email OTP
curl -X POST http://localhost:8080/auth/email/send-otp \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com"}'

# Verify OTP and get tokens
curl -X POST http://localhost:8080/auth/email/verify \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "code": "123456"}'

# Response:
# {
#   "access_token": "eyJ...",
#   "refresh_token": "a1b2c3...",
#   "user_id": "550e8400-..."
# }
```

## Configuration

Erebor is configured via environment variables:

```bash
# Gateway
RUST_LOG=info                    # Log level

# Auth
GOOGLE_CLIENT_ID=...             # Google OAuth (optional)
GOOGLE_CLIENT_SECRET=...
GOOGLE_REDIRECT_URI=...
JWT_SECRET=...                   # JWT signing key (min 32 bytes)
SIWE_DOMAIN=yourdomain.com      # Expected SIWE domain

# Vault
KEY_STRATEGY=shamir              # shamir | mpc_tss | tee
VAULT_MASTER_KEY=...             # Master encryption key (32 bytes hex)

# Database
DATABASE_URL=postgres://...
REDIS_URL=redis://...
```

## Security

Erebor handles private key material. Security is non-negotiable:

- **No single compromise yields a key** — Shamir 2-of-3 means server breach alone is useless
- **Key material is zeroed after use** — `zeroize` crate on all secret types
- **Envelope encryption** — Per-user derived keys via HKDF from a master key
- **Immutable audit trail** — Every key operation is logged
- **Rate limiting** — Token bucket per IP on all endpoints
- **Refresh token rotation** — Detect token theft via single-use refresh tokens

See [SECURITY.md](SECURITY.md) for our vulnerability disclosure policy.

## Contributing

We welcome contributions! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
# Fork, branch, code, test, PR
git checkout -b feat/your-feature
cargo test --workspace
cargo fmt --check
cargo clippy -- -D warnings
```

## Documentation

Full documentation is available at the [Erebor docs site](docs/) built with mdBook:

```bash
cd docs && mdbook serve
```

## Roadmap

- [x] **Phase 1:** Auth service + Shamir vault + gateway
- [ ] **Phase 2:** ERC-4337 bundler + paymaster + smart accounts
- [ ] **Phase 3:** MPC-TSS (CGGMP21) + social recovery + anomaly detection
- [ ] **Phase 4:** Multi-chain (Solana) + React/React Native SDKs
- [ ] **Phase 5:** TEE support + HSM + Kubernetes Helm charts

## License

[MIT](LICENSE) — Use it however you want.
