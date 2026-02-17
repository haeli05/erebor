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
| `erebor-aa` | ✅ Implemented | ERC-4337 bundler, paymaster (verifying, sponsored, ERC-20), smart contract wallets, session keys with spending limits |
| `erebor-chain` | ✅ Implemented | Multi-chain RPC pooling with failover, EIP-1559 + legacy gas estimation, chain registry (ETH, Base, Polygon, Arbitrum, Optimism, Solana) |

## Feature Parity with Privy

Honest accounting of where Erebor stands today versus Privy's production offering.

### ✅ At Parity

| Feature | Erebor | Privy | Notes |
|---------|--------|-------|-------|
| Email OTP auth | ✅ | ✅ | Rate-limited, 6-digit, 10min TTL |
| Google OAuth | ✅ | ✅ | Code → token → userinfo flow |
| SIWE (wallet login) | ✅ | ✅ | EIP-4361 with nonce/domain/expiry validation |
| JWT sessions | ✅ | ✅ | Refresh token rotation with theft detection |
| Identity linking | ✅ | ✅ | Multi-provider per user, last-identity guard |
| Key splitting | ✅ Shamir 2-of-3 | MPC | Different approach — Shamir is simpler, auditable |
| HD key derivation | ✅ BIP-32/44 | ✅ | ETH (`m/44'/60'/0'/0/n`) + Solana (`m/44'/501'/0'/0'`) |
| Envelope encryption | ✅ AES-256-GCM | Proprietary | Per-user HKDF-derived keys, zeroize on drop |
| ERC-4337 structures | ✅ | ✅ | UserOperation, bundler, paymaster, session keys |
| Multi-chain config | ✅ | ✅ | EVM (ETH, Base, Polygon, Arbitrum, Optimism) + Solana |
| Gas estimation | ✅ | ✅ | EIP-1559 + legacy oracles with safety margins |
| RPC pool + failover | ✅ | ✅ | Health tracking, caching, automatic failover |
| Self-hosted | ✅ | ❌ | Erebor's entire value proposition |
| Full source audit | ✅ | ❌ | MIT licensed, every line readable |
| Rate limiting | ✅ | ✅ | Token bucket per key |
| Audit trail | ✅ | Partial | Immutable log of every key operation |

### ❌ Not Yet at Parity

| Feature | Priority | Privy Has | Erebor Status | Gap Size |
|---------|----------|-----------|---------------|----------|
| **React SDK (`useErebor()`)** | 🔴 Critical | `@privy-io/react-auth` — hooks, login modals, wallet UI | Doc stubs only | Huge — this IS the product |
| **Embedded wallet iframe** | 🔴 Critical | Cross-origin iframe isolates key ops from app | Server-side vault only | Huge — security model difference |
| **Transaction signing + broadcast** | 🔴 Critical | `eth_sendTransaction`, `signMessage`, `signTypedData`, nonce mgmt | RPC pool exists, no tx pipeline | Large |
| **Smart wallet deployment** | 🟡 High | Deploys real ERC-4337 accounts on-chain | In-memory structs, no on-chain calls | Large |
| **More OAuth providers** | 🟡 High | Apple, Twitter, Discord, GitHub, Farcaster, Telegram, Instagram, Twitch, Spotify, LinkedIn | Google only | Medium |
| **Phone / SMS auth** | 🟡 High | Twilio-backed phone OTP | Not implemented | Medium |
| **Policy engine** | 🟡 High | Rules, condition sets, aggregations, key quorums, spending velocity | Basic session key limits | Medium |
| **Webhook events** | 🟢 Medium | User created, wallet created, tx complete callbacks | Audit log only (no outbound) | Small |
| **Fiat on/off ramp** | 🟢 Medium | KYC, bank accounts, onramp/offramp APIs | Not planned | Medium — niche |
| **React Native SDK** | 🟢 Medium | Full Expo SDK | Not started | Medium |
| **Swift / Kotlin SDKs** | 🟢 Medium | Native iOS + Android | Not started | Medium |
| **Admin dashboard** | 🟢 Medium | Web UI for users, apps, policies | CLI/API only | Small |
| **Passkey auth** | 🟢 Medium | WebAuthn / FIDO2 | Stub only | Small |
| **Pre-generated wallets** | 🟢 Medium | Create wallets before user signs in | Not implemented | Small |
| **Custom auth (OIDC)** | 🟢 Medium | Bring-your-own identity provider | Not implemented | Small |

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

- [x] **Phase 1:** Auth service (OAuth, Email OTP, SIWE) + Shamir vault + gateway
- [x] **Phase 2:** ERC-4337 bundler + paymaster + smart accounts + session keys
- [x] **Phase 3:** Multi-chain RPC pooling + gas estimation + chain registry
- [ ] **Phase 4:** Gateway API routes — full REST API for auth, wallets, signing, transactions
- [ ] **Phase 5:** Transaction signing + broadcast pipeline (nonce mgmt, gas bumping, retry)
- [ ] **Phase 6:** React SDK (`@erebor/react`) — `useErebor()`, login modal, wallet hooks
- [ ] **Phase 7:** Embedded wallet iframe — cross-origin key isolation
- [ ] **Phase 8:** More OAuth providers (Apple, Twitter, Discord, GitHub, Farcaster)
- [ ] **Phase 9:** Policy engine — rules, condition sets, spending velocity, key quorums
- [ ] **Phase 10:** React Native + Swift + Kotlin SDKs
- [ ] **Phase 11:** MPC-TSS (CGGMP21) + social recovery + anomaly detection
- [ ] **Phase 12:** TEE support + HSM + Kubernetes Helm charts

## License

[MIT](LICENSE) — Use it however you want.
