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
| **Auth methods** | OAuth (Google, Apple, Twitter, Discord, GitHub), Email, Phone, SIWE, Farcaster, Telegram | OAuth, Email, Phone, SIWE | OAuth, Email, Phone | Email, Phone, OAuth |
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
| `erebor-auth` | ✅ Implemented | OAuth (Google, Apple, Twitter, Discord, GitHub), Email OTP, Phone OTP, SIWE, Farcaster SIWF, Telegram, Passkey stub. JWT sessions, identity linking, rate limiting, auth middleware |
| `erebor-vault` | ✅ Implemented | Shamir 2-of-3 over GF(2^8), AES-256-GCM envelope encryption, BIP-32/44 HD derivation (ETH + Solana), secp256k1/Ed25519 signing, share rotation, recovery export, audit trail |
| `erebor-gateway` | ✅ Implemented | axum API gateway with 18+ REST endpoints, auth middleware, CORS, rate limiting |
| `erebor-aa` | ✅ Implemented | ERC-4337 bundler, paymaster (verifying, sponsored, ERC-20), smart contract wallets, session keys with spending limits |
| `erebor-chain` | ✅ Implemented | Multi-chain RPC pooling with failover, EIP-1559 + legacy gas estimation, tx signing + broadcast pipeline, nonce management, chain registry (ETH, Base, Polygon, Arbitrum, Optimism, Solana) |
| `erebor-policy` | ✅ Implemented | Policy engine with 11 rule types, condition sets (AND/OR), aggregation tracking, multi-party key quorums, approval workflows |
| `@erebor/react` | ✅ Implemented | React SDK — `useErebor()`, `useWallets()`, `useSendTransaction()`, LoginModal, WalletButton, iframe bridge, `usePrivy()` compatibility shim |

## Feature Parity with Privy

Honest accounting of where Erebor stands today versus Privy's production offering.

### ✅ At Parity

| Feature | Erebor | Privy | Notes |
|---------|--------|-------|-------|
| Email OTP auth | ✅ | ✅ | Rate-limited, 6-digit, 10min TTL |
| Google OAuth | ✅ | ✅ | Code → token → userinfo flow |
| Apple OAuth | ✅ | ✅ | ES256 JWT client secret, ID token validation |
| Twitter OAuth | ✅ | ✅ | OAuth 2.0 with PKCE |
| Discord OAuth | ✅ | ✅ | Standard OAuth 2.0 |
| GitHub OAuth | ✅ | ✅ | OAuth 2.0 with email scope |
| Farcaster (SIWF) | ✅ | ✅ | Sign In With Farcaster, custody address verification |
| Telegram auth | ✅ | ✅ | Login Widget HMAC-SHA256 verification |
| Phone / SMS OTP | ✅ | ✅ | E.164 validation, rate limiting, Twilio-ready |
| SIWE (wallet login) | ✅ | ✅ | EIP-4361 with nonce/domain/expiry validation |
| JWT sessions | ✅ | ✅ | Refresh token rotation with theft detection |
| Identity linking | ✅ | ✅ | Multi-provider per user, last-identity guard |
| Key splitting | ✅ Shamir 2-of-3 | MPC | Different approach — Shamir is simpler, auditable |
| HD key derivation | ✅ BIP-32/44 | ✅ | ETH (`m/44'/60'/0'/0/n`) + Solana (`m/44'/501'/0'/0'`) |
| Envelope encryption | ✅ AES-256-GCM | Proprietary | Per-user HKDF-derived keys, zeroize on drop |
| ERC-4337 bundler | ✅ | ✅ | UserOperation, mempool, bundle submission |
| Paymaster | ✅ | ✅ | Verifying, sponsored, and ERC-20 paymasters |
| Session keys | ✅ | ✅ | Spending limits, time bounds, permissions |
| Multi-chain config | ✅ | ✅ | EVM (ETH, Base, Polygon, Arbitrum, Optimism) + Solana |
| Gas estimation | ✅ | ✅ | EIP-1559 + legacy oracles with safety margins |
| RPC pool + failover | ✅ | ✅ | Health tracking, caching, automatic failover |
| Tx signing + broadcast | ✅ | ✅ | RLP encoding, EIP-155, nonce management, receipt polling |
| React SDK | ✅ | ✅ | `useErebor()`, `useWallets()`, LoginModal, `usePrivy()` compat shim |
| Embedded wallet iframe | ✅ | ✅ | Cross-origin iframe bridge with postMessage protocol |
| Policy engine | ✅ | ✅ | 11 rule types, condition sets, aggregations, key quorums |
| Rate limiting | ✅ | ✅ | Token bucket per key |
| Audit trail | ✅ | Partial | Immutable log of every key operation |
| Self-hosted | ✅ | ❌ | Erebor's entire value proposition |
| Full source audit | ✅ | ❌ | MIT licensed, every line readable |
| No per-MAU pricing | ✅ | ❌ | Free forever |

### 🔜 Planned (Beyond Privy Parity)

| Feature | Status | Notes |
|---------|--------|-------|
| Webhook events | 🟢 Planned | User/wallet/tx lifecycle callbacks |
| React Native SDK | 🟢 Planned | Expo-based mobile SDK |
| Swift / Kotlin SDKs | 🟢 Planned | Native iOS + Android |
| Admin dashboard | 🟢 Planned | Web UI for managing users, policies, apps |
| Fiat on/off ramp | 🟢 Planned | KYC + bank account integration |
| MPC-TSS (CGGMP21) | 🟢 Planned | Threshold signing without key reconstruction |
| TEE / HSM support | 🟢 Planned | Intel SGX, AWS Nitro enclaves |
| Passkey (WebAuthn) | 🟢 Planned | FIDO2 full implementation (stub exists) |
| Custom OIDC auth | 🟢 Planned | Bring-your-own identity provider |

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

## API Reference

Complete REST API reference for all endpoints:

### Public Endpoints (No Auth Required)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/` | API info and version |
| `GET` | `/health` | Health check |
| `POST` | `/auth/google` | Google OAuth login |
| `POST` | `/auth/email/send-otp` | Send email OTP |
| `POST` | `/auth/email/verify` | Verify email OTP and get tokens |
| `POST` | `/auth/siwe/nonce` | Get SIWE nonce |
| `POST` | `/auth/siwe/verify` | Verify SIWE signature and get tokens |
| `POST` | `/auth/refresh` | Refresh access token |

### Protected Endpoints (JWT Required)

| Method | Path | Description |
|--------|------|-------------|
| `GET` | `/auth/me` | Get current user info and linked identities |
| `POST` | `/auth/logout` | Revoke current session |
| `POST` | `/auth/link` | Link additional auth provider to account |
| `DELETE` | `/auth/link/:provider` | Unlink auth provider from account |
| `POST` | `/wallets` | Create new embedded wallet |
| `GET` | `/wallets` | List user's wallets |
| `GET` | `/wallets/:id` | Get wallet details |
| `POST` | `/wallets/:id/sign-message` | Sign arbitrary message |
| `POST` | `/wallets/:id/sign-transaction` | Sign transaction (returns signature) |
| `POST` | `/wallets/:id/send-transaction` | Sign and broadcast transaction |

## Project Structure

```
erebor/
├── crates/                      # Rust workspace crates
│   ├── erebor-common/          # Shared types, errors, utilities
│   │   ├── src/
│   │   │   ├── types.rs        # Core types (UserId, SecretBytes)
│   │   │   ├── error.rs        # Common error types
│   │   │   └── lib.rs          # Public API
│   │   └── Cargo.toml
│   │
│   ├── erebor-auth/            # Authentication & session management
│   │   ├── src/
│   │   │   ├── providers.rs    # OAuth, Email OTP, SIWE, Passkey
│   │   │   ├── jwt.rs          # JWT token handling
│   │   │   ├── session.rs      # Session management with rotation
│   │   │   ├── linking.rs      # Multi-provider identity linking
│   │   │   ├── middleware.rs   # Auth & rate limiting middleware
│   │   │   └── lib.rs          # Public API
│   │   └── Cargo.toml
│   │
│   ├── erebor-vault/           # Key vault with Shamir secret sharing
│   │   ├── src/
│   │   │   ├── shamir.rs       # Shamir 2-of-3 implementation
│   │   │   ├── encryption.rs   # AES-256-GCM envelope encryption
│   │   │   ├── key_derivation.rs # BIP-32/44 HD key derivation
│   │   │   ├── storage.rs      # Key storage interface & in-memory impl
│   │   │   └── lib.rs          # VaultService API
│   │   └── Cargo.toml
│   │
│   ├── erebor-chain/           # Multi-chain RPC & transaction handling
│   │   ├── src/
│   │   │   ├── lib.rs          # ChainService API
│   │   │   ├── gas.rs          # EIP-1559 & legacy gas estimation
│   │   │   ├── tx.rs           # Transaction building & signing
│   │   │   ├── signer.rs       # Multi-curve signing (secp256k1, Ed25519)
│   │   │   └── broadcast.rs    # RPC pooling & failover
│   │   └── Cargo.toml
│   │
│   ├── erebor-aa/              # ERC-4337 Account Abstraction
│   │   ├── src/
│   │   │   ├── lib.rs          # Account abstraction API
│   │   │   ├── bundler.rs      # ERC-4337 bundler
│   │   │   ├── paymaster.rs    # Paymaster types (verifying, sponsored, ERC-20)
│   │   │   ├── smart_wallet.rs # Smart contract wallet management
│   │   │   └── session.rs      # Session keys with spending limits
│   │   └── Cargo.toml
│   │
│   ├── erebor-gateway/         # HTTP API gateway
│   │   ├── src/
│   │   │   ├── main.rs         # Server startup & middleware
│   │   │   ├── state.rs        # Application state management
│   │   │   ├── error.rs        # API error handling
│   │   │   ├── auth.rs         # JWT middleware
│   │   │   └── routes/
│   │   │       ├── mod.rs      # Route module exports
│   │   │       ├── auth.rs     # Authentication endpoints
│   │   │       └── wallets.rs  # Wallet & signing endpoints
│   │   └── Cargo.toml
│   │
│   └── erebor-tests/           # Integration tests
│       ├── tests/              # End-to-end test scenarios
│       └── Cargo.toml
│
├── docs/                       # Documentation (mdBook)
│   ├── book.toml              # mdBook configuration
│   └── src/                   # Markdown source files
│       ├── SUMMARY.md         # Documentation structure
│       ├── architecture/      # Architecture deep-dives
│       ├── guides/           # Setup & deployment guides
│       ├── sdk/              # SDK documentation
│       └── getting-started/   # Quick start guides
│
├── Cargo.toml                 # Workspace configuration
├── Cargo.lock                 # Dependency lock file
├── docker-compose.yml         # Local development setup
├── Dockerfile                 # Container build
├── README.md                  # This file
└── LICENSE                   # MIT license
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
- [x] **Phase 4:** Gateway API routes — 18+ REST endpoints for auth, wallets, signing, transactions
- [x] **Phase 5:** Transaction signing + broadcast pipeline (RLP, EIP-155, nonce mgmt, receipt polling)
- [x] **Phase 6:** React SDK (`@erebor/react`) — `useErebor()`, login modal, wallet hooks, `usePrivy()` compat
- [x] **Phase 7:** Embedded wallet iframe — cross-origin key isolation via postMessage bridge
- [x] **Phase 8:** OAuth providers (Apple, Twitter, Discord, GitHub, Farcaster, Telegram, Phone OTP)
- [x] **Phase 9:** Policy engine — 11 rule types, condition sets, aggregations, key quorums
- [ ] **Phase 10:** React Native + Swift + Kotlin SDKs
- [ ] **Phase 11:** MPC-TSS (CGGMP21) + social recovery + anomaly detection
- [ ] **Phase 12:** TEE support + HSM + Kubernetes Helm charts

## License

[MIT](LICENSE) — Use it however you want.
