# Architecture Overview

Erebor is a modular wallet infrastructure stack. Each module is an independent Rust crate that communicates through well-defined interfaces.

## System Architecture

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
└─────────┘└─────────┘└─────────┘└──────────┘
     │          │          │          │
     ▼          ▼          ▼          ▼
┌─────────────────────────────────────────────────────────────┐
│  PostgreSQL · Redis · Encrypted KV (key shares)             │
└─────────────────────────────────────────────────────────────┘
```

## Modules

### Auth Service (`erebor-auth`)

Maps Web2 identities to Web3 addresses. A user signs in with Google → they get a wallet. Same user, different device, same Google account → same wallet.

**Key components:**
- **Providers** — Google OAuth, Email OTP, SIWE (Sign-In With Ethereum), Passkeys
- **Sessions** — JWT access tokens (15min) + refresh tokens (30 days) with rotation
- **Linking** — Append-only identity linking (Google + email + SIWE → one user)
- **Middleware** — Auth middleware for protecting routes, rate limiter

### Key Vault (`erebor-vault`)

The critical security module. Manages private keys such that no single compromise yields a key.

**Key components:**
- **Shamir** — 2-of-3 secret sharing over GF(2^8)
- **Encryption** — AES-256-GCM with per-user keys derived via HKDF
- **HD Derivation** — BIP-32/44 for Ethereum and Solana wallets
- **Storage** — Pluggable backend (in-memory for dev, PostgreSQL for production)
- **Audit** — Immutable log of every key operation

### Account Abstraction (`erebor-aa`)

Wraps EOA wallets in ERC-4337 smart contract accounts enabling gasless transactions, session keys, and spending limits.

**Key components:**
- **Bundler** — ERC-4337 UserOperation bundling and submission
- **Paymaster** — Gas sponsorship (verifying, sponsored, ERC-20 paymasters)
- **Smart Wallets** — Factory deployment and management
- **Session Keys** — Scoped permissions with spending limits

### Chain Service (`erebor-chain`)

Abstracts multi-chain complexity — RPC connection pooling, gas estimation, transaction broadcasting.

**Key components:**
- **Gas Estimation** — EIP-1559 and legacy gas oracles with safety margins
- **RPC Pool** — Multi-provider connection pooling with health tracking and failover
- **Transaction Pipeline** — Nonce management, signing, and broadcasting
- **Chain Registry** — Configuration for EVM chains (Ethereum, Base, Polygon, Arbitrum, Optimism) and Solana

## Request Flow

A typical authentication flow:

```
Client                    Gateway                 Auth                  Vault
  │                         │                      │                      │
  │── POST /auth/email/     │                      │                      │
  │   send-otp ────────────►│── rate check ───────►│                      │
  │                         │                      │── generate OTP       │
  │                         │◄─────────────────────│── send email         │
  │◄── 200 "OTP sent" ─────│                      │                      │
  │                         │                      │                      │
  │── POST /auth/email/     │                      │                      │
  │   verify ──────────────►│── rate check ───────►│                      │
  │                         │                      │── verify OTP         │
  │                         │                      │── deterministic_id   │
  │                         │                      │── create session     │
  │                         │                      │── issue JWT          │
  │◄── 200 { tokens } ─────│◄─────────────────────│                      │
  │                         │                      │                      │
  │── POST /vault/create    │                      │                      │
  │   (with Bearer JWT) ───►│── verify JWT ───────►│                      │
  │                         │                      │                      │
  │                         │─────────────────────────── create_wallet ──►│
  │                         │                      │   │ generate seed    │
  │                         │                      │   │ derive ETH key   │
  │                         │                      │   │ shamir split     │
  │                         │                      │   │ encrypt shares   │
  │                         │                      │   │ store shares     │
  │                         │                      │   │ zeroize seed     │
  │◄── 200 { address } ────│◄─────────────────────────────────────────────│
```

## Tech Stack

| Component | Choice | Rationale |
|-----------|--------|-----------|
| Language | **Rust** | Memory safety for key material, `zeroize` crate, no GC pauses, high performance |
| API framework | **axum** | Async, tower middleware ecosystem, production-proven |
| Database | **PostgreSQL** | ACID for user/session/policy data |
| Cache | **Redis** | Sessions, nonces, rate limiting |
| Key encryption | **AES-256-GCM** | Industry-standard AEAD |
| Key derivation | **HKDF-SHA256** | Per-user key derivation from master key |
| Secret sharing | **Custom GF(2^8)** | Shamir SSS with Galois field arithmetic |
| HD wallets | **BIP-32/44** | Standard hierarchical derivation |
| Signing | **secp256k1 / Ed25519** | EVM and Solana respectively |
| Smart contracts | **Solidity (Foundry)** | ERC-4337 ecosystem compatibility |

## Data Flow Principles

1. **Key material never persists in plaintext** — Seeds are generated, split into shares, encrypted, stored, then zeroed from memory.
2. **Shares are encrypted with per-user keys** — HKDF derives a unique DEK from the master key + user context. A database breach yields only encrypted blobs.
3. **Authentication is deterministic** — `hash(provider || provider_user_id)` always produces the same internal user ID. Same Google account = same wallet, always.
4. **Sessions use refresh token rotation** — Each refresh invalidates the old token. Using a revoked token triggers revocation of all sessions for that user (theft detection).
