# Erebor

**Self-custodial wallet infrastructure. Open source.**

An open-source alternative to Privy — auth, embedded wallets, and account abstraction in one self-hosted stack.

## What is this?

Erebor is four modules, all swappable:

1. **Auth Service** — OAuth, email/phone OTP, SIWE, passkeys. Maps Web2 identity to wallets deterministically.
2. **Key Vault** — Shamir 2-of-3, MPC-TSS (CGGMP21), or TEE-backed key management. No single compromise yields a key.
3. **Account Abstraction** — ERC-4337 bundler + paymaster + smart contract wallets. Gasless transactions, session keys, spending limits.
4. **Chain Service** — Multi-chain RPC pooling, gas estimation, event indexing.

## Why?

Privy charges per MAU for three commodity pieces glued together well. The moat is integration quality, not proprietary cryptography. Erebor matches the DX, self-hosted, auditable, and free.

## Tech Stack

- **Rust** — Memory safety for key material, `zeroize` crate, no GC pauses
- **axum** — Async API framework
- **PostgreSQL** — Users, sessions, policies
- **Redis** — Caching, rate limiting, nonces
- **Foundry** — Solidity smart contracts (ERC-4337)

## Architecture

```
┌─────────────────────────────────────────────────────────────┐
│                        CLIENT SDKs                          │
│  React │ React Native │ Swift │ Kotlin │ Flutter │ Unity    │
└──────────────────────────┬──────────────────────────────────┘
                           │ HTTPS/WSS
┌──────────────────────────▼──────────────────────────────────┐
│                      API GATEWAY (axum)                     │
│         Rate limiting · JWT validation · Routing            │
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

## Quick Start

```bash
docker compose up
```

## Build from Source

```bash
cargo build --release
```

## Project Status

Phase 1 (Auth + Shamir Vault + React SDK) — **In Development**

## License

MIT
