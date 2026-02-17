# Introduction

**Erebor** is a modular, self-hosted wallet infrastructure stack written in Rust. It provides the same capabilities as [Privy](https://privy.io) — social login → embedded wallets → smart accounts — but you run it yourself, audit every line, and pay nothing per MAU.

## The Problem

Services like Privy, Web3Auth, and Magic bundle three commodity pieces — OAuth, key splitting, and smart contract wallets — into a SaaS with per-user pricing. At scale, this costs hundreds of thousands per year for infrastructure built on open standards.

Worse, you can't audit the key management. You can't self-host. You're trusting a third party with your users' private keys.

## The Erebor Approach

Erebor unbundles wallet infrastructure into four swappable Rust crates you compose however you want:

| Crate | Purpose |
|-------|---------|
| `erebor-auth` | OAuth, Email OTP, SIWE, Passkeys → JWT sessions |
| `erebor-vault` | Shamir 2-of-3 key splitting, AES-256-GCM encryption, BIP-32/44 HD derivation |
| `erebor-aa` | ERC-4337 bundler, paymaster, smart contract wallets |
| `erebor-chain` | Multi-chain RPC pooling, gas estimation |

All wrapped by `erebor-gateway`, an axum-based API gateway with rate limiting and JWT validation.

## Comparison

| | **Erebor** | **Privy** | **Web3Auth** | **Magic** |
|---|---|---|---|---|
| Self-hosted | ✅ | ❌ SaaS only | ⚠️ Partial | ❌ |
| Open source | ✅ MIT | ❌ | ⚠️ Partial | ❌ |
| Key custody | ✅ Shamir 2-of-3 | ⚠️ MPC | ⚠️ MPC | ❌ Delegated |
| Pricing | ✅ Free | 💰 Per MAU | 💰 Per MAU | 💰 Per MAU |
| Full audit | ✅ | ❌ | ⚠️ | ❌ |

## How This Documentation Is Organised

- **Getting Started** — Run Erebor in under 5 minutes
- **Architecture** — Deep dives into each crate and the security model
- **Guides** — Self-hosting in production, key management best practices
- **Contributing** — How to develop, test, and report security issues
