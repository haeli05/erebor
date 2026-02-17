# Contributing to Erebor

Thank you for your interest in contributing to Erebor! We welcome contributions of all kinds — bug fixes, features, documentation, and security improvements.

## Quick Start

```bash
git clone https://github.com/haeli05/erebor.git
cd erebor
cargo build --workspace
cargo test --workspace
```

## How to Contribute

1. **Fork** the repository
2. **Branch** from `main`: `git checkout -b feat/your-feature`
3. **Code** your changes
4. **Test**: `cargo test --workspace`
5. **Lint**: `cargo fmt --all && cargo clippy --workspace -- -D warnings`
6. **Commit** with a [conventional commit](https://www.conventionalcommits.org/) message
7. **Push** and open a pull request

## Code Standards

- All code must pass `cargo fmt --check` and `cargo clippy -- -D warnings`
- New code must include tests
- Public APIs must have documentation comments
- Security-sensitive code (vault, encryption) requires extra scrutiny — see below

## Security-Sensitive Contributions

Erebor handles private key material. If your change touches `erebor-vault`, `erebor-auth`, or any cryptographic code:

- Use `SecretBytes` for all secret data (auto-zeroes on drop)
- Never log or debug-print key material
- Test failure cases (wrong keys, tampered data, expired tokens)
- Run `cargo audit` before submitting

See the full [Security Policy](SECURITY.md) for vulnerability reporting.

## Commit Messages

```
feat: add passkey authentication provider
fix: handle expired SIWE nonces correctly
docs: update key vault architecture docs
test: add BIP-32 test vector 2
refactor: extract GF(256) arithmetic
chore: update dependencies
```

## Project Structure

| Crate | Description |
|-------|-------------|
| `erebor-common` | Shared types, errors, `SecretBytes` |
| `erebor-auth` | OAuth, Email OTP, SIWE, JWT, sessions |
| `erebor-vault` | Shamir SSS, AES-256-GCM, BIP-32/44, signing |
| `erebor-aa` | ERC-4337 account abstraction |
| `erebor-chain` | Multi-chain RPC, gas estimation |
| `erebor-gateway` | axum API gateway |

## Questions?

Open a [GitHub issue](https://github.com/haeli05/erebor/issues) or start a discussion.
