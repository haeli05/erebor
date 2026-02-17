# Contributing to Erebor

Thank you for your interest in contributing to Erebor! This project aims to provide open-source, self-custodial wallet infrastructure that anyone can run. Every contribution matters.

## Quick Start

```bash
# Fork and clone
git clone https://github.com/<your-username>/erebor.git
cd erebor

# Build
cargo build

# Run tests
cargo test

# Run with logging
RUST_LOG=debug cargo run -p erebor-gateway
```

## Development Setup

### Prerequisites

- **Rust 1.75+** — Install via [rustup](https://rustup.rs/)
- **PostgreSQL 16** — For user/session storage (optional for unit tests)
- **Redis 7** — For caching/rate limiting (optional for unit tests)
- **Docker & Docker Compose** — For integration tests and local development

### Project Structure

```
erebor/
├── crates/
│   ├── erebor-common/     # Shared types, errors
│   ├── erebor-auth/       # Authentication (OAuth, OTP, SIWE, Passkey)
│   ├── erebor-vault/      # Key management (Shamir, encryption, HD derivation)
│   ├── erebor-aa/         # Account abstraction (ERC-4337) [WIP]
│   ├── erebor-chain/      # Multi-chain RPC management [WIP]
│   └── erebor-gateway/    # API gateway (axum)
├── tests/                 # Integration tests
├── docs/                  # mdBook documentation site
└── contracts/             # Solidity smart contracts [planned]
```

## How to Contribute

### Reporting Bugs

1. Check [existing issues](https://github.com/haeli05/erebor/issues) first
2. Use the bug report template
3. Include: Rust version, OS, steps to reproduce, expected vs actual behavior

### Suggesting Features

1. Open a [discussion](https://github.com/haeli05/erebor/discussions) first for larger features
2. For smaller improvements, open an issue with the `enhancement` label

### Submitting Code

1. **Fork** the repository
2. **Branch** from `main`: `git checkout -b feat/your-feature` or `fix/your-fix`
3. **Write tests** — All new code must have tests. We aim for >80% coverage on security-critical paths.
4. **Run the full test suite:** `cargo test --workspace`
5. **Format and lint:**
   ```bash
   cargo fmt --check
   cargo clippy -- -D warnings
   ```
6. **Commit** with conventional commits:
   - `feat: add passkey authentication`
   - `fix: prevent share reconstruction with invalid indices`
   - `docs: update key vault architecture guide`
   - `test: add edge cases for Shamir splitting`
   - `refactor: extract GF(256) arithmetic to module`
7. **Push** and open a **Pull Request** against `main`

### PR Guidelines

- Keep PRs focused — one feature or fix per PR
- Update documentation if behavior changes
- Add entries to CHANGELOG.md for user-facing changes
- Security-sensitive changes require review from a maintainer
- All CI checks must pass

## Code Standards

### Rust Style

- Follow standard Rust idioms and the [Rust API Guidelines](https://rust-lang.github.io/api-guidelines/)
- Use `thiserror` for library errors, `anyhow` only in binaries
- All public items must have doc comments
- Unsafe code requires a `// SAFETY:` comment explaining the invariant

### Security Requirements

- **All secret types must implement `Zeroize`** — Use `zeroize` crate with `#[zeroize(drop)]`
- **No logging of key material** — Never log private keys, shares, seeds, or any cryptographic secrets
- **Constant-time comparisons** for any security-sensitive equality checks
- **Input validation** at API boundaries — don't trust the client
- **Rate limiting** on all authentication and signing endpoints

### Testing

- Unit tests live alongside the code (`#[cfg(test)]` modules)
- Integration tests go in `tests/`
- Use `#[tokio::test]` for async tests
- Test both success paths and error cases
- Security-critical code needs adversarial test cases (e.g., tampered ciphertext, expired tokens, replayed nonces)

## Architecture Decisions

Major architecture decisions are documented in the `docs/` site. If you're proposing a significant change:

1. Write up the problem and proposed solution
2. Open a discussion or RFC issue
3. Get feedback before writing code

## Community

- Be respectful and constructive
- Follow the [Rust Code of Conduct](https://www.rust-lang.org/policies/code-of-conduct)
- Help others in issues and discussions
- Credit prior art and related work

## License

By contributing, you agree that your contributions will be licensed under the MIT License.
