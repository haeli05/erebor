# Development Setup

## Prerequisites

- **Rust 1.75+** via [rustup](https://rustup.rs/)
- **Git**
- **Docker** (optional, for integration tests)

## Getting Started

```bash
# Clone your fork
git clone https://github.com/<your-username>/erebor.git
cd erebor

# Build
cargo build

# Run all tests
cargo test --workspace

# Run with debug logging
RUST_LOG=debug cargo run -p erebor-gateway
```

## Project Structure

```
erebor/
├── Cargo.toml              # Workspace root
├── crates/
│   ├── erebor-common/      # Shared types, errors
│   │   └── src/
│   │       ├── types.rs    # UserId, AuthProvider, SecretBytes, Chain, etc.
│   │       └── error.rs    # EreborError enum
│   ├── erebor-auth/        # Authentication
│   │   └── src/
│   │       ├── providers.rs  # Google OAuth, Email OTP, SIWE, Passkey
│   │       ├── jwt.rs        # JWT issuance and verification
│   │       ├── session.rs    # Session management with token rotation
│   │       ├── linking.rs    # Multi-provider identity linking
│   │       ├── middleware.rs  # Auth middleware, rate limiter
│   │       └── routes.rs     # HTTP route handlers
│   ├── erebor-vault/       # Key management
│   │   └── src/
│   │       ├── shamir.rs       # Shamir SSS over GF(2^8)
│   │       ├── encryption.rs   # AES-256-GCM envelope encryption
│   │       ├── key_derivation.rs  # BIP-32/44, ETH/SOL addresses, signing
│   │       ├── storage.rs     # Share storage trait + in-memory impl
│   │       └── lib.rs         # VaultService (high-level API)
│   ├── erebor-aa/          # Account abstraction [stubs]
│   ├── erebor-chain/       # Chain service [stubs]
│   └── erebor-gateway/     # API gateway
│       └── src/main.rs     # axum server with health endpoint
├── tests/                  # Integration tests
├── docs/                   # mdBook documentation
├── CONTRIBUTING.md
├── SECURITY.md
└── LICENSE
```

## Development Workflow

```bash
# Create a feature branch
git checkout -b feat/your-feature

# Make changes, run tests frequently
cargo test -p erebor-vault
cargo test --workspace

# Format and lint before committing
cargo fmt
cargo clippy -- -D warnings

# Commit with conventional commits
git commit -m "feat: add social recovery to vault"

# Push and create PR
git push origin feat/your-feature
```

## Useful Commands

```bash
# Watch mode (rebuild on save)
cargo install cargo-watch
cargo watch -x 'test --workspace'

# Check without building (faster)
cargo check --workspace

# Generate docs
cargo doc --workspace --no-deps --open

# Specific test
cargo test -p erebor-vault test_shamir

# Test with output
cargo test -- --nocapture

# Release build
cargo build --release
```

## Adding a New Crate

1. Create the crate: `cargo new crates/erebor-newcrate --lib`
2. Add to workspace `members` in root `Cargo.toml`
3. Add workspace dependencies
4. Write implementation + tests
5. Update docs

## Code Style

- All public items have doc comments (`///`)
- Secret types implement `Zeroize`
- Error types use `thiserror`
- Async code uses `tokio`
- Tests cover both success and error paths
