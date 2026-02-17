# Installation

## Prerequisites

- **Rust 1.75+** — Install via [rustup](https://rustup.rs/)
- **PostgreSQL 15+** — User and session storage
- **Redis 7+** — Caching, nonces, rate limiting

## From Source

```bash
git clone https://github.com/haeli05/erebor.git
cd erebor

# Build all crates
cargo build --release

# Run the full test suite
cargo test --workspace

# Start the gateway
RUST_LOG=info cargo run -p erebor-gateway
```

The release binary is at `target/release/erebor-gateway`.

## Crate Structure

```
erebor/
├── crates/
│   ├── erebor-common/     # Shared types, errors, SecretBytes
│   ├── erebor-auth/       # Authentication providers + JWT
│   ├── erebor-vault/      # Shamir SSS + encryption + HD derivation
│   ├── erebor-aa/         # Account abstraction (ERC-4337)
│   ├── erebor-chain/      # Multi-chain RPC + gas estimation
│   └── erebor-gateway/    # axum API gateway (binary)
├── docs/                  # This documentation (mdBook)
├── Cargo.toml             # Workspace root
└── docker-compose.yml
```

## Docker

```bash
# Build the image
docker build -t erebor:latest .

# Run with environment variables
docker run -p 8080:8080 \
  -e RUST_LOG=info \
  -e JWT_SECRET=$(openssl rand -hex 32) \
  -e VAULT_MASTER_KEY=$(openssl rand -hex 32) \
  erebor:latest
```

## Docker Compose (Full Stack)

```bash
docker compose up -d
```

This starts:
- **erebor-gateway** on port 8080
- **PostgreSQL** on port 5432
- **Redis** on port 6379

## Verifying the Installation

```bash
# Health check
curl http://localhost:8080/health
# {"status":"ok","version":"0.1.0"}

# Root info
curl http://localhost:8080/
# {"name":"erebor","description":"Self-custodial wallet infrastructure","version":"0.1.0"}
```

## Development Tools

```bash
# Format code
cargo fmt --all

# Lint
cargo clippy --workspace -- -D warnings

# Run tests with output
cargo test --workspace -- --nocapture

# Watch mode (requires cargo-watch)
cargo install cargo-watch
cargo watch -x 'test --workspace'
```
