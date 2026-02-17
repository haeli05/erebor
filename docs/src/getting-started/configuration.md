# Configuration

Erebor is configured entirely via environment variables. No config files required.

## Environment Variables Reference

### Gateway

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `RUST_LOG` | No | `info` | Log level (`trace`, `debug`, `info`, `warn`, `error`) |
| `BIND_ADDR` | No | `0.0.0.0:8080` | Listen address |

### Authentication

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `JWT_SECRET` | **Yes** | — | HMAC-SHA256 signing key (min 32 bytes, hex-encoded) |
| `GOOGLE_CLIENT_ID` | No | — | Google OAuth 2.0 client ID |
| `GOOGLE_CLIENT_SECRET` | No | — | Google OAuth 2.0 client secret |
| `GOOGLE_REDIRECT_URI` | No | — | OAuth redirect URI |
| `SIWE_DOMAIN` | No | `localhost` | Expected domain for SIWE messages |
| `ACCESS_TOKEN_TTL` | No | `900` | Access token lifetime in seconds (default 15 min) |
| `REFRESH_TOKEN_TTL` | No | `2592000` | Refresh token lifetime in seconds (default 30 days) |

### Key Vault

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `KEY_STRATEGY` | No | `shamir` | Key management strategy: `shamir`, `mpc_tss`, `tee` |
| `VAULT_MASTER_KEY` | **Yes** | — | Master encryption key (32 bytes, hex-encoded) |
| `SHAMIR_THRESHOLD` | No | `2` | Minimum shares needed to reconstruct |
| `SHAMIR_TOTAL` | No | `3` | Total shares to generate |

### Database

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `DATABASE_URL` | **Yes** | — | PostgreSQL connection string |
| `REDIS_URL` | No | `redis://127.0.0.1:6379` | Redis connection URL |
| `DB_MAX_CONNECTIONS` | No | `10` | Connection pool size |

### Rate Limiting

| Variable | Required | Default | Description |
|----------|----------|---------|-------------|
| `RATE_LIMIT_MAX_TOKENS` | No | `60` | Max requests per bucket |
| `RATE_LIMIT_REFILL_RATE` | No | `1.0` | Tokens refilled per second |
| `OTP_MAX_SENDS_PER_HOUR` | No | `5` | Max OTP emails per address per hour |
| `OTP_MAX_ATTEMPTS` | No | `3` | Max verification attempts per OTP |

## Generating Secrets

```bash
# Generate a JWT secret
openssl rand -hex 32

# Generate a vault master key
openssl rand -hex 32

# Generate a full .env file
cat > .env << 'EOF'
RUST_LOG=info
JWT_SECRET=$(openssl rand -hex 32)
VAULT_MASTER_KEY=$(openssl rand -hex 32)
DATABASE_URL=postgres://erebor:erebor@localhost:5432/erebor
REDIS_URL=redis://127.0.0.1:6379
SIWE_DOMAIN=yourdomain.com
EOF
```

## Example `.env`

```bash
# Gateway
RUST_LOG=info

# Auth
JWT_SECRET=a3f2b1c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1
GOOGLE_CLIENT_ID=123456789.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-xxxxxxxxxxxxx
GOOGLE_REDIRECT_URI=http://localhost:3000/auth/callback
SIWE_DOMAIN=localhost

# Vault
KEY_STRATEGY=shamir
VAULT_MASTER_KEY=deadbeefcafebabe0123456789abcdef0123456789abcdefdeadbeefcafebabe

# Database
DATABASE_URL=postgres://erebor:erebor@localhost:5432/erebor
REDIS_URL=redis://127.0.0.1:6379
```

## Security Notes

- **Never commit `.env` files** — add `.env` to `.gitignore`
- **Rotate `JWT_SECRET` periodically** — all existing access tokens will be invalidated
- **The `VAULT_MASTER_KEY` is critical** — losing it means losing access to all encrypted key shares. Back it up securely (e.g., in a hardware security module or split across multiple secure locations)
- **Use strong random values** — always generate secrets with `openssl rand` or equivalent CSPRNG
