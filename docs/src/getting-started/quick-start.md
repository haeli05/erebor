# Quick Start

Get Erebor running in under 5 minutes.

## Docker Compose (Recommended)

```bash
git clone https://github.com/haeli05/erebor.git
cd erebor
docker compose up
```

The gateway starts at `http://localhost:8080`.

## Verify

```bash
curl http://localhost:8080/health
# {"status":"ok","version":"0.1.0"}
```

## Authenticate a User

### 1. Send an Email OTP

```bash
curl -X POST http://localhost:8080/auth/email/send-otp \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com"}'
# {"message":"OTP sent"}
```

### 2. Verify the OTP

```bash
curl -X POST http://localhost:8080/auth/email/verify \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "code": "123456"}'
```

Response:

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiJ9...",
  "refresh_token": "a1b2c3d4e5f6...",
  "user_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

### 3. Use the Access Token

```bash
# Get current user info
curl http://localhost:8080/auth/me \
  -H "Authorization: Bearer eyJhbGciOiJIUzI1NiJ9..."

# Refresh when the access token expires (15 min)
curl -X POST http://localhost:8080/auth/refresh \
  -H "Content-Type: application/json" \
  -d '{"refresh_token": "a1b2c3d4e5f6..."}'
```

## Sign-In With Ethereum (SIWE)

```bash
# 1. Get a nonce
curl http://localhost:8080/auth/siwe/nonce

# 2. Have the user sign an EIP-4361 message with the nonce

# 3. Verify the signature
curl -X POST http://localhost:8080/auth/siwe/verify \
  -H "Content-Type: application/json" \
  -d '{
    "message": {
      "domain": "yourdomain.com",
      "address": "0x1234...abcd",
      "statement": "Sign in to Erebor",
      "uri": "https://yourdomain.com",
      "version": "1",
      "chain_id": 1,
      "nonce": "<nonce-from-step-1>",
      "issued_at": "2026-01-01T00:00:00Z"
    },
    "signature": "0x..."
  }'
```

## Google OAuth

```bash
# Exchange an authorization code for tokens
curl -X POST http://localhost:8080/auth/google \
  -H "Content-Type: application/json" \
  -d '{"code": "<google-auth-code>"}'
```

Requires `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, and `GOOGLE_REDIRECT_URI` to be set. See [Configuration](configuration.md).

## Next Steps

- [Installation](installation.md) — Build from source
- [Configuration](configuration.md) — Environment variables reference
- [Architecture Overview](../architecture/overview.md) — How the pieces fit together
