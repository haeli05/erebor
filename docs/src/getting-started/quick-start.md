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

## Complete Auth → Wallet → Sign Flow

### 1. Send an Email OTP

```bash
curl -X POST http://localhost:8080/auth/email/send-otp \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com"}'
# {"message":"OTP sent"}
```

### 2. Verify the OTP and Get Tokens

```bash
curl -X POST http://localhost:8080/auth/email/verify \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "code": "123456"}'
```

Response (save the access_token):

```json
{
  "access_token": "eyJhbGciOiJIUzI1NiJ9...",
  "refresh_token": "a1b2c3d4e5f6...",
  "user_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

### 3. Create an Embedded Wallet

```bash
ACCESS_TOKEN="eyJhbGciOiJIUzI1NiJ9..."

curl -X POST http://localhost:8080/wallets \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name": "My Main Wallet"}'
```

Response (save the wallet_id and ethereum_address):

```json
{
  "wallet_id": "wallet-123-abc",
  "ethereum_address": "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf",
  "share_indices": [1, 2, 3],
  "created_at": "2026-02-17T00:00:00Z"
}
```

### 4. Sign a Message

```bash
WALLET_ID="wallet-123-abc"

curl -X POST http://localhost:8080/wallets/$WALLET_ID/sign-message \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "message": "Hello, Erebor!",
    "share_indices": [1, 2]
  }'
```

Response:

```json
{
  "signature": "0x1b2e4f7a8c9d3e6f1a2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b7c8d9e0f1a2b3c4d5e6f7a8b9c0d1e",
  "message_hash": "0x7b5c3d8e1f2a4b6c9d0e3f5a7b8c1d4e6f9a2b5c8d0e3f6a9b2c5d8e1f4a7b0c3d6e9f2a5b8c1d4e7f0a3b6c9d2e5f8",
  "recovery_id": 27
}
```

### 5. Send a Transaction

```bash
curl -X POST http://localhost:8080/wallets/$WALLET_ID/send-transaction \
  -H "Authorization: Bearer $ACCESS_TOKEN" \
  -H "Content-Type: application/json" \
  -d '{
    "to": "0x1234567890abcdef1234567890abcdef12345678",
    "value": "1000000000000000000",
    "data": "0x",
    "gas_limit": 21000,
    "gas_price": "20000000000",
    "share_indices": [1, 2]
  }'
```

Response:

```json
{
  "transaction_hash": "0xabc123def456...",
  "status": "pending",
  "gas_used": null,
  "block_number": null
}
```

That's it! You've authenticated a user, created their embedded wallet, and signed a transaction — all via REST API calls.

### Additional Operations

```bash
# Get current user info
curl http://localhost:8080/auth/me \
  -H "Authorization: Bearer $ACCESS_TOKEN"

# List user's wallets
curl http://localhost:8080/wallets \
  -H "Authorization: Bearer $ACCESS_TOKEN"

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
