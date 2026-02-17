# API Reference

Complete HTTP API reference for the Erebor gateway.

## Base URL

```
http://localhost:8080
```

In production, use your domain with TLS: `https://erebor.yourdomain.com`

## Authentication

Protected endpoints require a JWT access token in the `Authorization` header:

```
Authorization: Bearer eyJhbGciOiJIUzI1NiJ9...
```

Access tokens expire after 15 minutes. Use the refresh endpoint to obtain new tokens.

---

## Health

### `GET /health`

Health check endpoint.

**Response:**
```json
{
  "status": "ok",
  "version": "0.1.0"
}
```

### `GET /`

Service info.

**Response:**
```json
{
  "name": "erebor",
  "description": "Self-custodial wallet infrastructure",
  "version": "0.1.0"
}
```

---

## Authentication Endpoints

### `POST /auth/google`

Exchange a Google OAuth authorization code for Erebor tokens.

**Request:**
```json
{
  "code": "4/0AX4XfWh..."
}
```

**Response (200):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiJ9...",
  "refresh_token": "a1b2c3d4e5f6...",
  "user_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Errors:**
- `401` — Invalid authorization code
- `501` — Google OAuth not configured

---

### `POST /auth/email/send-otp`

Send a 6-digit OTP to an email address.

**Request:**
```json
{
  "email": "user@example.com"
}
```

**Response (200):**
```json
{
  "message": "OTP sent"
}
```

**Errors:**
- `429` — Rate limited (max 5 sends per email per hour)

---

### `POST /auth/email/verify`

Verify an email OTP and receive authentication tokens.

**Request:**
```json
{
  "email": "user@example.com",
  "code": "482910"
}
```

**Response (200):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiJ9...",
  "refresh_token": "a1b2c3d4e5f6...",
  "user_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Errors:**
- `401` — Invalid or expired OTP, too many attempts

---

### `POST /auth/siwe/verify`

Verify a Sign-In With Ethereum (EIP-4361) message and signature.

**Request:**
```json
{
  "message": {
    "domain": "yourdomain.com",
    "address": "0x1234567890abcdef1234567890abcdef12345678",
    "statement": "Sign in to Erebor",
    "uri": "https://yourdomain.com",
    "version": "1",
    "chain_id": 1,
    "nonce": "a1b2c3d4e5f6a1b2c3d4e5f6a1b2c3d4",
    "issued_at": "2026-02-17T00:00:00Z",
    "expiration_time": "2026-02-17T01:00:00Z"
  },
  "signature": "0xabcdef..."
}
```

**Response (200):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiJ9...",
  "refresh_token": "a1b2c3d4e5f6...",
  "user_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Errors:**
- `401` — Domain mismatch, invalid nonce, expired message, bad signature

---

### `POST /auth/refresh`

Refresh authentication tokens. Implements refresh token rotation — the old refresh token is invalidated.

**Request:**
```json
{
  "refresh_token": "a1b2c3d4e5f6..."
}
```

**Response (200):**
```json
{
  "access_token": "eyJhbGciOiJIUzI1NiJ9...",
  "refresh_token": "new-refresh-token...",
  "user_id": "550e8400-e29b-41d4-a716-446655440000"
}
```

**Errors:**
- `401` — Invalid, expired, or revoked refresh token. If a revoked token is used, ALL sessions for the user are revoked (theft detection).

---

### `GET /auth/me` 🔒

Get the currently authenticated user's information.

**Headers:** `Authorization: Bearer <access_token>`

**Response (200):**
```json
{
  "user_id": "550e8400-e29b-41d4-a716-446655440000",
  "providers": ["google", "email"],
  "linked_identities": [
    {
      "provider": "google",
      "provider_user_id": "118234...",
      "email": "user@gmail.com",
      "linked_at": "2026-02-17T00:00:00Z"
    },
    {
      "provider": "email",
      "provider_user_id": "abc123...",
      "email": "user@example.com",
      "linked_at": "2026-02-17T01:00:00Z"
    }
  ]
}
```

---

### `POST /auth/link` 🔒

Link a new authentication method to the current user.

**Headers:** `Authorization: Bearer <access_token>`

**Request:**
```json
{
  "provider": "siwe",
  "provider_user_id": "0x1234...abcd",
  "email": null
}
```

**Response (200):**
```json
{
  "message": "Identity linked"
}
```

**Errors:**
- `400` — Identity already linked to a different user

---

### `DELETE /auth/link/:provider` 🔒

Unlink an authentication method. Must keep at least one linked identity.

**Headers:** `Authorization: Bearer <access_token>`

**Response (200):**
```json
{
  "message": "Identity unlinked"
}
```

**Errors:**
- `400` — Cannot unlink last identity, or unknown provider

---

## Wallet Endpoints

### `POST /wallets` 🔒

Create a new embedded wallet for the authenticated user.

**Headers:** `Authorization: Bearer <access_token>`

**Request:**
```json
{
  "name": "My Main Wallet"
}
```

**Response (200):**
```json
{
  "wallet_id": "wallet-123-abc",
  "ethereum_address": "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf",
  "share_indices": [1, 2, 3],
  "created_at": "2026-02-17T00:00:00Z"
}
```

---

### `GET /wallets` 🔒

List all wallets for the authenticated user.

**Headers:** `Authorization: Bearer <access_token>`

**Response (200):**
```json
{
  "wallets": [
    {
      "wallet_id": "wallet-123-abc",
      "ethereum_address": "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf",
      "share_count": 3,
      "created_at": "2026-02-17T00:00:00Z"
    }
  ]
}
```

---

### `GET /wallets/:id` 🔒

Get details for a specific wallet.

**Headers:** `Authorization: Bearer <access_token>`

**Response (200):**
```json
{
  "wallet_id": "wallet-123-abc",
  "ethereum_address": "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf",
  "share_indices": [1, 2, 3],
  "created_at": "2026-02-17T00:00:00Z"
}
```

**Errors:**
- `404` — Wallet not found or not owned by user

---

### `POST /wallets/:id/sign-message` 🔒

Sign an arbitrary message with the wallet's private key.

**Headers:** `Authorization: Bearer <access_token>`

**Request:**
```json
{
  "message": "Hello, Erebor!",
  "share_indices": [1, 2]
}
```

**Response (200):**
```json
{
  "signature": "0x1b2e4f...",
  "message_hash": "0x7b5c3d...",
  "recovery_id": 27
}
```

**Errors:**
- `400` — Insufficient shares (need at least 2 of 3)
- `404` — Wallet not found

---

### `POST /wallets/:id/sign-transaction` 🔒

Sign a transaction (returns signature without broadcasting).

**Headers:** `Authorization: Bearer <access_token>`

**Request:**
```json
{
  "to": "0x1234567890abcdef1234567890abcdef12345678",
  "value": "1000000000000000000",
  "data": "0x",
  "gas_limit": 21000,
  "max_fee_per_gas": "30000000000",
  "max_priority_fee_per_gas": "1500000000",
  "nonce": 42,
  "share_indices": [1, 2]
}
```

**Response (200):**
```json
{
  "signature": "0xr=1b2e4f...,s=3a5c7d...,v=27",
  "transaction_hash": "0xabc123...",
  "signed_transaction": "0x02f86c..."
}
```

---

### `POST /wallets/:id/send-transaction` 🔒

Sign and broadcast a transaction to the network.

**Headers:** `Authorization: Bearer <access_token>`

**Request:**
```json
{
  "to": "0x1234567890abcdef1234567890abcdef12345678",
  "value": "1000000000000000000",
  "data": "0x",
  "gas_limit": 21000,
  "gas_price": "20000000000",
  "share_indices": [1, 2]
}
```

**Response (200):**
```json
{
  "transaction_hash": "0xabc123def456...",
  "status": "pending",
  "gas_used": null,
  "block_number": null
}
```

**Errors:**
- `400` — Invalid transaction parameters
- `500` — RPC error or broadcast failure

---

## Error Format

All errors return a JSON body with a message:

```json
{
  "error": "Description of what went wrong"
}
```

Common HTTP status codes:
- `400` — Bad request (invalid input)
- `401` — Unauthorized (missing or invalid token)
- `404` — Not found
- `429` — Rate limited
- `500` — Internal server error
- `501` — Not implemented (feature not configured)
