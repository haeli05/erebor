# Auth Service

The auth service (`erebor-auth`) maps Web2 identities to internal user IDs that correspond to wallets. It handles authentication, session management, and identity linking.

## Core Concept: Deterministic User IDs

When a user authenticates via any provider, Erebor generates a deterministic user ID:

```rust
pub fn deterministic_user_id(provider: &AuthProvider, provider_user_id: &str) -> UserId {
    let mut hasher = Sha256::new();
    hasher.update(provider_str.as_bytes());
    hasher.update(b"||");
    hasher.update(provider_user_id.as_bytes());
    let hash = hasher.finalize();
    UserId(Uuid::from_slice(&hash[..16]).unwrap())
}
```

Same Google account → same `UserId` → same wallet. Always. Across devices, sessions, and server restarts.

## Authentication Providers

### Google OAuth

Full OAuth 2.0 authorization code flow:

1. Client redirects to Google's consent screen
2. Google redirects back with an authorization code
3. Erebor exchanges the code for tokens server-side
4. Fetches user info from Google's userinfo endpoint
5. Maps `sub` (Google's unique user ID) to an Erebor `UserId`

```bash
# Exchange Google auth code for Erebor tokens
curl -X POST http://localhost:8080/auth/google \
  -H "Content-Type: application/json" \
  -d '{"code": "4/0AX4XfWh..."}'
```

**Configuration required:**
```bash
GOOGLE_CLIENT_ID=your-client-id.apps.googleusercontent.com
GOOGLE_CLIENT_SECRET=GOCSPX-xxx
GOOGLE_REDIRECT_URI=http://localhost:3000/auth/callback
```

### Email OTP

Six-digit one-time password via email:

1. User requests OTP → server generates 6-digit code, stores with 10-minute TTL
2. User submits code → server verifies (max 3 attempts)
3. On success, generates deterministic `UserId` from `hash("email_otp:" + email)`

**Security features:**
- 6-digit codes with 10-minute expiry
- Maximum 3 verification attempts per code
- Rate limited: 5 OTP sends per email per hour
- Case-insensitive email matching
- Single-use: code is consumed on successful verification

```bash
# Send OTP
curl -X POST http://localhost:8080/auth/email/send-otp \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com"}'

# Verify OTP
curl -X POST http://localhost:8080/auth/email/verify \
  -H "Content-Type: application/json" \
  -d '{"email": "user@example.com", "code": "482910"}'
```

### SIWE (Sign-In With Ethereum)

[EIP-4361](https://eips.ethereum.org/EIPS/eip-4361) Sign-In With Ethereum:

1. Client requests a nonce from Erebor
2. User signs a structured message with their wallet
3. Erebor verifies domain, nonce (single-use), version, and expiration
4. Maps the Ethereum address to a `UserId`

```bash
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
      "nonce": "a1b2c3d4...",
      "issued_at": "2026-02-17T00:00:00Z"
    },
    "signature": "0xabcd..."
  }'
```

### Passkeys (WebAuthn/FIDO2)

Stub implementation — planned for full WebAuthn support with:
- Resident credentials (discoverable)
- Cross-platform authenticators
- RP ID locked to deployment domain

## Session Management

### JWT Tokens

- **Access tokens:** 15-minute TTL, contain `user_id` and linked `providers`
- **Refresh tokens:** 30-day TTL, stored in session store
- **Signing:** HMAC-SHA256 (configurable)

```rust
pub struct Claims {
    pub sub: String,           // user_id
    pub exp: i64,              // expiration timestamp
    pub iat: i64,              // issued at timestamp
    pub jti: String,           // unique token ID
    pub providers: Vec<String>, // linked auth providers
}
```

### Refresh Token Rotation

Every refresh request:
1. Validates the refresh token
2. **Revokes** the old session
3. Creates a new session with a new refresh token
4. Returns new access + refresh tokens

If someone tries to use a **revoked** refresh token (possible token theft), Erebor revokes **all** sessions for that user:

```rust
if session.revoked {
    // Possible token theft — revoke all sessions for this user
    self.store.revoke_all_for_user(&session.user_id).await?;
    return Err(EreborError::Unauthorized);
}
```

## Identity Linking

Users can link multiple auth methods to one account:

```bash
# Link an additional provider (requires JWT)
curl -X POST http://localhost:8080/auth/link \
  -H "Authorization: Bearer eyJ..." \
  -H "Content-Type: application/json" \
  -d '{
    "provider": "siwe",
    "provider_user_id": "0x1234...",
    "email": null
  }'
```

**Safety rules:**
- **Append-only by default** — Linking is idempotent; re-linking the same identity succeeds silently
- **Cross-user protection** — If a provider identity is already linked to a different user, the request fails
- **Minimum one identity** — Cannot unlink the last remaining identity (prevents account lockout)

```bash
# Unlink a provider (must keep at least one)
curl -X DELETE http://localhost:8080/auth/link/google \
  -H "Authorization: Bearer eyJ..."
```

## Auth Middleware

Protects routes by extracting and validating the JWT from the `Authorization: Bearer <token>` header:

```rust
pub async fn auth_middleware(
    mut request: Request<Body>,
    next: Next,
) -> Result<Response, StatusCode> {
    // Extract JWT from Authorization header
    // Verify signature and expiration
    // Insert AuthenticatedUser into request extensions
    // Pass to next handler
}
```

Protected handlers can access the authenticated user:

```rust
async fn me(
    Extension(auth_user): Extension<AuthenticatedUser>,
) -> impl IntoResponse {
    Json(MeResponse {
        user_id: auth_user.user_id.0.to_string(),
        providers: auth_user.claims.providers,
    })
}
```

## Rate Limiting

Token bucket rate limiter per client IP:

- Configurable max tokens and refill rate
- Uses `X-Forwarded-For` or `X-Real-IP` headers behind a reverse proxy
- Returns `429 Too Many Requests` when exhausted

```rust
let limiter = RateLimiter::new(
    100.0,  // max tokens per bucket
    10.0,   // tokens refilled per second
);
```

## API Routes

| Method | Path | Auth | Description |
|--------|------|------|-------------|
| POST | `/auth/google` | No | Exchange Google OAuth code |
| POST | `/auth/email/send-otp` | No | Send OTP to email |
| POST | `/auth/email/verify` | No | Verify OTP, get tokens |
| POST | `/auth/siwe/verify` | No | Verify SIWE message |
| POST | `/auth/refresh` | No | Refresh session tokens |
| GET | `/auth/me` | Yes | Get current user info |
| POST | `/auth/link` | Yes | Link new auth method |
| DELETE | `/auth/link/:provider` | Yes | Unlink auth method |
