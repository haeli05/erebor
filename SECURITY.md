# Security Policy

## Supported Versions

| Version | Supported          |
| ------- | ------------------ |
| 0.1.x   | :white_check_mark: |

## Reporting a Vulnerability

**Do not open a public GitHub issue for security vulnerabilities.**

Erebor handles private key material. We take security extremely seriously.

### How to Report

1. **Email:** Send a detailed report to **security@erebor.dev**
2. **Subject:** `[SECURITY] Brief description`
3. **Include:**
   - Description of the vulnerability
   - Steps to reproduce
   - Potential impact assessment
   - Suggested fix (if any)

### What to Expect

- **Acknowledgment:** Within 48 hours
- **Initial Assessment:** Within 5 business days
- **Resolution Timeline:** Depends on severity
  - **Critical** (key material exposure, authentication bypass): Patch within 72 hours
  - **High** (privilege escalation, data leakage): Patch within 1 week
  - **Medium** (denial of service, information disclosure): Patch within 2 weeks
  - **Low** (minor issues): Next scheduled release

### Severity Classification

| Severity | Examples |
|----------|----------|
| **Critical** | Private key extraction, share reconstruction bypass, authentication bypass allowing wallet access |
| **High** | Session hijacking, encryption downgrade, audit log tampering |
| **Medium** | Rate limit bypass, information disclosure (non-key material), DoS vectors |
| **Low** | Minor information leaks, cosmetic security issues |

### Safe Harbor

We consider security research conducted in good faith to be authorized. We will not pursue legal action against researchers who:

- Make a good faith effort to avoid privacy violations, data destruction, and service disruption
- Only interact with accounts you own or with explicit permission
- Report vulnerabilities promptly and do not exploit them beyond what is necessary to demonstrate the issue
- Do not publicly disclose the vulnerability before we've had reasonable time to address it

### Recognition

We maintain a Hall of Fame for security researchers who responsibly disclose vulnerabilities. With your permission, we'll credit you in our security advisories and CHANGELOG.

### Scope

The following are **in scope**:

- All Erebor crates (`erebor-auth`, `erebor-vault`, `erebor-aa`, `erebor-chain`, `erebor-gateway`, `erebor-common`)
- Docker images and deployment configurations
- Client SDKs (when released)
- Smart contracts (when deployed)

The following are **out of scope**:

- Third-party dependencies (report these upstream, but let us know)
- Social engineering attacks
- Denial of service via volumetric attacks
- Issues in development/test configurations that don't affect production

## Security Design Principles

Erebor is built on these non-negotiable security principles:

1. **No single compromise yields a key** — Server breach alone or device theft alone cannot expose private keys
2. **Key material is zeroed after use** — All secret types use the `zeroize` crate with drop semantics
3. **Envelope encryption** — Shares are encrypted with per-user derived keys (HKDF from master key)
4. **Audit trail** — Every key operation is logged immutably
5. **Rate limiting** — All authentication and signing endpoints are rate-limited
6. **Constant-time operations** — Cryptographic comparisons use constant-time implementations where applicable

## Cryptographic Choices

| Purpose | Algorithm | Notes |
|---------|-----------|-------|
| Key encryption at rest | AES-256-GCM | AEAD with per-user derived keys |
| Key derivation | HKDF-SHA256 | From master key + user context |
| Secret sharing | Shamir over GF(2^8) | Custom implementation, audited |
| Wallet derivation | BIP-32/44 | Standard HD wallet paths |
| JWT signing | HMAC-SHA256 | Short-lived (15min access tokens) |
| Password hashing | Argon2id | For any password-derived encryption |
| Signatures | ECDSA secp256k1 / EdDSA Ed25519 | Chain-specific |
