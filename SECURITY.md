# Security Policy

## Reporting a Vulnerability

**Do not open public GitHub issues for security vulnerabilities.**

Erebor handles private key material. If you discover a security issue, please report it responsibly.

### How to Report

Email the maintainers with:

1. **Description** of the vulnerability
2. **Steps to reproduce** (proof of concept if possible)
3. **Potential impact** (key leakage, auth bypass, etc.)
4. **Suggested fix** (optional but appreciated)

### Response Timeline

| Timeframe | Action |
|-----------|--------|
| 48 hours | Acknowledgement of report |
| 7 days | Initial assessment shared |
| 30 days | Fix developed and tested |
| 45 days | Coordinated public disclosure |

## Scope

### In Scope

- Private key or seed leakage
- Shamir secret sharing implementation flaws
- AES-256-GCM encryption weaknesses (nonce reuse, key derivation issues)
- JWT forgery or authentication bypass
- Session hijacking or refresh token vulnerabilities
- Memory safety issues
- Timing or side-channel attacks on cryptographic operations
- Rate limiting bypass
- Audit log tampering or deletion

### Out of Scope

- Denial of service via resource exhaustion
- Vulnerabilities in upstream dependencies (report upstream, but notify us)
- Social engineering

## Security Design

Erebor's security model is documented in detail:

- **Shamir 2-of-3** — No single compromise yields a key
- **Envelope encryption** — AES-256-GCM with per-user HKDF-derived keys
- **Zeroize** — All secret material zeroed from memory after use
- **Refresh token rotation** — Detect and respond to token theft
- **Rate limiting** — Token bucket per IP on all endpoints
- **Immutable audit trail** — Every key operation logged

See the [Architecture documentation](docs/src/architecture/security-model.md) for the full threat model.

## Supported Versions

| Version | Supported |
|---------|-----------|
| 0.1.x | ✅ |

## Credit

We credit security researchers in our release notes and CHANGELOG unless they prefer to remain anonymous.
