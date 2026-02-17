# Key Management Guide

This guide explains how Erebor manages cryptographic keys and how to operate the key vault securely.

## How Keys Work in Erebor

When a user creates a wallet, Erebor:

1. **Generates** a 32-byte random seed
2. **Derives** chain-specific keys from the seed (BIP-32/44)
3. **Splits** the seed into shares (Shamir 2-of-3)
4. **Encrypts** each share with a user-specific key (AES-256-GCM)
5. **Stores** the encrypted shares
6. **Zeroes** all key material from memory

The seed is the master secret. From it, keys for Ethereum, Solana, and any other chain can be derived deterministically.

## Share Distribution

Default 2-of-3 setup:

| Share | Location | Purpose |
|-------|----------|---------|
| Share 1 | Erebor server (encrypted) | Available for every sign operation |
| Share 2 | User's device | Provided by client SDK during signing |
| Share 3 | Recovery backup | Used only when device is lost |

Any two shares can reconstruct the seed. No single share reveals anything about the key.

## Master Key Management

The `VAULT_MASTER_KEY` encrypts all server-side shares. It's the most important secret in the system.

### Development

```bash
# Generate and set in .env
VAULT_MASTER_KEY=$(openssl rand -hex 32)
```

### Production Options

**AWS KMS:**
```bash
# Create a KMS key
aws kms create-key --description "Erebor master key"

# Use the KMS key ARN
VAULT_MASTER_KEY_SOURCE=aws_kms
VAULT_KMS_KEY_ARN=arn:aws:kms:us-east-1:123456789:key/abc-123
```

**GCP KMS:**
```bash
VAULT_MASTER_KEY_SOURCE=gcp_kms
VAULT_KMS_KEY_NAME=projects/myproject/locations/us/keyRings/erebor/cryptoKeys/master
```

**HashiCorp Vault:**
```bash
VAULT_MASTER_KEY_SOURCE=hashicorp_vault
VAULT_HC_ADDR=https://vault.internal:8200
VAULT_HC_PATH=secret/data/erebor/master-key
```

## Share Rotation

Periodically re-split the seed with fresh randomness. Old shares become useless.

```rust
// Programmatic rotation
let new_indices = vault.rotate_shares(&user_id).await?;
```

**Why rotate?**
- If a share was compromised at some point, rotation invalidates it
- Fresh randomness strengthens the security of current shares
- The underlying key (and wallet address) doesn't change

**Rotation schedule:**
- Minimum: quarterly
- Recommended: monthly for high-value wallets
- On demand: after any suspected compromise

## Recovery Flows

### Lost Device

User still has server access (can authenticate via email/OAuth):

1. User authenticates → server provides Share 1
2. User retrieves recovery backup → provides Share 3
3. Two shares reconstruct the seed
4. New Share 2 generated for the new device
5. Old Share 2 invalidated via rotation

### Lost Server Access

Server goes down but user has their device:

1. Share 2 from device + Share 3 from recovery backup
2. Two shares reconstruct the seed
3. User can export the raw private key
4. Re-deploy server, create new shares

### Both Device and Server Compromised (at different times)

This is why rotation matters:

- If Share 1 was leaked from server in January
- And Share 2 was leaked from device in March
- But shares were rotated in February
- The January Share 1 and March Share 2 are from **different** sets
- They cannot be combined — the rotation created a new polynomial

## Signing Operations

Transaction signing is a brief, secure process:

```
1. Client sends sign request with JWT
2. Server retrieves encrypted Share 1
3. Client provides Share 2 (encrypted in transit)
4. Server decrypts both shares
5. Lagrange interpolation reconstructs seed
6. BIP-44 derives the signing key
7. ECDSA signs the transaction hash
8. All key material is zeroed
9. Signature returned to client
```

The seed exists in memory for milliseconds during signing.

## Audit Trail

Every key operation is logged:

```json
{
  "id": "550e8400-...",
  "user_id": "7c9e6679-...",
  "operation": "SignTransaction",
  "timestamp": "2026-02-17T03:41:00Z",
  "details": "Signed tx 0xabcdef..."
}
```

Monitor the audit log for:
- Unusual signing frequency
- Sign operations at unexpected hours
- Multiple failed reconstruction attempts
- Rotation requests from unexpected sources

## Best Practices

1. **Use KMS in production** — Don't store the master key in an environment variable on the server
2. **Rotate shares regularly** — Monthly minimum
3. **Monitor audit logs** — Set up alerts for anomalous patterns
4. **Test recovery** — Periodically verify that recovery flows work
5. **Separate backups** — Don't store recovery shares in the same location as server shares
6. **Rate limit signing** — Prevent rapid-fire signing from a compromised session
