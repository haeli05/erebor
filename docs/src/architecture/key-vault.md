# Key Vault

The key vault (`erebor-vault`) is the most security-critical module in Erebor. It generates, splits, encrypts, stores, and reconstructs private keys. Its fundamental guarantee: **no single compromise yields a key**.

## The Core Problem

Users need wallets. Users lose devices. Users don't write down seed phrases. The private key must be:

1. **Usable** — User can sign transactions without friction
2. **Recoverable** — User can regain access if they lose a device
3. **Non-custodial** — No single entity (including the server operator) can access the key unilaterally
4. **Secure at rest** — Even a full database compromise doesn't leak keys

## Key Management Strategies

### Shamir Secret Sharing (Implemented ✅)

The default strategy. Splits secrets into N shares with threshold T (default: 2-of-3):

```
┌──────────┐     ┌──────────┐     ┌──────────┐
│  Share 1 │     │  Share 2 │     │  Share 3 │
│ (server) │     │ (device) │     │(recovery)│
│ encrypted│     │ encrypted│     │ encrypted│
└──────────┘     └──────────┘     └──────────┘
      │                │                │
      └────── any 2 ──────────────────┘
                   │
              Reconstruct
                   │
              ┌─────────┐
              │  Seed   │
              │ (zeroed │
              │  after  │
              │  use)   │
              └─────────┘
```

**Implementation:** Custom Shamir over GF(2^8) using the AES irreducible polynomial:

```rust
// Split a 32-byte seed into 3 shares, any 2 can reconstruct
let vault = ShamirVault::new(2, 3)?;
let shares = vault.split(&seed)?;

// Reconstruct from any 2 shares
let recovered = vault.reconstruct(&[shares[0].clone(), shares[2].clone()])?;
assert_eq!(recovered.0, seed);
```

The GF(2^8) arithmetic ensures:
- Any `t` shares reconstruct the secret perfectly
- Any `t-1` shares reveal zero information about the secret
- Works byte-by-byte, supporting arbitrary-length secrets

### MPC-TSS (Planned 🚧)

Threshold signatures via CGGMP21 — the key **never exists in full anywhere**. Each party holds a share and participates in a distributed signing protocol. More secure than Shamir (no key reconstruction), but requires interactive protocol.

### TEE-Backed (Planned 🚧)

Keys generated and used inside a Trusted Execution Environment (AWS Nitro, Intel SGX). Even the server operator can't extract keys. Fastest signing, but requires hardware trust.

## Encryption

Shares are encrypted at rest using **AES-256-GCM** with per-user derived keys:

```
Master Key (from env/KMS)
       │
       │ HKDF-SHA256
       │ context = user_id bytes
       ▼
  Per-User DEK
       │
       │ AES-256-GCM
       │ random 12-byte nonce
       ▼
  Encrypted Share + Nonce
```

```rust
let encryption = EncryptionService::new(SecretBytes(master_key));

// Encrypt with user-specific derived key
let (ciphertext, nonce) = encryption.encrypt(&share_data, user_id.as_bytes())?;

// Decrypt
let plaintext = encryption.decrypt(&ciphertext, &nonce, user_id.as_bytes())?;
```

**Security properties:**
- Each user gets a unique data encryption key derived via HKDF
- Random 12-byte nonce per encryption (never reused)
- GCM provides authentication — tampered ciphertext is detected
- Different users' shares are encrypted with different keys — compromising one user's DEK doesn't affect others

## HD Wallet Derivation

Erebor uses BIP-32/44 hierarchical deterministic wallets. A single seed derives keys for all chains:

```
Seed (32 bytes)
  │
  ├── m/44'/60'/0'/0/0  → Ethereum address #0
  ├── m/44'/60'/0'/0/1  → Ethereum address #1
  ├── m/44'/501'/0'/0'  → Solana address
  └── ...               → Any chain
```

```rust
// Derive Ethereum key from seed
let eth_key = derive_ethereum_key(&seed, 0)?;
let address = ethereum_address(&eth_key.secret_key)?;
// "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"

// Derive Solana keypair
let sol_key = solana_keypair_from_seed(&seed)?;
```

The implementation passes BIP-32 test vectors from the specification.

## Wallet Lifecycle

### Creation

```rust
let vault = VaultService::new(shamir, encryption, store);
let info = vault.create_wallet(&user_id).await?;
// WalletInfo { ethereum_address: "0x...", share_indices: [1, 2, 3] }
```

Internally:
1. Generate 32 random bytes (seed)
2. Derive Ethereum key via BIP-44 path
3. Split seed into 3 Shamir shares
4. Encrypt each share with user-specific key
5. Store encrypted shares
6. **Zeroize** seed from memory
7. Log to audit trail

### Transaction Signing

```rust
let signature = vault.sign_transaction(&user_id, &[1, 2], &tx_hash).await?;
```

1. Retrieve encrypted shares for requested indices
2. Decrypt shares with user-specific key
3. Reconstruct seed via Lagrange interpolation
4. Derive signing key for the target chain
5. Sign the transaction hash
6. **Zeroize** seed and key material
7. Return signature

### Share Rotation

Proactive share refresh without changing the underlying key:

```rust
let new_indices = vault.rotate_shares(&user_id).await?;
```

1. Decrypt enough shares to reconstruct
2. Reconstruct seed
3. Re-split with fresh random coefficients
4. Encrypt and store new shares
5. Atomically replace old shares
6. **Zeroize** all intermediate material

After rotation, old compromised shares become useless. The underlying key remains unchanged, so the wallet address doesn't change.

### Recovery Export

Export a share encrypted with a user-chosen password for backup:

```rust
let backup = vault.export_recovery_share(&user_id, share_index, password).await?;
// Returns: nonce || ciphertext (encrypted with password-derived key)
```

## Audit Trail

Every key operation is logged:

```rust
pub enum KeyOperation {
    CreateWallet,
    StoreShare,
    RetrieveShare,
    RotateShares,
    SignTransaction,
    ExportRecoveryShare,
    DeleteShares,
}
```

Each entry includes: user ID, operation type, timestamp, and details. The log is append-only — entries cannot be modified or deleted.

## Security Invariants

These must always hold:

1. **No single compromise yields a key** — Server DB breach → encrypted shares, useless without the master key. Master key compromise → can decrypt shares, but each share alone is useless without meeting the threshold.
2. **Key material is zeroed after use** — All `SecretBytes` types implement `Zeroize` with drop semantics. Seeds and keys exist in memory only briefly during signing.
3. **Unique nonces** — Every encryption uses a fresh random 12-byte nonce. Nonce reuse with AES-GCM would be catastrophic.
4. **Audit everything** — Every key operation is logged with timestamp and context.
