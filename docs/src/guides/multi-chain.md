# Multi-Chain Support

Erebor derives wallet keys for multiple chains from a single seed. This guide explains how multi-chain wallet management works.

## One Seed, Many Chains

Erebor uses BIP-32/44 hierarchical deterministic derivation. A single 32-byte seed produces keys for every supported chain:

```
Seed (32 bytes, stored as Shamir shares)
  │
  │  BIP-44 derivation paths
  │
  ├── m/44'/60'/0'/0/0  → Ethereum (secp256k1)
  │                        Same address on: Base, Polygon, Arbitrum, Optimism
  │
  ├── m/44'/60'/0'/0/1  → Ethereum account #2
  │
  └── m/44'/501'/0'/0'  → Solana (Ed25519)
```

### EVM Chains Share Addresses

All EVM-compatible chains use secp256k1 keys and the same address derivation (Keccak-256 of public key). This means:

- `0x7e5f...` on Ethereum = `0x7e5f...` on Base = `0x7e5f...` on Polygon
- One key signs transactions for all EVM chains
- Chain ID in the transaction prevents cross-chain replay

### Solana Uses Different Cryptography

Solana uses Ed25519 instead of secp256k1:

```rust
// Different derivation path and key type
let sol_key = solana_keypair_from_seed(&seed)?;
// Returns: ed25519_dalek::SigningKey
```

The Solana address is the base58-encoded public key, completely different from the Ethereum address — but derived from the same seed.

## Supported Chains

### Currently Implemented

| Chain | Key Type | Derivation Path | Status |
|-------|----------|----------------|--------|
| Ethereum | secp256k1 | m/44'/60'/0'/0/n | ✅ Key derivation |
| Solana | Ed25519 | m/44'/501'/0'/0' | ✅ Key derivation |

### Planned (same key as Ethereum)

| Chain | Chain ID | Notes |
|-------|----------|-------|
| Base | 8453 | Same key, different RPC |
| Polygon | 137 | Same key, different gas model |
| Arbitrum | 42161 | Same key, ArbGas estimation |
| Optimism | 10 | Same key, L1 data fee |

## Using Multi-Chain Wallets

### Derive an Ethereum Address

```rust
use erebor_vault::key_derivation::{derive_ethereum_key, ethereum_address};

let seed = /* from vault reconstruction */;
let key = derive_ethereum_key(&seed, 0)?;  // account index 0
let addr = ethereum_address(&key.secret_key)?;
// "0x7e5f4552091a69125d5dfcb7b8c2659029395bdf"
```

### Derive Multiple Accounts

```rust
// Account 0
let key0 = derive_ethereum_key(&seed, 0)?;
let addr0 = ethereum_address(&key0.secret_key)?;

// Account 1 (different address, same seed)
let key1 = derive_ethereum_key(&seed, 1)?;
let addr1 = ethereum_address(&key1.secret_key)?;

assert_ne!(addr0, addr1);
```

### Sign for Any EVM Chain

```rust
use erebor_vault::key_derivation::secp256k1_sign;

// Same key works for any EVM chain
// The chain_id is encoded in the transaction, not the key
let signature = secp256k1_sign(&key.secret_key, &tx_hash)?;
```

### Derive a Solana Keypair

```rust
use erebor_vault::key_derivation::solana_keypair_from_seed;

let keypair = solana_keypair_from_seed(&seed)?;
let pubkey = keypair.verifying_key();
// Base58 encode for Solana address
```

## Adding New Chains

To add support for a new chain:

1. **Same curve as Ethereum (secp256k1)?** → Just add the chain to the chain service registry. The same key and address work.

2. **Different curve?** → Add a new derivation function in `key_derivation.rs`:

```rust
// Example: adding Cosmos (secp256k1 but different address format)
pub fn derive_cosmos_key(seed: &[u8], index: u32) -> Result<ExtendedPrivateKey> {
    derive_path(seed, &[
        44 + HARDENED_OFFSET,
        118 + HARDENED_OFFSET,  // Cosmos coin type
        HARDENED_OFFSET,
        0,
        index,
    ])
}

// Cosmos address = bech32(ripemd160(sha256(compressed_pubkey)))
pub fn cosmos_address(private_key: &[u8]) -> Result<String> {
    let pubkey = public_key_from_private(private_key)?;
    // bech32 encode with "cosmos" prefix
    todo!()
}
```

The beauty of HD derivation: adding a chain requires zero changes to key storage. The same Shamir shares protect the same seed, which derives keys for the new chain.
