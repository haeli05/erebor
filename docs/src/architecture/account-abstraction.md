# Account Abstraction

The `erebor-aa` crate provides ERC-4337 account abstraction — smart contract wallets with gasless transactions, session keys, and programmable permissions.

> **Status:** 🚧 Planned — module structure and interfaces are defined; implementation is in progress.

## What Account Abstraction Enables

| Feature | EOA (Raw Key) | Smart Account (AA) |
|---------|--------------|-------------------|
| Gas payment | User pays in ETH | Paymaster sponsors or user pays in ERC-20 |
| Batched txns | One at a time | Multiple in one transaction |
| Session keys | N/A | Temporary keys with limited permissions |
| Spending limits | N/A | On-chain daily/weekly caps |
| Recovery | Seed phrase | Social recovery on-chain |
| Upgradeable | No | Yes (proxy pattern) |

## Architecture

```
┌─────────────────────────────────────┐
│            AA Service               │
│                                     │
│  ┌───────────┐  ┌────────────────┐  │
│  │  Bundler  │  │   Paymaster    │  │
│  │           │  │                │  │
│  │ mempool   │  │ verifying      │  │
│  │ bundle    │  │ erc20          │  │
│  │ submit    │  │ sponsored      │  │
│  └───────────┘  └────────────────┘  │
│                                     │
│  ┌───────────┐  ┌────────────────┐  │
│  │  Wallet   │  │  Session Keys  │  │
│  │  Factory  │  │                │  │
│  │           │  │ permissions    │  │
│  │ CREATE2   │  │ allowlists     │  │
│  │ deploy    │  │ time bounds    │  │
│  └───────────┘  └────────────────┘  │
└─────────────────────────────────────┘
```

## ERC-4337 Overview

```
┌──────┐     ┌─────────┐     ┌────────────┐     ┌──────────┐
│Client│────►│ Bundler  │────►│ EntryPoint │────►│ Account  │
│      │     │          │     │ (on-chain) │     │(on-chain)│
└──────┘     └─────────┘     └────────────┘     └──────────┘
                  │                │
                  ▼                ▼
            ┌──────────┐    ┌──────────┐
            │ Mempool  │    │Paymaster │
            └──────────┘    └──────────┘
```

1. Client constructs a `UserOperation` — a struct describing the intended action
2. Bundler collects UserOps into a bundle
3. Bundler submits the bundle to the on-chain `EntryPoint` contract
4. EntryPoint validates each UserOp via the account's `validateUserOp`
5. If a paymaster is specified, it pays for gas

## Planned Module Structure

```
erebor-aa/src/
├── bundler.rs      # UserOperation mempool + bundling
├── paymaster.rs    # Gas sponsorship strategies
├── wallet.rs       # Smart account factory + deployment
└── lib.rs
```

## Bundler

The bundler manages a mempool of `UserOperation` structs and submits them to the EntryPoint:

```rust
pub struct UserOperation {
    pub sender: Address,
    pub nonce: U256,
    pub init_code: Bytes,        // Factory call for new accounts
    pub call_data: Bytes,        // Account.execute(...) payload
    pub call_gas_limit: U256,
    pub verification_gas: U256,
    pub pre_verification_gas: U256,
    pub max_fee_per_gas: U256,
    pub max_priority_fee: U256,
    pub paymaster_and_data: Bytes,
    pub signature: Bytes,
}
```

## Paymaster

Three paymaster strategies:

| Strategy | Description | Use Case |
|----------|-------------|----------|
| **Verifying** | Off-chain signature authorises gas sponsorship | App approves specific operations |
| **ERC-20** | User pays gas in stablecoins (USDC, DAI) | Users without ETH |
| **Sponsored** | App pays all gas | Onboarding, free tier |

## Smart Account

Deterministic deployment via CREATE2:

```
Account address = CREATE2(factory, salt, bytecode_hash)
```

The address is known before deployment — users can receive funds at their smart account address before the account contract exists on-chain.

## Session Keys

Temporary keys with scoped permissions:

```
SessionKey {
    public_key: Address,
    valid_after: u64,         // Unix timestamp
    valid_until: u64,
    spending_limit: U256,     // Max ETH per session
    allowed_contracts: [Address],
    allowed_functions: [bytes4],
}
```

Session keys enable:
- **Gaming** — sign in-game transactions without wallet popups
- **Subscriptions** — approve recurring payments up to a limit
- **DeFi** — allow specific contract interactions for a limited time

## Integration with Key Vault

The AA service uses the Key Vault for signing:

```
Client ──► AA Service ──► Key Vault (sign UserOp hash)
                │
                ▼
           Bundler ──► EntryPoint (on-chain)
```

The EOA key from the vault acts as the **owner** of the smart account. The smart account's `validateUserOp` checks that the UserOp was signed by the owner.
