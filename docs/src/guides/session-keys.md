# Session Keys

> **Status:** 🚧 Planned — Session keys will be implemented as part of the Account Abstraction module (Phase 2).

Session keys are temporary, limited-permission keys that allow dApps to execute transactions on behalf of users without requiring approval for every action.

## Concept

Instead of granting a dApp full access to your wallet, you create a session key with specific permissions:

```
Main Wallet Key (in vault)
       │
       │ delegates to
       ▼
Session Key: 0xabc...
├── Allowed contracts: [0xUniswapRouter, 0xAavePool]
├── Allowed functions: [swap, supply, withdraw]
├── Spending limit: 0.5 ETH per day
├── Valid: 2026-02-17 to 2026-02-18
└── Revocable: instantly by main key
```

## How It Works

### 1. Create Session Key

User approves a session key with specific permissions:

```typescript
// React SDK (planned)
const session = await erebor.createSessionKey({
  permissions: {
    contracts: ['0xUniswapRouter'],
    functions: ['exactInputSingle', 'exactOutputSingle'],
    spendLimit: {
      amount: '0.5',
      token: 'ETH',
      period: 'day',
    },
  },
  validUntil: new Date(Date.now() + 24 * 60 * 60 * 1000), // 24 hours
});
```

### 2. Use Session Key

The dApp uses the session key to sign UserOperations:

```typescript
// Sign with session key (no user prompt needed)
const tx = await erebor.sendTransaction({
  to: '0xUniswapRouter',
  data: swapCalldata,
  sessionKey: session.key,
});
```

### 3. On-Chain Validation

The smart account's session key validator module checks:

1. Is this session key registered and not revoked?
2. Is the target contract in the allowlist?
3. Is the function selector in the allowlist?
4. Is the value within the spending limit?
5. Is the session still valid (not expired)?

### 4. Revoke Session Key

```typescript
await erebor.revokeSessionKey(session.id);
// Instant — on-chain revocation
```

## Use Cases

| Use Case | Session Key Config |
|----------|-------------------|
| DEX trading bot | Contracts: DEX router. Functions: swap. Limit: $1000/day. Duration: 30 days. |
| NFT minting | Contracts: NFT contract. Functions: mint. Limit: 1 ETH. Duration: 1 hour. |
| Gaming | Contracts: game contract. Functions: all. Limit: $10/day. Duration: session. |
| DCA (dollar-cost averaging) | Contracts: DEX. Functions: swap. Limit: $100/week. Duration: 90 days. |

## Permission Types

### Contract Allowlist

Restrict which contracts the session key can interact with:

```solidity
mapping(address => bool) public allowedContracts;
```

### Function Allowlist

Restrict which function selectors are permitted:

```solidity
mapping(bytes4 => bool) public allowedFunctions;
```

### Spending Limits

On-chain enforcement of value transfer caps:

```solidity
struct SpendingPolicy {
    uint256 limit;        // Max spend per period
    uint256 spent;        // Amount spent in current period
    uint256 periodStart;  // When the current period began
    uint256 periodLength; // Period duration in seconds
}
```

### Time Bounds

Session keys automatically expire:

```solidity
uint48 public validAfter;
uint48 public validUntil;
```

## ERC-7715 Compatibility

Erebor's session key implementation follows the [ERC-7715](https://eips.ethereum.org/EIPS/eip-7715) standard for wallet permission grants, ensuring compatibility with the broader ecosystem.
