# Chain Service

The `erebor-chain` crate abstracts multi-chain complexity — RPC connection management, gas estimation, and chain configuration.

> **Status:** 🚧 Planned — module interfaces are defined; implementation is in progress.

## Purpose

Applications shouldn't need to manage RPC endpoints, handle failover, or estimate gas across different chains. The chain service provides a unified interface.

## Module Structure

```
erebor-chain/src/
├── rpc.rs       # RPC connection pool with failover
├── gas.rs       # Gas estimation (EIP-1559 aware)
├── chains.rs    # Chain registry and configuration
└── lib.rs
```

## RPC Connection Pool

```rust
pub struct RpcPool {
    endpoints: Vec<RpcEndpoint>,
    strategy: LoadBalanceStrategy,
}

pub struct RpcEndpoint {
    pub url: String,
    pub chain_id: u64,
    pub priority: u8,
    pub max_requests_per_second: u32,
}

pub enum LoadBalanceStrategy {
    RoundRobin,
    Priority,      // Use highest-priority endpoint first
    Failover,      // Try in order, skip failures
    LowestLatency, // Track response times, prefer fastest
}
```

Features:
- **Automatic failover** — if an RPC endpoint is down, route to the next
- **Rate limiting** — respect per-endpoint request limits
- **Response caching** — cache block data, gas prices (short TTL)
- **Health checks** — periodic liveness probes

## Gas Estimation

```rust
pub struct GasEstimate {
    pub gas_limit: u64,
    pub max_fee_per_gas: u64,       // EIP-1559
    pub max_priority_fee: u64,      // EIP-1559
    pub estimated_cost_wei: u128,
    pub estimated_cost_usd: Option<f64>,
}

pub trait GasEstimator {
    async fn estimate(&self, chain_id: u64, tx: &TransactionRequest) -> Result<GasEstimate>;
}
```

The gas estimator:
1. Fetches the latest base fee from the chain
2. Samples recent priority fees
3. Applies a safety margin (default: 20%)
4. Optionally converts to USD via price oracle

## Chain Registry

```rust
pub struct ChainConfig {
    pub chain_id: u64,
    pub name: String,
    pub native_currency: String,
    pub rpc_urls: Vec<String>,
    pub explorer_url: Option<String>,
    pub is_testnet: bool,
}
```

Built-in chains:

| Chain | ID | Currency |
|-------|----|----------|
| Ethereum | 1 | ETH |
| Base | 8453 | ETH |
| Polygon | 137 | MATIC |
| Arbitrum | 42161 | ETH |
| Optimism | 10 | ETH |
| Solana | — | SOL |

Custom chains can be added via configuration.

## Configuration

```bash
# Per-chain RPC endpoints
ETH_RPC_URL=https://eth-mainnet.g.alchemy.com/v2/YOUR_KEY
BASE_RPC_URL=https://base-mainnet.g.alchemy.com/v2/YOUR_KEY
POLYGON_RPC_URL=https://polygon-mainnet.g.alchemy.com/v2/YOUR_KEY

# Fallback endpoints (comma-separated)
ETH_RPC_FALLBACK=https://rpc.ankr.com/eth,https://ethereum.publicnode.com
```

## Planned Features

- **Event indexing** — listen for wallet activity (transfers, approvals)
- **Token balance tracking** — aggregate ERC-20 balances across chains
- **Transaction status** — track pending transactions with receipt polling
- **Nonce management** — prevent nonce collisions for concurrent transactions
