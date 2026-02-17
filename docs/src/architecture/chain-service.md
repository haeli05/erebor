# Chain Service

The `erebor-chain` crate abstracts multi-chain complexity — RPC connection management, gas estimation, transaction handling, and multi-chain signing.

## Purpose

Applications shouldn't need to manage RPC endpoints, handle failover, or estimate gas across different chains. The chain service provides a unified interface.

## Module Structure

```
erebor-chain/src/
├── lib.rs        # ChainService main API
├── gas.rs        # Gas estimation (EIP-1559 + legacy)
├── tx.rs         # Transaction building and handling
├── signer.rs     # Multi-curve signing (secp256k1, Ed25519)
└── broadcast.rs  # RPC pooling and transaction broadcasting
```

## RPC Connection Pool

The `RpcPool` provides connection pooling and failover for blockchain RPC endpoints:

```rust
pub struct RpcPool {
    chain_id: u64,
    endpoints: Vec<String>,
    client: reqwest::Client,
}

impl RpcPool {
    pub fn new(chain_id: u64, endpoints: Vec<String>) -> Self;
    pub async fn call(&self, method: &str, params: &[serde_json::Value]) -> Result<JsonRpcResponse, RpcError>;
}
```

The pool automatically handles:
- **Endpoint failover** — if one RPC fails, try the next in the list
- **Retry logic** — exponential backoff for transient failures
- **Request routing** — distributes load across available endpoints

Separate client types for EVM and Solana:
```rust
let evm_client = EvmRpcClient::new(pool);
let receipt = evm_client.get_transaction_receipt(&tx_hash).await?;

let solana_client = SolanaRpcClient::new(pool);
let balance = solana_client.get_balance(&pubkey).await?;
```

## Gas Estimation

Erebor supports both EIP-1559 (type 2) and legacy (type 0) gas estimation:

```rust
pub struct GasEstimate {
    pub max_fee_per_gas: u128,
    pub max_priority_fee_per_gas: Option<u128>, // None for legacy transactions
    pub gas_limit: u64,
    pub is_eip1559: bool,
}

pub struct GasEstimator {
    safety_margin: f64, // Default 1.2 (20% margin)
}
```

The estimation process:
1. **Detect EIP-1559 support** — checks if the chain supports type 2 transactions
2. **For EIP-1559 chains:**
   - Uses `eth_feeHistory` to analyze recent blocks
   - Calculates median priority fees from recent transactions
   - Sets `max_fee_per_gas = base_fee * 2 + priority_fee` (with safety margin)
3. **For legacy chains:**
   - Uses `eth_gasPrice` RPC call
   - Applies safety margin to the returned gas price
4. **Gas limit estimation** — uses `eth_estimateGas` for transaction simulation

Two oracle implementations:
```rust
// EIP-1559 oracle (default for Ethereum, Base, etc.)
let eip1559_oracle = Eip1559GasOracle::new();

// Legacy oracle (for older chains or L2s without EIP-1559)
let legacy_oracle = LegacyGasOracle::new();
```

## Transaction Signing Pipeline

The chain service handles the complete transaction lifecycle from building to broadcasting:

### Multi-Curve Signing

Erebor supports both secp256k1 (EVM) and Ed25519 (Solana) signature schemes:

```rust
// EVM transaction signing (secp256k1)
let evm_signer = EvmSigner::new();
let signed_tx = evm_signer.sign_transaction(&unsigned_tx, &private_key)?;

// Solana transaction signing (Ed25519)
let solana_signer = SolanaSigner::new();
let signature = solana_signer.sign_message(&message, &keypair)?;
```

The signing process:
1. **Transaction encoding** — RLP encoding for EVM, Borsh for Solana
2. **Hash computation** — Keccak256 for EVM transactions
3. **Signature generation** — ECDSA for EVM, EdDSA for Solana
4. **Recovery ID** — Includes chain ID for EIP-155 replay protection

### Nonce Management

The `NonceManager` prevents nonce collisions in concurrent transactions:

```rust
pub struct NonceManager {
    nonces: HashMap<(u64, String), u64>, // (chain_id, address) -> next_nonce
}

impl NonceManager {
    pub async fn get_nonce(&mut self, chain_id: u64, address: &str) -> u64;
    pub fn increment_nonce(&mut self, chain_id: u64, address: &str);
    pub async fn sync_nonce(&mut self, chain_id: u64, address: &str, pool: &RpcPool);
}
```

Features:
- **Local tracking** — maintains next nonce for each address per chain
- **Periodic sync** — fetches on-chain nonce to detect external transactions
- **Collision prevention** — sequential nonce allocation for concurrent signings

### Transaction Broadcasting

The `EvmBroadcaster` handles submission and receipt tracking:

```rust
pub enum TransactionStatus {
    Pending,
    Confirmed { block_number: u64, gas_used: u64 },
    Failed { error: String },
    Dropped,
}

let receipt = broadcaster.submit_and_wait(&signed_tx, chain_id).await?;
```

Broadcasting pipeline:
1. **Submit** — `eth_sendRawTransaction` to the RPC pool
2. **Track** — poll for receipt using `eth_getTransactionReceipt`
3. **Retry** — resubmit with higher gas if stuck
4. **Timeout** — return error after configurable timeout

## Chain Registry

The `ChainRegistry` manages chain configurations and provides a unified interface across EVM and Solana networks:

```rust
pub struct ChainConfig {
    pub chain_id: u64,
    pub name: String,
    pub chain_type: ChainType,
    pub rpc_urls: Vec<String>,
    pub native_currency: NativeCurrency,
    pub block_explorer: Option<String>,
    pub is_testnet: bool,
    pub supports_eip1559: bool,
}

pub enum ChainType {
    Evm,
    Solana,
}
```

Built-in chains:

| Chain | ID | Type | Currency | EIP-1559 |
|-------|----|----- |----------|----------|
| Ethereum | 1 | EVM | ETH | ✅ |
| Base | 8453 | EVM | ETH | ✅ |
| Polygon | 137 | EVM | POL | ✅ |
| Arbitrum One | 42161 | EVM | ETH | ✅ |
| Optimism | 10 | EVM | ETH | ✅ |
| Sepolia | 11155111 | EVM | ETH (testnet) | ✅ |
| Solana | 900001 | Solana | SOL | ❌ |

Custom chains can be added dynamically:

```rust
let registry = ChainRegistry::new();
let custom_chain = ChainConfig {
    chain_id: 31337,
    name: "Hardhat Local".into(),
    chain_type: ChainType::Evm,
    rpc_urls: vec!["http://127.0.0.1:8545".into()],
    // ... other fields
};
registry.add_custom_chain(custom_chain)?;
```

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
