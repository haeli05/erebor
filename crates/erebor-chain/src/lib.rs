pub mod chains;
pub mod gas;
pub mod rpc;

// Re-exports for convenience
pub use chains::{ChainConfig, ChainRegistry, ChainType, NativeCurrency};
pub use gas::{Eip1559GasOracle, GasEstimate, GasEstimator, GasOracle, LegacyGasOracle, TransactionRequest};
pub use rpc::{EvmRpcClient, RpcClient, RpcPool, SolanaRpcClient};

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

/// Top-level chain service — wires together registry, RPC pools, and gas estimation.
pub struct ChainService {
    pub registry: ChainRegistry,
    pools: Arc<RwLock<HashMap<u64, Arc<RpcPool>>>>,
    pub gas_estimator: GasEstimator,
}

impl ChainService {
    /// Create a new ChainService with default registry and gas estimator.
    pub fn new() -> Self {
        Self::with_safety_margin(1.2)
    }

    /// Create with a custom gas safety margin.
    pub fn with_safety_margin(safety_margin: f64) -> Self {
        Self {
            registry: ChainRegistry::new(),
            pools: Arc::new(RwLock::new(HashMap::new())),
            gas_estimator: GasEstimator::new(safety_margin),
        }
    }

    /// Get or create an RPC pool for a given chain.
    pub fn get_pool(&self, chain_id: u64) -> Result<Arc<RpcPool>, chains::ChainError> {
        // Check if pool already exists
        {
            let pools = self.pools.read().unwrap();
            if let Some(pool) = pools.get(&chain_id) {
                return Ok(Arc::clone(pool));
            }
        }

        // Create a new pool from registry config
        let config = self.registry.get_chain(chain_id)?;
        let pool = Arc::new(RpcPool::new(chain_id, config.rpc_urls));

        let mut pools = self.pools.write().unwrap();
        pools.insert(chain_id, Arc::clone(&pool));
        Ok(pool)
    }

    /// Get an EVM RPC client for a chain.
    pub fn evm_client(&self, chain_id: u64) -> Result<EvmRpcClient, chains::ChainError> {
        let pool = self.get_pool(chain_id)?;
        Ok(EvmRpcClient::new(pool))
    }

    /// Get a Solana RPC client.
    pub fn solana_client(&self, chain_id: u64) -> Result<SolanaRpcClient, chains::ChainError> {
        let pool = self.get_pool(chain_id)?;
        Ok(SolanaRpcClient::new(pool))
    }
}

impl Default for ChainService {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_chain_service_creation() {
        let svc = ChainService::new();
        assert!(svc.registry.get_chain(1).is_ok());
        assert!(svc.registry.get_chain(8453).is_ok());
    }

    #[test]
    fn test_chain_service_pool_creation() {
        let svc = ChainService::new();
        let pool = svc.get_pool(1).unwrap();
        // Same pool returned on second call
        let pool2 = svc.get_pool(1).unwrap();
        assert!(Arc::ptr_eq(&pool, &pool2));
    }

    #[test]
    fn test_chain_service_unknown_chain() {
        let svc = ChainService::new();
        assert!(svc.get_pool(999999).is_err());
    }

    #[test]
    fn test_evm_client_creation() {
        let svc = ChainService::new();
        let _client = svc.evm_client(1).unwrap();
        let _client = svc.evm_client(137).unwrap();
    }
}
