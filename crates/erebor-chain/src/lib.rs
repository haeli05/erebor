pub mod broadcast;
pub mod chains;
pub mod gas;
pub mod rpc;
pub mod signer;
pub mod tx;

// Re-exports for convenience
pub use broadcast::{Broadcaster, EvmBroadcaster, SolanaBroadcaster, TransactionReceipt, TransactionStatus, TxHash};
pub use chains::{ChainConfig, ChainRegistry, ChainType, NativeCurrency};
pub use gas::{Eip1559GasOracle, GasEstimate, GasEstimator, GasOracle, LegacyGasOracle, TransactionRequest};
pub use rpc::{EvmRpcClient, RpcClient, RpcPool, SolanaRpcClient};
pub use signer::{EvmSigner, SecretBytes, SolanaSigner, TransactionSigner};
pub use tx::{
    Eip1559Transaction, LegacyTransaction, NonceManager, SignedTransaction, 
    TransactionBuilder, TransactionRequest as TxRequest, UnsignedTransaction
};

use std::collections::HashMap;
use std::sync::{Arc, RwLock};

use crate::broadcast::BroadcastError;
use crate::tx::TxError;

/// Top-level chain service — wires together registry, RPC pools, and gas estimation.
pub struct ChainService {
    pub registry: ChainRegistry,
    pools: Arc<RwLock<HashMap<u64, Arc<RpcPool>>>>,
    pub gas_estimator: GasEstimator,
    pub tx_builder: tx::TransactionBuilder,
    pub nonce_manager: Arc<RwLock<tx::NonceManager>>,
    pub evm_signer: signer::EvmSigner,
    pub evm_broadcaster: broadcast::EvmBroadcaster,
}

impl ChainService {
    /// Create a new ChainService with default registry and gas estimator.
    pub fn new() -> Self {
        Self::with_safety_margin(1.2)
    }

    /// Create with a custom gas safety margin.
    pub fn with_safety_margin(safety_margin: f64) -> Self {
        let evm_broadcaster = broadcast::EvmBroadcaster::new();
        
        Self {
            registry: ChainRegistry::new(),
            pools: Arc::new(RwLock::new(HashMap::new())),
            gas_estimator: GasEstimator::new(safety_margin),
            tx_builder: tx::TransactionBuilder::new(),
            nonce_manager: Arc::new(RwLock::new(tx::NonceManager::new())),
            evm_signer: signer::EvmSigner::new(),
            evm_broadcaster,
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

        // Add pool to broadcaster if it's an EVM chain
        if config.chain_type == ChainType::Evm {
            self.evm_broadcaster.add_pool(chain_id, Arc::clone(&pool));
        }

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

    /// Estimate gas for a transaction request.
    pub async fn estimate_transaction(
        &self,
        chain_id: u64,
        request: &tx::TransactionRequest,
    ) -> Result<GasEstimate, TxError> {
        let config = self.registry.get_chain(chain_id)?;
        let pool = self.get_pool(chain_id)?;
        
        // Convert tx::TransactionRequest to gas::TransactionRequest
        let gas_request = gas::TransactionRequest {
            from: None, // Gas estimation doesn't need from address
            to: request.to.clone(),
            value: request.value,
            data: request.data.clone(),
        };
        
        if config.supports_eip1559 {
            let oracle = gas::Eip1559GasOracle::new();
            self.gas_estimator.estimate(&pool, &oracle, Some(&gas_request)).await.map_err(Into::into)
        } else {
            let oracle = gas::LegacyGasOracle;
            self.gas_estimator.estimate(&pool, &oracle, Some(&gas_request)).await.map_err(Into::into)
        }
    }

    /// Sign and send a transaction in one operation.
    pub async fn sign_and_send(
        &self,
        chain_id: u64,
        from_address: &str,
        request: &tx::TransactionRequest,
        private_key: &SecretBytes,
    ) -> Result<TxHash, Box<dyn std::error::Error + Send + Sync>> {
        // Estimate gas
        let gas_estimate = self.estimate_transaction(chain_id, request).await?;
        
        // Get next nonce
        let nonce = {
            let mut nonce_mgr = self.nonce_manager.write().unwrap();
            nonce_mgr.next_nonce(chain_id, from_address)
        };
        
        // Build unsigned transaction
        let unsigned_tx = self.tx_builder.build_transaction(request, &gas_estimate, nonce)?;
        
        // Sign transaction
        let signed_tx = self.evm_signer.sign_transaction(&unsigned_tx, private_key)?;
        
        // Broadcast transaction
        let tx_hash = self.evm_broadcaster.broadcast(&signed_tx).await?;
        
        // Confirm nonce was used
        {
            let mut nonce_mgr = self.nonce_manager.write().unwrap();
            nonce_mgr.confirm_nonce(chain_id, from_address, nonce);
        }
        
        Ok(tx_hash)
    }

    /// Get the status of a transaction.
    pub async fn get_transaction_status(
        &self,
        tx_hash: &TxHash,
    ) -> Result<TransactionStatus, BroadcastError> {
        match self.evm_broadcaster.get_receipt(tx_hash).await? {
            Some(receipt) => Ok(TransactionStatus::Confirmed(receipt)),
            None => Ok(TransactionStatus::Pending),
        }
    }

    /// Sync nonce manager with chain state for an address.
    #[allow(clippy::await_holding_lock)] // TODO: Use tokio::sync::RwLock for async compatibility
    pub async fn sync_nonce(
        &self,
        chain_id: u64,
        address: &str,
    ) -> Result<u64, TxError> {
        let client = self.evm_client(chain_id)?;
        let mut nonce_mgr = self.nonce_manager.write().unwrap();
        nonce_mgr.sync_from_chain(chain_id, address, &client).await
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
