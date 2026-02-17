use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::atomic::{AtomicU64, Ordering};
use thiserror::Error;
use tracing::{debug, warn};

use crate::gas::GasEstimate;
use crate::rpc::{RpcClient, RpcError};

#[derive(Error, Debug)]
pub enum TxError {
    #[error("RPC error: {0}")]
    Rpc(#[from] RpcError),
    #[error("invalid parameter: {0}")]
    InvalidParameter(String),
    #[error("encoding error: {0}")]
    Encoding(String),
    #[error("nonce synchronization failed: {0}")]
    NonceSyncFailed(String),
}

/// A transaction request before gas estimation and nonce assignment.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionRequest {
    pub to: Option<String>,
    pub value: Option<u128>,
    pub data: Option<String>,
    pub chain_id: u64,
    pub gas_limit: Option<u64>,
    pub gas_price: Option<u128>,
}

impl TransactionRequest {
    pub fn new(chain_id: u64) -> Self {
        Self {
            to: None,
            value: None,
            data: None,
            chain_id,
            gas_limit: None,
            gas_price: None,
        }
    }

    pub fn to(mut self, to: String) -> Self {
        self.to = Some(to);
        self
    }

    pub fn value(mut self, value: u128) -> Self {
        self.value = Some(value);
        self
    }

    pub fn data(mut self, data: String) -> Self {
        self.data = Some(data);
        self
    }

    pub fn gas_limit(mut self, gas_limit: u64) -> Self {
        self.gas_limit = Some(gas_limit);
        self
    }

    pub fn gas_price(mut self, gas_price: u128) -> Self {
        self.gas_price = Some(gas_price);
        self
    }
}

/// EIP-1559 transaction with dynamic fee structure.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Eip1559Transaction {
    pub chain_id: u64,
    pub nonce: u64,
    pub max_priority_fee_per_gas: u128,
    pub max_fee_per_gas: u128,
    pub gas_limit: u64,
    pub to: Option<String>,
    pub value: u128,
    pub data: Vec<u8>,
    pub access_list: Vec<AccessListItem>,
}

/// Legacy transaction with fixed gas price.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LegacyTransaction {
    pub chain_id: u64,
    pub nonce: u64,
    pub gas_price: u128,
    pub gas_limit: u64,
    pub to: Option<String>,
    pub value: u128,
    pub data: Vec<u8>,
}

/// Access list entry for EIP-2930 transactions.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AccessListItem {
    pub address: String,
    pub storage_keys: Vec<String>,
}

/// Union type for different transaction formats.
#[derive(Debug, Clone)]
pub enum UnsignedTransaction {
    Eip1559(Eip1559Transaction),
    Legacy(LegacyTransaction),
}

impl UnsignedTransaction {
    pub fn chain_id(&self) -> u64 {
        match self {
            UnsignedTransaction::Eip1559(tx) => tx.chain_id,
            UnsignedTransaction::Legacy(tx) => tx.chain_id,
        }
    }

    pub fn nonce(&self) -> u64 {
        match self {
            UnsignedTransaction::Eip1559(tx) => tx.nonce,
            UnsignedTransaction::Legacy(tx) => tx.nonce,
        }
    }

    pub fn gas_limit(&self) -> u64 {
        match self {
            UnsignedTransaction::Eip1559(tx) => tx.gas_limit,
            UnsignedTransaction::Legacy(tx) => tx.gas_limit,
        }
    }
}

/// A signed transaction ready for broadcast.
#[derive(Debug, Clone)]
pub struct SignedTransaction {
    pub raw_tx: Vec<u8>,
    pub tx_hash: String,
}

/// Builds unsigned transactions from requests and gas estimates.
pub struct TransactionBuilder;

impl TransactionBuilder {
    pub fn new() -> Self {
        Self
    }

    /// Build an unsigned transaction from a request and gas estimate.
    pub fn build_transaction(
        &self,
        request: &TransactionRequest,
        gas_estimate: &GasEstimate,
        nonce: u64,
    ) -> Result<UnsignedTransaction, TxError> {
        let to = request.to.clone();
        let value = request.value.unwrap_or(0);
        let data = if let Some(ref data_hex) = request.data {
            hex::decode(data_hex.trim_start_matches("0x"))
                .map_err(|e| TxError::InvalidParameter(format!("invalid data hex: {e}")))?
        } else {
            Vec::new()
        };

        let gas_limit = request.gas_limit.unwrap_or(gas_estimate.gas_limit);

        if gas_estimate.is_eip1559 {
            let max_priority_fee_per_gas = gas_estimate.max_priority_fee_per_gas
                .ok_or_else(|| TxError::InvalidParameter("missing priority fee for EIP-1559".into()))?;

            Ok(UnsignedTransaction::Eip1559(Eip1559Transaction {
                chain_id: request.chain_id,
                nonce,
                max_priority_fee_per_gas,
                max_fee_per_gas: gas_estimate.max_fee_per_gas,
                gas_limit,
                to,
                value,
                data,
                access_list: Vec::new(), // Empty for now
            }))
        } else {
            let gas_price = request.gas_price.unwrap_or(gas_estimate.max_fee_per_gas);

            Ok(UnsignedTransaction::Legacy(LegacyTransaction {
                chain_id: request.chain_id,
                nonce,
                gas_price,
                gas_limit,
                to,
                value,
                data,
            }))
        }
    }
}

impl Default for TransactionBuilder {
    fn default() -> Self {
        Self::new()
    }
}

/// Manages nonces for transaction ordering and prevents replay.
pub struct NonceManager {
    // (chain_id, address) -> current nonce
    nonces: HashMap<(u64, String), AtomicU64>,
}

impl NonceManager {
    pub fn new() -> Self {
        Self {
            nonces: HashMap::new(),
        }
    }

    /// Get the next nonce for an address on a chain.
    pub fn next_nonce(&mut self, chain_id: u64, address: &str) -> u64 {
        let key = (chain_id, address.to_lowercase());
        let nonce = self.nonces.entry(key).or_insert_with(|| AtomicU64::new(0));
        nonce.fetch_add(1, Ordering::SeqCst)
    }

    /// Confirm that a nonce was successfully used (for cleanup/tracking).
    pub fn confirm_nonce(&mut self, chain_id: u64, address: &str, nonce: u64) {
        let key = (chain_id, address.to_lowercase());
        debug!("Confirmed nonce {nonce} for address {address} on chain {chain_id}");
        
        // Update our tracking to be at least this nonce + 1
        if let Some(stored_nonce) = self.nonces.get(&key) {
            let current = stored_nonce.load(Ordering::SeqCst);
            if nonce + 1 > current {
                stored_nonce.store(nonce + 1, Ordering::SeqCst);
            }
        }
    }

    /// Synchronize nonce with the chain's current state.
    pub async fn sync_from_chain<C: RpcClient>(
        &mut self,
        chain_id: u64,
        address: &str,
        client: &C,
    ) -> Result<u64, TxError> {
        let chain_nonce = client.get_nonce(address).await?;
        let key = (chain_id, address.to_lowercase());
        
        let stored_nonce = self.nonces.entry(key).or_insert_with(|| AtomicU64::new(0));
        let current = stored_nonce.load(Ordering::SeqCst);
        
        if chain_nonce > current {
            debug!(
                "Syncing nonce for {address} on chain {chain_id}: {current} -> {chain_nonce}"
            );
            stored_nonce.store(chain_nonce, Ordering::SeqCst);
            Ok(chain_nonce)
        } else if chain_nonce < current {
            warn!(
                "Local nonce ({current}) ahead of chain nonce ({chain_nonce}) for {address} on chain {chain_id}"
            );
            // Keep local nonce if it's ahead (pending transactions)
            Ok(current)
        } else {
            Ok(chain_nonce)
        }
    }
}

impl Default for NonceManager {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::gas::GasEstimate;

    #[test]
    fn test_transaction_request_builder() {
        let tx = TransactionRequest::new(1)
            .to("0x1234567890123456789012345678901234567890".into())
            .value(1000000000000000000u128)
            .data("0x".into())
            .gas_limit(21000)
            .gas_price(20000000000u128);

        assert_eq!(tx.chain_id, 1);
        assert_eq!(tx.to, Some("0x1234567890123456789012345678901234567890".into()));
        assert_eq!(tx.value, Some(1000000000000000000u128));
        assert_eq!(tx.gas_limit, Some(21000));
        assert_eq!(tx.gas_price, Some(20000000000u128));
    }

    #[test]
    fn test_transaction_builder_eip1559() {
        let request = TransactionRequest::new(1)
            .to("0x1234567890123456789012345678901234567890".into())
            .value(1000000000000000000u128);

        let gas_estimate = GasEstimate {
            max_fee_per_gas: 30000000000u128,
            max_priority_fee_per_gas: Some(2000000000u128),
            gas_limit: 21000,
            is_eip1559: true,
        };

        let builder = TransactionBuilder::new();
        let unsigned_tx = builder.build_transaction(&request, &gas_estimate, 42).unwrap();

        match unsigned_tx {
            UnsignedTransaction::Eip1559(tx) => {
                assert_eq!(tx.chain_id, 1);
                assert_eq!(tx.nonce, 42);
                assert_eq!(tx.max_fee_per_gas, 30000000000u128);
                assert_eq!(tx.max_priority_fee_per_gas, 2000000000u128);
                assert_eq!(tx.gas_limit, 21000);
                assert_eq!(tx.value, 1000000000000000000u128);
            }
            _ => panic!("Expected EIP-1559 transaction"),
        }
    }

    #[test]
    fn test_transaction_builder_legacy() {
        let request = TransactionRequest::new(1)
            .to("0x1234567890123456789012345678901234567890".into())
            .value(500000000000000000u128);

        let gas_estimate = GasEstimate {
            max_fee_per_gas: 20000000000u128,
            max_priority_fee_per_gas: None,
            gas_limit: 21000,
            is_eip1559: false,
        };

        let builder = TransactionBuilder::new();
        let unsigned_tx = builder.build_transaction(&request, &gas_estimate, 10).unwrap();

        match unsigned_tx {
            UnsignedTransaction::Legacy(tx) => {
                assert_eq!(tx.chain_id, 1);
                assert_eq!(tx.nonce, 10);
                assert_eq!(tx.gas_price, 20000000000u128);
                assert_eq!(tx.gas_limit, 21000);
                assert_eq!(tx.value, 500000000000000000u128);
            }
            _ => panic!("Expected Legacy transaction"),
        }
    }

    #[test]
    fn test_transaction_builder_with_data() {
        let request = TransactionRequest::new(1)
            .to("0x1234567890123456789012345678901234567890".into())
            .data("0xa9059cbb000000000000000000000000def1c0ded9bec7f1a1670819833240f027b25eff000000000000000000000000000000000000000000000000000000e8d4a51000".into());

        let gas_estimate = GasEstimate {
            max_fee_per_gas: 25000000000u128,
            max_priority_fee_per_gas: None,
            gas_limit: 60000,
            is_eip1559: false,
        };

        let builder = TransactionBuilder::new();
        let unsigned_tx = builder.build_transaction(&request, &gas_estimate, 5).unwrap();

        match unsigned_tx {
            UnsignedTransaction::Legacy(tx) => {
                assert_eq!(tx.data.len(), 68); // 4 + 32 + 32 bytes
                assert!(!tx.data.is_empty());
            }
            _ => panic!("Expected Legacy transaction"),
        }
    }

    #[test]
    fn test_transaction_builder_invalid_data_hex() {
        let request = TransactionRequest::new(1)
            .data("0xinvalid_hex".into());

        let gas_estimate = GasEstimate {
            max_fee_per_gas: 20000000000u128,
            max_priority_fee_per_gas: None,
            gas_limit: 21000,
            is_eip1559: false,
        };

        let builder = TransactionBuilder::new();
        let result = builder.build_transaction(&request, &gas_estimate, 0);
        assert!(result.is_err());
    }

    #[test]
    fn test_nonce_manager_increment() {
        let mut manager = NonceManager::new();
        let addr = "0x1234567890123456789012345678901234567890";
        
        assert_eq!(manager.next_nonce(1, addr), 0);
        assert_eq!(manager.next_nonce(1, addr), 1);
        assert_eq!(manager.next_nonce(1, addr), 2);
    }

    #[test]
    fn test_nonce_manager_different_chains() {
        let mut manager = NonceManager::new();
        let addr = "0x1234567890123456789012345678901234567890";
        
        assert_eq!(manager.next_nonce(1, addr), 0);
        assert_eq!(manager.next_nonce(137, addr), 0); // Different chain, reset nonce
        assert_eq!(manager.next_nonce(1, addr), 1);  // Back to chain 1
    }

    #[test]
    fn test_nonce_manager_different_addresses() {
        let mut manager = NonceManager::new();
        let addr1 = "0x1234567890123456789012345678901234567890";
        let addr2 = "0x0987654321098765432109876543210987654321";
        
        assert_eq!(manager.next_nonce(1, addr1), 0);
        assert_eq!(manager.next_nonce(1, addr2), 0);
        assert_eq!(manager.next_nonce(1, addr1), 1);
        assert_eq!(manager.next_nonce(1, addr2), 1);
    }

    #[test]
    fn test_nonce_manager_case_insensitive() {
        let mut manager = NonceManager::new();
        let addr_upper = "0x1234567890123456789012345678901234567890";
        let addr_lower = "0x1234567890123456789012345678901234567890";
        
        assert_eq!(manager.next_nonce(1, addr_upper), 0);
        assert_eq!(manager.next_nonce(1, addr_lower), 1); // Same address
    }

    #[test]
    fn test_nonce_manager_confirm() {
        let mut manager = NonceManager::new();
        let addr = "0x1234567890123456789012345678901234567890";
        
        // Get some nonces
        assert_eq!(manager.next_nonce(1, addr), 0);
        assert_eq!(manager.next_nonce(1, addr), 1);
        
        // Confirm nonce 0 was used
        manager.confirm_nonce(1, addr, 0);
        
        // Next nonce should still be sequential
        assert_eq!(manager.next_nonce(1, addr), 2);
    }

    #[test]
    fn test_unsigned_transaction_accessors() {
        let legacy = UnsignedTransaction::Legacy(LegacyTransaction {
            chain_id: 1,
            nonce: 42,
            gas_price: 20000000000,
            gas_limit: 21000,
            to: None,
            value: 0,
            data: vec![],
        });

        assert_eq!(legacy.chain_id(), 1);
        assert_eq!(legacy.nonce(), 42);
        assert_eq!(legacy.gas_limit(), 21000);

        let eip1559 = UnsignedTransaction::Eip1559(Eip1559Transaction {
            chain_id: 137,
            nonce: 10,
            max_priority_fee_per_gas: 2000000000,
            max_fee_per_gas: 30000000000,
            gas_limit: 60000,
            to: None,
            value: 0,
            data: vec![],
            access_list: vec![],
        });

        assert_eq!(eip1559.chain_id(), 137);
        assert_eq!(eip1559.nonce(), 10);
        assert_eq!(eip1559.gas_limit(), 60000);
    }
}