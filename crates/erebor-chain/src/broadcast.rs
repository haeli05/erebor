use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use thiserror::Error;
use tokio::time::Instant;
use tracing::{debug, warn};

use crate::rpc::{RpcError, RpcPool};
use crate::tx::SignedTransaction;

#[derive(Error, Debug)]
pub enum BroadcastError {
    #[error("RPC error: {0}")]
    Rpc(#[from] RpcError),
    #[error("transaction not found: {0}")]
    TransactionNotFound(String),
    #[error("broadcast timeout: {0}")]
    Timeout(String),
    #[error("invalid transaction hash: {0}")]
    InvalidTxHash(String),
}

/// A unique transaction hash.
pub type TxHash = String;

/// On-chain receipt status.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum ReceiptStatus {
    Success,
    Reverted,
}

/// Receipt for a mined transaction.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub struct TransactionReceipt {
    pub tx_hash: TxHash,
    pub block_number: u64,
    pub gas_used: u64,
    pub status: ReceiptStatus,
}

/// Status of a transaction (lifecycle).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
pub enum TransactionStatus {
    Pending,
    Confirmed(TransactionReceipt),
    Failed(String),
}

/// Tracks a pending transaction with metadata.
#[derive(Debug, Clone)]
pub struct PendingTransaction {
    pub tx_hash: TxHash,
    pub submitted_at: Instant,
    pub chain_id: u64,
    pub last_checked: Option<Instant>,
}

/// Trait for broadcasting signed transactions.
#[allow(async_fn_in_trait)]
pub trait Broadcaster: Send + Sync {
    /// Broadcast a signed transaction to the network.
    async fn broadcast(&self, signed_tx: &SignedTransaction) -> Result<TxHash, BroadcastError>;
    
    /// Get a transaction receipt if available.
    async fn get_receipt(&self, tx_hash: &TxHash) -> Result<Option<TransactionReceipt>, BroadcastError>;
}

/// EVM transaction broadcaster using JSON-RPC.
pub struct EvmBroadcaster {
    pools: Arc<RwLock<HashMap<u64, Arc<RpcPool>>>>,
    pending_transactions: Arc<RwLock<HashMap<TxHash, PendingTransaction>>>,
}

impl EvmBroadcaster {
    pub fn new() -> Self {
        Self {
            pools: Arc::new(RwLock::new(HashMap::new())),
            pending_transactions: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    /// Add an RPC pool for a specific chain.
    pub fn add_pool(&self, chain_id: u64, pool: Arc<RpcPool>) {
        let mut pools = self.pools.write().unwrap();
        pools.insert(chain_id, pool);
    }

    /// Get an RPC pool for a chain.
    fn get_pool(&self, chain_id: u64) -> Result<Arc<RpcPool>, BroadcastError> {
        let pools = self.pools.read().unwrap();
        pools
            .get(&chain_id)
            .cloned()
            .ok_or(BroadcastError::Rpc(RpcError::NoEndpoints(chain_id)))
    }

    /// Track a pending transaction.
    fn track_pending(&self, tx_hash: TxHash, chain_id: u64) {
        let mut pending = self.pending_transactions.write().unwrap();
        pending.insert(tx_hash.clone(), PendingTransaction {
            tx_hash,
            submitted_at: Instant::now(),
            chain_id,
            last_checked: None,
        });
    }

    /// Update the last checked time for a pending transaction.
    fn update_last_checked(&self, tx_hash: &TxHash) {
        let mut pending = self.pending_transactions.write().unwrap();
        if let Some(tx) = pending.get_mut(tx_hash) {
            tx.last_checked = Some(Instant::now());
        }
    }

    /// Remove a transaction from pending tracking.
    pub fn remove_pending(&self, tx_hash: &TxHash) {
        let mut pending = self.pending_transactions.write().unwrap();
        pending.remove(tx_hash);
    }

    /// Get all pending transactions.
    pub fn get_pending(&self) -> Vec<PendingTransaction> {
        let pending = self.pending_transactions.read().unwrap();
        pending.values().cloned().collect()
    }

    /// Parse a transaction receipt from RPC response.
    fn parse_receipt(&self, receipt_json: serde_json::Value) -> Result<TransactionReceipt, BroadcastError> {
        let tx_hash = receipt_json["transactionHash"]
            .as_str()
            .ok_or_else(|| BroadcastError::InvalidTxHash("missing transactionHash".into()))?
            .to_string();

        let block_number_hex = receipt_json["blockNumber"]
            .as_str()
            .ok_or_else(|| BroadcastError::InvalidTxHash("missing blockNumber".into()))?;
        
        let block_number = u64::from_str_radix(
            block_number_hex.strip_prefix("0x").unwrap_or(block_number_hex),
            16,
        ).map_err(|e| BroadcastError::InvalidTxHash(format!("invalid blockNumber: {e}")))?;

        let gas_used_hex = receipt_json["gasUsed"]
            .as_str()
            .ok_or_else(|| BroadcastError::InvalidTxHash("missing gasUsed".into()))?;
        
        let gas_used = u64::from_str_radix(
            gas_used_hex.strip_prefix("0x").unwrap_or(gas_used_hex),
            16,
        ).map_err(|e| BroadcastError::InvalidTxHash(format!("invalid gasUsed: {e}")))?;

        // Parse status (1 = success, 0 = failure)
        let status_value = receipt_json["status"]
            .as_str()
            .unwrap_or("0x1"); // Default to success if missing

        let is_success = status_value == "0x1";
        
        let receipt = TransactionReceipt {
            tx_hash: tx_hash.clone(),
            block_number,
            gas_used,
            status: if is_success {
                ReceiptStatus::Success
            } else {
                ReceiptStatus::Reverted
            },
        };

        Ok(receipt)
    }
}

impl Default for EvmBroadcaster {
    fn default() -> Self {
        Self::new()
    }
}

impl Broadcaster for EvmBroadcaster {
    async fn broadcast(&self, signed_tx: &SignedTransaction) -> Result<TxHash, BroadcastError> {
        // We need to determine the chain ID from the signed transaction
        // For now, we'll assume chain ID 1 (Ethereum mainnet)
        // In a real implementation, we'd parse this from the transaction
        let chain_id = 1u64; // TODO: Extract from signed transaction
        
        let pool = self.get_pool(chain_id)?;
        
        // Encode transaction as hex string
        let raw_tx_hex = format!("0x{}", hex::encode(&signed_tx.raw_tx));
        
        debug!("Broadcasting transaction: {}", signed_tx.tx_hash);
        
        // Send raw transaction
        let result = pool.request("eth_sendRawTransaction", serde_json::json!([raw_tx_hex])).await?;
        
        let returned_hash = result
            .as_str()
            .ok_or_else(|| BroadcastError::InvalidTxHash("expected string tx hash from RPC".into()))?
            .to_string();

        // Verify the returned hash matches what we calculated
        if returned_hash.to_lowercase() != signed_tx.tx_hash.to_lowercase() {
            warn!(
                "RPC returned different tx hash: expected {}, got {}",
                signed_tx.tx_hash, returned_hash
            );
        }

        // Track this transaction as pending
        self.track_pending(signed_tx.tx_hash.clone(), chain_id);

        debug!("Successfully broadcasted transaction: {}", signed_tx.tx_hash);
        Ok(signed_tx.tx_hash.clone())
    }

    async fn get_receipt(&self, tx_hash: &TxHash) -> Result<Option<TransactionReceipt>, BroadcastError> {
        // Find the chain ID for this transaction
        let chain_id = {
            let pending = self.pending_transactions.read().unwrap();
            pending
                .get(tx_hash)
                .map(|tx| tx.chain_id)
                .unwrap_or(1u64) // Default to Ethereum mainnet
        };

        let pool = self.get_pool(chain_id)?;

        debug!("Checking receipt for transaction: {}", tx_hash);
        
        // Update last checked time
        self.update_last_checked(tx_hash);

        // Get transaction receipt
        let result = pool
            .request("eth_getTransactionReceipt", serde_json::json!([tx_hash]))
            .await?;

        if result.is_null() {
            debug!("No receipt yet for transaction: {}", tx_hash);
            return Ok(None);
        }

        let receipt = self.parse_receipt(result)?;
        
        debug!(
            "Found receipt for transaction {}: block {}, gas used {}, success: {}",
            tx_hash,
            receipt.block_number,
            receipt.gas_used,
            matches!(receipt.status, ReceiptStatus::Success)
        );

        // Remove from pending tracking since we have a receipt
        self.remove_pending(tx_hash);

        Ok(Some(receipt))
    }
}

/// Solana transaction broadcaster (stub implementation).
pub struct SolanaBroadcaster;

impl SolanaBroadcaster {
    pub fn new() -> Self {
        Self
    }
}

impl Default for SolanaBroadcaster {
    fn default() -> Self {
        Self::new()
    }
}

impl Broadcaster for SolanaBroadcaster {
    async fn broadcast(&self, _signed_tx: &SignedTransaction) -> Result<TxHash, BroadcastError> {
        // Stub implementation - would implement Solana transaction broadcasting
        Err(BroadcastError::Rpc(RpcError::JsonRpc {
            code: -1,
            message: "Solana broadcasting not implemented".into(),
        }))
    }

    async fn get_receipt(&self, _tx_hash: &TxHash) -> Result<Option<TransactionReceipt>, BroadcastError> {
        // Stub implementation - would implement Solana receipt checking
        Ok(None)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::rpc::RpcPool;
    use crate::tx::SignedTransaction;
    use tokio::time::sleep;
    use std::sync::atomic::{AtomicU32, Ordering};

    // Mock RPC server for testing
    async fn mock_broadcast_server(responses: Vec<&'static str>) -> (u16, tokio::task::JoinHandle<()>) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let response_counter = Arc::new(AtomicU32::new(0));

        let handle = tokio::spawn(async move {
            for _ in 0..responses.len() {
                if let Ok((mut stream, _)) = listener.accept().await {
                    let mut buf = vec![0u8; 4096];
                    let _ = stream.read(&mut buf).await;
                    
                    let idx = response_counter.fetch_add(1, Ordering::SeqCst) as usize;
                    let response_body = responses.get(idx).unwrap_or(&responses[0]);
                    
                    let http_resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                        response_body.len(),
                        response_body
                    );
                    let _ = stream.write_all(http_resp.as_bytes()).await;
                }
            }
        });
        (port, handle)
    }

    fn test_signed_transaction() -> SignedTransaction {
        SignedTransaction {
            raw_tx: vec![0x02, 0xf8, 0x6d, 0x01, 0x02, 0x84, 0x77, 0x35, 0x94, 0x00],
            tx_hash: "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef".into(),
        }
    }

    #[test]
    fn test_transaction_receipt_parsing() {
        let broadcaster = EvmBroadcaster::new();
        let receipt_json = serde_json::json!({
            "transactionHash": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            "blockNumber": "0x10",
            "gasUsed": "0x5208",
            "status": "0x1"
        });

        let receipt = broadcaster.parse_receipt(receipt_json).unwrap();
        assert_eq!(receipt.tx_hash, "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
        assert_eq!(receipt.block_number, 16);
        assert_eq!(receipt.gas_used, 21000);
        assert!(matches!(receipt.status, ReceiptStatus::Success));
    }

    #[test]
    fn test_transaction_receipt_failed_status() {
        let broadcaster = EvmBroadcaster::new();
        let receipt_json = serde_json::json!({
            "transactionHash": "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef",
            "blockNumber": "0x20",
            "gasUsed": "0x7530",
            "status": "0x0"
        });

        let receipt = broadcaster.parse_receipt(receipt_json).unwrap();
        assert_eq!(receipt.block_number, 32);
        assert_eq!(receipt.gas_used, 30000);
        assert!(matches!(receipt.status, ReceiptStatus::Reverted));
    }

    #[test]
    fn test_pending_transaction_tracking() {
        let broadcaster = EvmBroadcaster::new();
        let tx_hash = "0xtest123";

        // Initially no pending transactions
        assert!(broadcaster.get_pending().is_empty());

        // Track a pending transaction
        broadcaster.track_pending(tx_hash.to_string(), 1);
        let pending = broadcaster.get_pending();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].tx_hash, tx_hash);
        assert_eq!(pending[0].chain_id, 1);

        // Update last checked time
        broadcaster.update_last_checked(tx_hash);
        let pending = broadcaster.get_pending();
        assert!(pending[0].last_checked.is_some());

        // Remove pending transaction
        broadcaster.remove_pending(tx_hash);
        assert!(broadcaster.get_pending().is_empty());
    }

    #[tokio::test]
    async fn test_evm_broadcaster_successful_broadcast() {
        let broadcast_resp = r#"{"jsonrpc":"2.0","result":"0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef","id":1}"#;
        let (port, _server) = mock_broadcast_server(vec![broadcast_resp]).await;

        let broadcaster = EvmBroadcaster::new();
        let pool = Arc::new(RpcPool::new(1, vec![format!("http://127.0.0.1:{port}")]));
        broadcaster.add_pool(1, pool);

        let signed_tx = test_signed_transaction();
        let result = broadcaster.broadcast(&signed_tx).await;

        assert!(result.is_ok());
        let returned_hash = result.unwrap();
        assert_eq!(returned_hash, signed_tx.tx_hash);

        // Should be tracked as pending
        let pending = broadcaster.get_pending();
        assert_eq!(pending.len(), 1);
        assert_eq!(pending[0].tx_hash, signed_tx.tx_hash);
    }

    #[tokio::test]
    async fn test_evm_broadcaster_get_receipt_none() {
        let receipt_resp = r#"{"jsonrpc":"2.0","result":null,"id":1}"#;
        let (port, _server) = mock_broadcast_server(vec![receipt_resp]).await;

        let broadcaster = EvmBroadcaster::new();
        let pool = Arc::new(RpcPool::new(1, vec![format!("http://127.0.0.1:{port}")]));
        broadcaster.add_pool(1, pool);

        let tx_hash = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        broadcaster.track_pending(tx_hash.to_string(), 1);

        let result = broadcaster.get_receipt(&tx_hash.to_string()).await.unwrap();
        assert!(result.is_none());
    }

    #[tokio::test]
    async fn test_evm_broadcaster_get_receipt_success() {
        let receipt_resp = r#"{"jsonrpc":"2.0","result":{"transactionHash":"0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef","blockNumber":"0xa","gasUsed":"0x5208","status":"0x1"},"id":1}"#;
        let (port, _server) = mock_broadcast_server(vec![receipt_resp]).await;

        let broadcaster = EvmBroadcaster::new();
        let pool = Arc::new(RpcPool::new(1, vec![format!("http://127.0.0.1:{port}")]));
        broadcaster.add_pool(1, pool);

        let tx_hash = "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef";
        broadcaster.track_pending(tx_hash.to_string(), 1);

        let result = broadcaster.get_receipt(&tx_hash.to_string()).await.unwrap();
        assert!(result.is_some());

        let receipt = result.unwrap();
        assert_eq!(receipt.tx_hash, tx_hash);
        assert_eq!(receipt.block_number, 10);
        assert_eq!(receipt.gas_used, 21000);

        // Should be removed from pending after getting receipt
        assert!(broadcaster.get_pending().is_empty());
    }

    #[tokio::test]
    async fn test_evm_broadcaster_no_pool() {
        let broadcaster = EvmBroadcaster::new();
        let signed_tx = test_signed_transaction();
        
        let result = broadcaster.broadcast(&signed_tx).await;
        assert!(result.is_err());
        assert!(matches!(result.unwrap_err(), BroadcastError::Rpc(RpcError::NoEndpoints(_))));
    }

    #[tokio::test]
    async fn test_solana_broadcaster_stub() {
        let broadcaster = SolanaBroadcaster::new();
        let signed_tx = test_signed_transaction();

        let broadcast_result = broadcaster.broadcast(&signed_tx).await;
        assert!(broadcast_result.is_err());

        let receipt_result = broadcaster.get_receipt("test_hash").await;
        assert!(receipt_result.is_ok());
        assert!(receipt_result.unwrap().is_none());
    }

    #[test]
    fn test_transaction_status_serialization() {
        let status = TransactionStatus::Pending;
        let json = serde_json::to_string(&status).unwrap();
        assert!(json.contains("Pending"));

        let failed_status = TransactionStatus::Failed("Gas limit exceeded".into());
        let json = serde_json::to_string(&failed_status).unwrap();
        assert!(json.contains("Failed"));
        assert!(json.contains("Gas limit exceeded"));
    }

    #[test]
    fn test_pending_transaction_timing() {
        let broadcaster = EvmBroadcaster::new();
        let tx_hash = "0xtest456";

        broadcaster.track_pending(tx_hash.to_string(), 1);
        let pending_before = broadcaster.get_pending();
        assert_eq!(pending_before.len(), 1);
        assert!(pending_before[0].last_checked.is_none());

        broadcaster.update_last_checked(tx_hash);
        let pending_after = broadcaster.get_pending();
        assert!(pending_after[0].last_checked.is_some());
        assert!(pending_after[0].submitted_at <= pending_after[0].last_checked.unwrap());
    }
}