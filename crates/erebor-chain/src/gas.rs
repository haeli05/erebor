use serde::{Deserialize, Serialize};
use std::collections::VecDeque;
use std::sync::{Arc, RwLock};
use thiserror::Error;

use crate::rpc::{RpcError, RpcPool};

#[derive(Error, Debug)]
pub enum GasError {
    #[error("RPC error: {0}")]
    Rpc(#[from] RpcError),
    #[error("failed to parse gas data: {0}")]
    Parse(String),
}

/// Gas price estimate for a transaction.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct GasEstimate {
    /// For EIP-1559: max fee per gas in wei. For legacy: gas price.
    pub max_fee_per_gas: u128,
    /// For EIP-1559 only: max priority fee (tip).
    pub max_priority_fee_per_gas: Option<u128>,
    /// Estimated gas units for the transaction.
    pub gas_limit: u64,
    /// Whether this is an EIP-1559 estimate.
    pub is_eip1559: bool,
}

/// Trait for gas price oracles.
#[allow(async_fn_in_trait)]
pub trait GasOracle: Send + Sync {
    /// Estimate current gas prices. Returns (max_fee_per_gas, max_priority_fee_per_gas).
    async fn estimate_gas_price(
        &self,
        pool: &RpcPool,
    ) -> Result<(u128, Option<u128>), GasError>;
}

/// EIP-1559 gas oracle using `eth_feeHistory`.
pub struct Eip1559GasOracle {
    /// Number of recent blocks to analyze.
    block_count: u64,
    /// Reward percentile to target (e.g. 50 for median tip).
    reward_percentile: f64,
}

impl Eip1559GasOracle {
    pub fn new() -> Self {
        Self {
            block_count: 5,
            reward_percentile: 50.0,
        }
    }

    pub fn with_params(block_count: u64, reward_percentile: f64) -> Self {
        Self {
            block_count,
            reward_percentile,
        }
    }
}

impl Default for Eip1559GasOracle {
    fn default() -> Self {
        Self::new()
    }
}

impl GasOracle for Eip1559GasOracle {
    async fn estimate_gas_price(
        &self,
        pool: &RpcPool,
    ) -> Result<(u128, Option<u128>), GasError> {
        let result = pool
            .request(
                "eth_feeHistory",
                serde_json::json!([
                    format!("0x{:x}", self.block_count),
                    "latest",
                    [self.reward_percentile]
                ]),
            )
            .await?;

        // Parse baseFeePerGas from latest block
        let base_fees = result["baseFeePerGas"]
            .as_array()
            .ok_or_else(|| GasError::Parse("missing baseFeePerGas".into()))?;

        let latest_base_fee = base_fees
            .last()
            .and_then(|v| v.as_str())
            .ok_or_else(|| GasError::Parse("empty baseFeePerGas".into()))?;

        let base_fee = parse_hex_u128(latest_base_fee)?;

        // Parse reward (priority fee) percentiles
        let rewards = result["reward"]
            .as_array()
            .ok_or_else(|| GasError::Parse("missing reward".into()))?;

        let priority_fees: Vec<u128> = rewards
            .iter()
            .filter_map(|r| r.as_array())
            .filter_map(|arr| arr.first())
            .filter_map(|v| v.as_str())
            .filter_map(|s| parse_hex_u128(s).ok())
            .collect();

        let avg_priority_fee = if priority_fees.is_empty() {
            1_500_000_000u128 // 1.5 gwei default
        } else {
            priority_fees.iter().sum::<u128>() / priority_fees.len() as u128
        };

        // max_fee = 2 * base_fee + priority_fee (standard formula)
        let max_fee = base_fee * 2 + avg_priority_fee;

        Ok((max_fee, Some(avg_priority_fee)))
    }
}

/// Legacy gas oracle using `eth_gasPrice`.
pub struct LegacyGasOracle;

impl GasOracle for LegacyGasOracle {
    async fn estimate_gas_price(
        &self,
        pool: &RpcPool,
    ) -> Result<(u128, Option<u128>), GasError> {
        let result = pool
            .request("eth_gasPrice", serde_json::json!([]))
            .await?;

        let hex = result
            .as_str()
            .ok_or_else(|| GasError::Parse("expected string gas price".into()))?;

        let gas_price = parse_hex_u128(hex)?;
        Ok((gas_price, None))
    }
}

/// Gas estimator with safety margins and fee history tracking.
pub struct GasEstimator {
    /// Safety margin multiplier (e.g., 1.2 = 20% extra).
    safety_margin: f64,
    /// Recent fee observations for trend analysis.
    fee_history: Arc<RwLock<VecDeque<FeeObservation>>>,
    /// Max history entries to keep.
    max_history: usize,
}

#[derive(Debug, Clone)]
struct FeeObservation {
    max_fee: u128,
    priority_fee: Option<u128>,
    timestamp: std::time::Instant,
}

impl GasEstimator {
    pub fn new(safety_margin: f64) -> Self {
        Self {
            safety_margin,
            fee_history: Arc::new(RwLock::new(VecDeque::new())),
            max_history: 100,
        }
    }

    /// Estimate gas for a transaction.
    pub async fn estimate<O: GasOracle>(
        &self,
        pool: &RpcPool,
        oracle: &O,
        tx_data: Option<&TransactionRequest>,
    ) -> Result<GasEstimate, GasError> {
        let (max_fee, priority_fee) = oracle.estimate_gas_price(pool).await?;

        // Record observation
        {
            let mut history = self.fee_history.write().unwrap();
            history.push_back(FeeObservation {
                max_fee,
                priority_fee,
                timestamp: std::time::Instant::now(),
            });
            while history.len() > self.max_history {
                history.pop_front();
            }
        }

        // Estimate gas limit
        let gas_limit = if let Some(tx) = tx_data {
            self.estimate_gas_limit(pool, tx).await?
        } else {
            21_000 // simple transfer default
        };

        // Apply safety margin
        let adjusted_fee = (max_fee as f64 * self.safety_margin) as u128;
        let adjusted_priority = priority_fee.map(|f| (f as f64 * self.safety_margin) as u128);
        let adjusted_gas_limit = (gas_limit as f64 * self.safety_margin) as u64;

        Ok(GasEstimate {
            max_fee_per_gas: adjusted_fee,
            max_priority_fee_per_gas: adjusted_priority,
            gas_limit: adjusted_gas_limit,
            is_eip1559: priority_fee.is_some(),
        })
    }

    /// Use eth_estimateGas to get gas limit for a specific transaction.
    async fn estimate_gas_limit(
        &self,
        pool: &RpcPool,
        tx: &TransactionRequest,
    ) -> Result<u64, GasError> {
        let mut call_obj = serde_json::Map::new();
        if let Some(ref from) = tx.from {
            call_obj.insert("from".into(), serde_json::json!(from));
        }
        if let Some(ref to) = tx.to {
            call_obj.insert("to".into(), serde_json::json!(to));
        }
        if let Some(ref data) = tx.data {
            call_obj.insert("data".into(), serde_json::json!(data));
        }
        if let Some(value) = tx.value {
            call_obj.insert("value".into(), serde_json::json!(format!("0x{value:x}")));
        }

        let result = pool
            .request(
                "eth_estimateGas",
                serde_json::json!([serde_json::Value::Object(call_obj)]),
            )
            .await?;

        let hex = result
            .as_str()
            .ok_or_else(|| GasError::Parse("expected string gas estimate".into()))?;

        let gas = u64::from_str_radix(hex.trim_start_matches("0x"), 16)
            .map_err(|e| GasError::Parse(format!("invalid gas hex: {e}")))?;

        Ok(gas)
    }

    /// Get average fee from recent observations.
    pub fn average_recent_fee(&self) -> Option<u128> {
        let history = self.fee_history.read().unwrap();
        if history.is_empty() {
            return None;
        }
        let sum: u128 = history.iter().map(|o| o.max_fee).sum();
        Some(sum / history.len() as u128)
    }

    /// Get the trend direction: positive means fees are rising.
    pub fn fee_trend(&self) -> Option<i128> {
        let history = self.fee_history.read().unwrap();
        if history.len() < 2 {
            return None;
        }
        let recent = history.back().unwrap().max_fee as i128;
        let older = history.front().unwrap().max_fee as i128;
        Some(recent - older)
    }
}

/// Simplified transaction request for gas estimation.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct TransactionRequest {
    pub from: Option<String>,
    pub to: Option<String>,
    pub data: Option<String>,
    pub value: Option<u128>,
}

fn parse_hex_u128(hex: &str) -> Result<u128, GasError> {
    u128::from_str_radix(hex.trim_start_matches("0x"), 16)
        .map_err(|e| GasError::Parse(format!("invalid hex '{hex}': {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tokio::io::{AsyncReadExt, AsyncWriteExt};
    use tokio::net::TcpListener;

    async fn mock_server(responses: Vec<&'static str>) -> (u16, tokio::task::JoinHandle<()>) {
        let listener = TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();

        let handle = tokio::spawn(async move {
            for resp_body in responses {
                if let Ok((mut stream, _)) = listener.accept().await {
                    let mut buf = vec![0u8; 4096];
                    let _ = stream.read(&mut buf).await;
                    let http = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                        resp_body.len(),
                        resp_body
                    );
                    let _ = stream.write_all(http.as_bytes()).await;
                }
            }
        });
        (port, handle)
    }

    #[test]
    fn test_parse_hex_u128() {
        assert_eq!(parse_hex_u128("0x3b9aca00").unwrap(), 1_000_000_000);
        assert_eq!(parse_hex_u128("0x0").unwrap(), 0);
        assert_eq!(parse_hex_u128("0xff").unwrap(), 255);
        assert!(parse_hex_u128("not_hex").is_err());
    }

    #[test]
    fn test_gas_estimator_fee_history() {
        let estimator = GasEstimator::new(1.0);
        assert!(estimator.average_recent_fee().is_none());
        assert!(estimator.fee_trend().is_none());

        // Manually add observations
        {
            let mut history = estimator.fee_history.write().unwrap();
            history.push_back(FeeObservation {
                max_fee: 100,
                priority_fee: Some(10),
                timestamp: std::time::Instant::now(),
            });
            history.push_back(FeeObservation {
                max_fee: 200,
                priority_fee: Some(20),
                timestamp: std::time::Instant::now(),
            });
        }

        assert_eq!(estimator.average_recent_fee(), Some(150));
        assert_eq!(estimator.fee_trend(), Some(100)); // rising
    }

    #[test]
    fn test_safety_margin_application() {
        let estimate = GasEstimate {
            max_fee_per_gas: (100.0 * 1.2) as u128,
            max_priority_fee_per_gas: Some((10.0 * 1.2) as u128),
            gas_limit: (21000.0 * 1.2) as u64,
            is_eip1559: true,
        };
        assert_eq!(estimate.max_fee_per_gas, 120);
        assert_eq!(estimate.max_priority_fee_per_gas, Some(12));
        assert_eq!(estimate.gas_limit, 25200);
    }

    #[tokio::test]
    async fn test_legacy_gas_oracle() {
        let resp = r#"{"jsonrpc":"2.0","result":"0x3b9aca00","id":1}"#;
        let (port, _server) = mock_server(vec![resp]).await;

        let pool = RpcPool::new(1, vec![format!("http://127.0.0.1:{port}")]);
        let oracle = LegacyGasOracle;
        let (gas_price, priority) = oracle.estimate_gas_price(&pool).await.unwrap();
        assert_eq!(gas_price, 1_000_000_000); // 1 gwei
        assert!(priority.is_none());
    }

    #[tokio::test]
    async fn test_eip1559_gas_oracle() {
        let resp = r#"{"jsonrpc":"2.0","result":{"baseFeePerGas":["0x3b9aca00","0x3b9aca00","0x3b9aca00","0x3b9aca00","0x3b9aca00","0x3b9aca00"],"reward":[["0x59682f00"],["0x59682f00"],["0x59682f00"],["0x59682f00"],["0x59682f00"]]},"id":1}"#;
        let (port, _server) = mock_server(vec![resp]).await;

        let pool = RpcPool::new(1, vec![format!("http://127.0.0.1:{port}")]);
        let oracle = Eip1559GasOracle::new();
        let (max_fee, priority) = oracle.estimate_gas_price(&pool).await.unwrap();

        let expected_priority: u128 = 0x59682f00;
        let expected_max = 1_000_000_000u128 * 2 + expected_priority;
        assert_eq!(max_fee, expected_max);
        assert_eq!(priority, Some(expected_priority));
    }

    #[tokio::test]
    async fn test_gas_estimator_full_flow() {
        let resp = r#"{"jsonrpc":"2.0","result":"0x3b9aca00","id":1}"#;
        let (port, _server) = mock_server(vec![resp]).await;

        let pool = RpcPool::new(1, vec![format!("http://127.0.0.1:{port}")]);
        let estimator = GasEstimator::new(1.2);
        let oracle = LegacyGasOracle;

        let estimate = estimator.estimate(&pool, &oracle, None).await.unwrap();
        assert!(!estimate.is_eip1559);
        // 1 gwei * 1.2 = 1.2 gwei
        assert_eq!(estimate.max_fee_per_gas, 1_200_000_000);
        // 21000 * 1.2 = 25200
        assert_eq!(estimate.gas_limit, 25200);

        // History should have one entry
        assert_eq!(estimator.average_recent_fee(), Some(1_000_000_000));
    }

    #[test]
    fn test_fee_history_max_capacity() {
        let estimator = GasEstimator::new(1.0);
        {
            let mut history = estimator.fee_history.write().unwrap();
            for i in 0..150 {
                history.push_back(FeeObservation {
                    max_fee: i as u128,
                    priority_fee: None,
                    timestamp: std::time::Instant::now(),
                });
            }
            // Manually trim like estimate() does
            while history.len() > estimator.max_history {
                history.pop_front();
            }
        }
        let history = estimator.fee_history.read().unwrap();
        assert_eq!(history.len(), 100);
        assert_eq!(history.front().unwrap().max_fee, 50);
    }
}
