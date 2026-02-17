use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use std::time::{Duration, Instant};
use thiserror::Error;
use tracing::{debug, warn};

#[derive(Error, Debug)]
pub enum RpcError {
    #[error("all RPC endpoints failed for chain {chain_id}")]
    AllEndpointsFailed { chain_id: u64 },
    #[error("HTTP error: {0}")]
    Http(String),
    #[error("JSON-RPC error {code}: {message}")]
    JsonRpc { code: i64, message: String },
    #[error("deserialization error: {0}")]
    Deserialize(String),
    #[error("no endpoints configured for chain {0}")]
    NoEndpoints(u64),
}

/// A raw JSON-RPC request.
#[derive(Debug, Serialize)]
pub struct JsonRpcRequest {
    pub jsonrpc: &'static str,
    pub method: String,
    pub params: serde_json::Value,
    pub id: u64,
}

/// A raw JSON-RPC response.
#[derive(Debug, Deserialize)]
pub struct JsonRpcResponse {
    pub jsonrpc: String,
    pub result: Option<serde_json::Value>,
    pub error: Option<JsonRpcError>,
    pub id: u64,
}

#[derive(Debug, Deserialize)]
pub struct JsonRpcError {
    pub code: i64,
    pub message: String,
}

/// Health status of an RPC endpoint.
#[derive(Debug, Clone)]
struct EndpointHealth {
    url: String,
    failures: u32,
    last_failure: Option<Instant>,
    last_success: Option<Instant>,
}

impl EndpointHealth {
    fn new(url: String) -> Self {
        Self {
            url,
            failures: 0,
            last_failure: None,
            last_success: None,
        }
    }

    fn is_healthy(&self) -> bool {
        if self.failures == 0 {
            return true;
        }
        // After 3+ consecutive failures, consider unhealthy for 30s
        if self.failures >= 3 {
            if let Some(t) = self.last_failure {
                return t.elapsed() > Duration::from_secs(30);
            }
        }
        true
    }

    fn record_success(&mut self) {
        self.failures = 0;
        self.last_success = Some(Instant::now());
    }

    fn record_failure(&mut self) {
        self.failures += 1;
        self.last_failure = Some(Instant::now());
    }
}

/// Simple response cache for immutable blockchain data.
struct CacheEntry {
    data: serde_json::Value,
    inserted_at: Instant,
    ttl: Duration,
}

impl CacheEntry {
    fn is_valid(&self) -> bool {
        self.inserted_at.elapsed() < self.ttl
    }
}

/// Trait for RPC clients — abstraction over EVM / Solana / etc.
#[allow(async_fn_in_trait)]
pub trait RpcClient: Send + Sync {
    async fn send_raw_transaction(&self, signed_tx: &str) -> Result<String, RpcError>;
    async fn get_balance(&self, address: &str) -> Result<String, RpcError>;
    async fn get_nonce(&self, address: &str) -> Result<u64, RpcError>;
    async fn get_block(&self, block_id: &str) -> Result<serde_json::Value, RpcError>;
    async fn call(&self, to: &str, data: &str) -> Result<String, RpcError>;
    async fn raw_request(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, RpcError>;
}

/// Connection pool with failover for a single chain's RPC endpoints.
pub struct RpcPool {
    chain_id: u64,
    endpoints: Arc<RwLock<Vec<EndpointHealth>>>,
    http: reqwest::Client,
    cache: Arc<RwLock<HashMap<String, CacheEntry>>>,
    request_id: Arc<std::sync::atomic::AtomicU64>,
}

impl RpcPool {
    pub fn new(chain_id: u64, urls: Vec<String>) -> Self {
        let endpoints = urls.into_iter().map(EndpointHealth::new).collect();
        Self {
            chain_id,
            endpoints: Arc::new(RwLock::new(endpoints)),
            http: reqwest::Client::builder()
                .timeout(Duration::from_secs(15))
                .build()
                .unwrap(),
            cache: Arc::new(RwLock::new(HashMap::new())),
            request_id: Arc::new(std::sync::atomic::AtomicU64::new(1)),
        }
    }

    fn next_id(&self) -> u64 {
        self.request_id
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
    }

    /// Get a cache value if present and valid.
    fn get_cached(&self, key: &str) -> Option<serde_json::Value> {
        let cache = self.cache.read().unwrap();
        cache
            .get(key)
            .filter(|e| e.is_valid())
            .map(|e| e.data.clone())
    }

    /// Store in cache with a TTL.
    fn set_cached(&self, key: String, data: serde_json::Value, ttl: Duration) {
        let mut cache = self.cache.write().unwrap();
        cache.insert(
            key,
            CacheEntry {
                data,
                inserted_at: Instant::now(),
                ttl,
            },
        );
    }

    /// Send a JSON-RPC request with automatic failover across endpoints.
    pub async fn request(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, RpcError> {
        let urls: Vec<(usize, String)> = {
            let eps = self.endpoints.read().unwrap();
            if eps.is_empty() {
                return Err(RpcError::NoEndpoints(self.chain_id));
            }
            // Healthy endpoints first, then unhealthy as fallback
            let mut ordered: Vec<(usize, &EndpointHealth)> =
                eps.iter().enumerate().collect();
            ordered.sort_by_key(|(_, e)| !e.is_healthy());
            ordered.iter().map(|(i, e)| (*i, e.url.clone())).collect()
        };

        let req_id = self.next_id();
        let body = JsonRpcRequest {
            jsonrpc: "2.0",
            method: method.to_string(),
            params: params.clone(),
            id: req_id,
        };
        let body_str = serde_json::to_string(&body)
            .map_err(|e| RpcError::Deserialize(e.to_string()))?;

        let mut last_err = None;
        for (idx, url) in &urls {
            debug!(chain_id = self.chain_id, url, method, "RPC request");
            match self
                .http
                .post(url)
                .header("Content-Type", "application/json")
                .body(body_str.clone())
                .send()
                .await
            {
                Ok(resp) => {
                    let status = resp.status();
                    if !status.is_success() {
                        let msg = format!("HTTP {status}");
                        warn!(chain_id = self.chain_id, url, %msg, "RPC HTTP error");
                        self.endpoints.write().unwrap()[*idx].record_failure();
                        last_err = Some(RpcError::Http(msg));
                        continue;
                    }
                    match resp.json::<JsonRpcResponse>().await {
                        Ok(rpc_resp) => {
                            if let Some(err) = rpc_resp.error {
                                // JSON-RPC level error — don't failover, it's a valid response
                                self.endpoints.write().unwrap()[*idx].record_success();
                                return Err(RpcError::JsonRpc {
                                    code: err.code,
                                    message: err.message,
                                });
                            }
                            self.endpoints.write().unwrap()[*idx].record_success();
                            return Ok(rpc_resp.result.unwrap_or(serde_json::Value::Null));
                        }
                        Err(e) => {
                            warn!(chain_id = self.chain_id, url, %e, "RPC parse error");
                            self.endpoints.write().unwrap()[*idx].record_failure();
                            last_err = Some(RpcError::Deserialize(e.to_string()));
                            continue;
                        }
                    }
                }
                Err(e) => {
                    warn!(chain_id = self.chain_id, url, %e, "RPC connection error");
                    self.endpoints.write().unwrap()[*idx].record_failure();
                    last_err = Some(RpcError::Http(e.to_string()));
                    continue;
                }
            }
        }

        Err(last_err.unwrap_or(RpcError::AllEndpointsFailed {
            chain_id: self.chain_id,
        }))
    }
}

/// EVM JSON-RPC client built on top of RpcPool.
pub struct EvmRpcClient {
    pool: Arc<RpcPool>,
}

impl EvmRpcClient {
    pub fn new(pool: Arc<RpcPool>) -> Self {
        Self { pool }
    }
}

impl RpcClient for EvmRpcClient {
    async fn send_raw_transaction(&self, signed_tx: &str) -> Result<String, RpcError> {
        let result = self
            .pool
            .request("eth_sendRawTransaction", serde_json::json!([signed_tx]))
            .await?;
        result
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| RpcError::Deserialize("expected string tx hash".into()))
    }

    async fn get_balance(&self, address: &str) -> Result<String, RpcError> {
        let cache_key = format!("balance:{}:{}", self.pool.chain_id, address);
        if let Some(cached) = self.pool.get_cached(&cache_key) {
            return cached
                .as_str()
                .map(|s| s.to_string())
                .ok_or_else(|| RpcError::Deserialize("cached value not string".into()));
        }
        let result = self
            .pool
            .request("eth_getBalance", serde_json::json!([address, "latest"]))
            .await?;
        // Cache balance briefly (2s) — it changes with every block
        self.pool
            .set_cached(cache_key, result.clone(), Duration::from_secs(2));
        result
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| RpcError::Deserialize("expected string balance".into()))
    }

    async fn get_nonce(&self, address: &str) -> Result<u64, RpcError> {
        let result = self
            .pool
            .request(
                "eth_getTransactionCount",
                serde_json::json!([address, "pending"]),
            )
            .await?;
        let hex = result
            .as_str()
            .ok_or_else(|| RpcError::Deserialize("expected string nonce".into()))?;
        u64::from_str_radix(hex.trim_start_matches("0x"), 16)
            .map_err(|e| RpcError::Deserialize(format!("invalid nonce hex: {e}")))
    }

    async fn get_block(&self, block_id: &str) -> Result<serde_json::Value, RpcError> {
        // Numbered blocks (not "latest") are immutable — cache longer
        let is_immutable = block_id.starts_with("0x") && block_id != "latest" && block_id != "pending";
        let cache_key = format!("block:{}:{}", self.pool.chain_id, block_id);
        if is_immutable {
            if let Some(cached) = self.pool.get_cached(&cache_key) {
                return Ok(cached);
            }
        }
        let result = self
            .pool
            .request("eth_getBlockByNumber", serde_json::json!([block_id, false]))
            .await?;
        if is_immutable {
            self.pool
                .set_cached(cache_key, result.clone(), Duration::from_secs(3600));
        }
        Ok(result)
    }

    async fn call(&self, to: &str, data: &str) -> Result<String, RpcError> {
        let result = self
            .pool
            .request(
                "eth_call",
                serde_json::json!([{"to": to, "data": data}, "latest"]),
            )
            .await?;
        result
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| RpcError::Deserialize("expected string call result".into()))
    }

    async fn raw_request(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, RpcError> {
        self.pool.request(method, params).await
    }
}

/// Solana RPC client stub — basic structure for future implementation.
pub struct SolanaRpcClient {
    pool: Arc<RpcPool>,
}

impl SolanaRpcClient {
    pub fn new(pool: Arc<RpcPool>) -> Self {
        Self { pool }
    }
}

impl RpcClient for SolanaRpcClient {
    async fn send_raw_transaction(&self, signed_tx: &str) -> Result<String, RpcError> {
        let result = self
            .pool
            .request("sendTransaction", serde_json::json!([signed_tx]))
            .await?;
        result
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| RpcError::Deserialize("expected string signature".into()))
    }

    async fn get_balance(&self, address: &str) -> Result<String, RpcError> {
        let result = self
            .pool
            .request("getBalance", serde_json::json!([address]))
            .await?;
        // Solana returns { value: <lamports> }
        Ok(result.to_string())
    }

    async fn get_nonce(&self, _address: &str) -> Result<u64, RpcError> {
        // Solana uses recent blockhash, not nonces in the EVM sense
        Ok(0)
    }

    async fn get_block(&self, block_id: &str) -> Result<serde_json::Value, RpcError> {
        let slot: u64 = block_id
            .parse()
            .map_err(|_| RpcError::Deserialize("expected slot number".into()))?;
        self.pool
            .request("getBlock", serde_json::json!([slot]))
            .await
    }

    async fn call(&self, _to: &str, _data: &str) -> Result<String, RpcError> {
        // Solana doesn't have eth_call equivalent in the same way
        // Use simulateTransaction instead (future implementation)
        Err(RpcError::JsonRpc {
            code: -1,
            message: "call not supported for Solana; use simulateTransaction".into(),
        })
    }

    async fn raw_request(
        &self,
        method: &str,
        params: serde_json::Value,
    ) -> Result<serde_json::Value, RpcError> {
        self.pool.request(method, params).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicU32, Ordering};

    // Mock HTTP server for testing
    async fn mock_rpc_server(
        port: u16,
        response_body: &'static str,
    ) -> tokio::task::JoinHandle<()> {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        use tokio::net::TcpListener;

        let listener = TcpListener::bind(format!("127.0.0.1:{port}"))
            .await
            .unwrap();

        tokio::spawn(async move {
            // Handle a few connections then exit
            for _ in 0..10 {
                if let Ok((mut stream, _)) = listener.accept().await {
                    let mut buf = vec![0u8; 4096];
                    let _ = stream.read(&mut buf).await;
                    let http_resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                        response_body.len(),
                        response_body
                    );
                    let _ = stream.write_all(http_resp.as_bytes()).await;
                }
            }
        })
    }

    #[test]
    fn test_endpoint_health_tracking() {
        let mut ep = EndpointHealth::new("http://localhost".into());
        assert!(ep.is_healthy());

        ep.record_failure();
        ep.record_failure();
        assert!(ep.is_healthy()); // < 3 failures

        ep.record_failure();
        assert!(!ep.is_healthy()); // 3 failures, recently

        ep.record_success();
        assert!(ep.is_healthy()); // reset
    }

    #[test]
    fn test_cache_expiry() {
        let pool = RpcPool::new(1, vec!["http://localhost".into()]);
        pool.set_cached(
            "test".into(),
            serde_json::json!("value"),
            Duration::from_millis(1),
        );
        // Immediately available
        assert!(pool.get_cached("test").is_some());

        // After expiry
        std::thread::sleep(Duration::from_millis(5));
        assert!(pool.get_cached("test").is_none());
    }

    #[tokio::test]
    async fn test_rpc_pool_no_endpoints() {
        let pool = RpcPool::new(1, vec![]);
        let result = pool.request("eth_blockNumber", serde_json::json!([])).await;
        assert!(matches!(result, Err(RpcError::NoEndpoints(1))));
    }

    #[tokio::test]
    async fn test_rpc_pool_successful_request() {
        let resp = r#"{"jsonrpc":"2.0","result":"0x10","id":1}"#;
        let _server = mock_rpc_server(18545, resp).await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let pool = RpcPool::new(1, vec!["http://127.0.0.1:18545".into()]);
        let result = pool
            .request("eth_blockNumber", serde_json::json!([]))
            .await
            .unwrap();
        assert_eq!(result, serde_json::json!("0x10"));
    }

    #[tokio::test]
    async fn test_rpc_pool_failover() {
        // First endpoint is unreachable, second works
        let resp = r#"{"jsonrpc":"2.0","result":"0xabc","id":1}"#;
        let _server = mock_rpc_server(18546, resp).await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let pool = RpcPool::new(
            1,
            vec![
                "http://127.0.0.1:19999".into(), // dead
                "http://127.0.0.1:18546".into(), // alive
            ],
        );
        let result = pool
            .request("eth_blockNumber", serde_json::json!([]))
            .await
            .unwrap();
        assert_eq!(result, serde_json::json!("0xabc"));

        // First endpoint should have a failure recorded
        let eps = pool.endpoints.read().unwrap();
        assert!(eps[0].failures > 0);
        assert_eq!(eps[1].failures, 0);
    }

    #[tokio::test]
    async fn test_rpc_json_rpc_error() {
        let resp = r#"{"jsonrpc":"2.0","error":{"code":-32600,"message":"Invalid Request"},"id":1}"#;
        let _server = mock_rpc_server(18547, resp).await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let pool = RpcPool::new(1, vec!["http://127.0.0.1:18547".into()]);
        let result = pool.request("eth_bad", serde_json::json!([])).await;
        match result {
            Err(RpcError::JsonRpc { code, .. }) => assert_eq!(code, -32600),
            other => panic!("expected JsonRpc error, got: {other:?}"),
        }
    }

    #[tokio::test]
    async fn test_evm_client_get_nonce() {
        let resp = r#"{"jsonrpc":"2.0","result":"0x2a","id":1}"#;
        let _server = mock_rpc_server(18548, resp).await;
        tokio::time::sleep(Duration::from_millis(50)).await;

        let pool = Arc::new(RpcPool::new(1, vec!["http://127.0.0.1:18548".into()]));
        let client = EvmRpcClient::new(pool);
        let nonce = client.get_nonce("0xabc").await.unwrap();
        assert_eq!(nonce, 42);
    }
}
