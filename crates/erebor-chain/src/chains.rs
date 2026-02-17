use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::sync::{Arc, RwLock};
use thiserror::Error;

#[derive(Error, Debug)]
pub enum ChainError {
    #[error("chain not found: {0}")]
    NotFound(String),
    #[error("chain already exists: {0}")]
    AlreadyExists(u64),
}

/// Native currency metadata.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct NativeCurrency {
    pub name: String,
    pub symbol: String,
    pub decimals: u8,
}

/// Identifies the chain network type.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "snake_case")]
pub enum ChainType {
    Evm,
    Solana,
}

/// Configuration for a single blockchain network.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainConfig {
    pub chain_id: u64,
    pub name: String,
    pub chain_type: ChainType,
    pub rpc_urls: Vec<String>,
    pub native_currency: NativeCurrency,
    pub block_explorer: Option<String>,
    pub is_testnet: bool,
    /// Whether the chain supports EIP-1559 fee market.
    pub supports_eip1559: bool,
}

/// Thread-safe chain registry with pre-configured and custom chains.
#[derive(Clone)]
pub struct ChainRegistry {
    chains: Arc<RwLock<HashMap<u64, ChainConfig>>>,
}

impl ChainRegistry {
    /// Create a new registry pre-loaded with well-known chains.
    pub fn new() -> Self {
        let mut map = HashMap::new();
        for chain in Self::default_chains() {
            map.insert(chain.chain_id, chain);
        }
        Self {
            chains: Arc::new(RwLock::new(map)),
        }
    }

    /// Create an empty registry (useful for tests).
    pub fn empty() -> Self {
        Self {
            chains: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    pub fn get_chain(&self, chain_id: u64) -> Result<ChainConfig, ChainError> {
        self.chains
            .read()
            .unwrap()
            .get(&chain_id)
            .cloned()
            .ok_or_else(|| ChainError::NotFound(format!("chain_id={chain_id}")))
    }

    pub fn list_chains(&self) -> Vec<ChainConfig> {
        self.chains.read().unwrap().values().cloned().collect()
    }

    pub fn add_custom_chain(&self, config: ChainConfig) -> Result<(), ChainError> {
        let mut chains = self.chains.write().unwrap();
        if chains.contains_key(&config.chain_id) {
            return Err(ChainError::AlreadyExists(config.chain_id));
        }
        chains.insert(config.chain_id, config);
        Ok(())
    }

    fn default_chains() -> Vec<ChainConfig> {
        vec![
            // Ethereum Mainnet
            ChainConfig {
                chain_id: 1,
                name: "Ethereum".into(),
                chain_type: ChainType::Evm,
                rpc_urls: vec!["https://eth.llamarpc.com".into()],
                native_currency: NativeCurrency {
                    name: "Ether".into(),
                    symbol: "ETH".into(),
                    decimals: 18,
                },
                block_explorer: Some("https://etherscan.io".into()),
                is_testnet: false,
                supports_eip1559: true,
            },
            // Base
            ChainConfig {
                chain_id: 8453,
                name: "Base".into(),
                chain_type: ChainType::Evm,
                rpc_urls: vec!["https://mainnet.base.org".into()],
                native_currency: NativeCurrency {
                    name: "Ether".into(),
                    symbol: "ETH".into(),
                    decimals: 18,
                },
                block_explorer: Some("https://basescan.org".into()),
                is_testnet: false,
                supports_eip1559: true,
            },
            // Polygon
            ChainConfig {
                chain_id: 137,
                name: "Polygon".into(),
                chain_type: ChainType::Evm,
                rpc_urls: vec!["https://polygon-rpc.com".into()],
                native_currency: NativeCurrency {
                    name: "POL".into(),
                    symbol: "POL".into(),
                    decimals: 18,
                },
                block_explorer: Some("https://polygonscan.com".into()),
                is_testnet: false,
                supports_eip1559: true,
            },
            // Arbitrum One
            ChainConfig {
                chain_id: 42161,
                name: "Arbitrum One".into(),
                chain_type: ChainType::Evm,
                rpc_urls: vec!["https://arb1.arbitrum.io/rpc".into()],
                native_currency: NativeCurrency {
                    name: "Ether".into(),
                    symbol: "ETH".into(),
                    decimals: 18,
                },
                block_explorer: Some("https://arbiscan.io".into()),
                is_testnet: false,
                supports_eip1559: true,
            },
            // Optimism
            ChainConfig {
                chain_id: 10,
                name: "Optimism".into(),
                chain_type: ChainType::Evm,
                rpc_urls: vec!["https://mainnet.optimism.io".into()],
                native_currency: NativeCurrency {
                    name: "Ether".into(),
                    symbol: "ETH".into(),
                    decimals: 18,
                },
                block_explorer: Some("https://optimistic.etherscan.io".into()),
                is_testnet: false,
                supports_eip1559: true,
            },
            // Sepolia (testnet)
            ChainConfig {
                chain_id: 11155111,
                name: "Sepolia".into(),
                chain_type: ChainType::Evm,
                rpc_urls: vec!["https://rpc.sepolia.org".into()],
                native_currency: NativeCurrency {
                    name: "Sepolia Ether".into(),
                    symbol: "ETH".into(),
                    decimals: 18,
                },
                block_explorer: Some("https://sepolia.etherscan.io".into()),
                is_testnet: true,
                supports_eip1559: true,
            },
            // Solana Mainnet — uses a synthetic chain_id (not EVM)
            ChainConfig {
                chain_id: 900001,
                name: "Solana".into(),
                chain_type: ChainType::Solana,
                rpc_urls: vec!["https://api.mainnet-beta.solana.com".into()],
                native_currency: NativeCurrency {
                    name: "SOL".into(),
                    symbol: "SOL".into(),
                    decimals: 9,
                },
                block_explorer: Some("https://explorer.solana.com".into()),
                is_testnet: false,
                supports_eip1559: false,
            },
        ]
    }
}

impl Default for ChainRegistry {
    fn default() -> Self {
        Self::new()
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_default_registry_contains_known_chains() {
        let reg = ChainRegistry::new();
        let chains = reg.list_chains();
        assert!(chains.len() >= 7);

        // Ethereum
        let eth = reg.get_chain(1).unwrap();
        assert_eq!(eth.name, "Ethereum");
        assert_eq!(eth.chain_type, ChainType::Evm);
        assert!(!eth.is_testnet);

        // Base
        let base = reg.get_chain(8453).unwrap();
        assert_eq!(base.name, "Base");

        // Sepolia is testnet
        let sep = reg.get_chain(11155111).unwrap();
        assert!(sep.is_testnet);

        // Solana
        let sol = reg.get_chain(900001).unwrap();
        assert_eq!(sol.chain_type, ChainType::Solana);
        assert_eq!(sol.native_currency.decimals, 9);
    }

    #[test]
    fn test_get_chain_not_found() {
        let reg = ChainRegistry::new();
        assert!(reg.get_chain(999999).is_err());
    }

    #[test]
    fn test_add_custom_chain() {
        let reg = ChainRegistry::new();
        let custom = ChainConfig {
            chain_id: 43114,
            name: "Avalanche C-Chain".into(),
            chain_type: ChainType::Evm,
            rpc_urls: vec!["https://api.avax.network/ext/bc/C/rpc".into()],
            native_currency: NativeCurrency {
                name: "AVAX".into(),
                symbol: "AVAX".into(),
                decimals: 18,
            },
            block_explorer: Some("https://snowtrace.io".into()),
            is_testnet: false,
            supports_eip1559: true,
        };
        reg.add_custom_chain(custom).unwrap();
        let avax = reg.get_chain(43114).unwrap();
        assert_eq!(avax.name, "Avalanche C-Chain");
    }

    #[test]
    fn test_add_duplicate_chain_fails() {
        let reg = ChainRegistry::new();
        let dup = ChainConfig {
            chain_id: 1,
            name: "Duplicate".into(),
            chain_type: ChainType::Evm,
            rpc_urls: vec![],
            native_currency: NativeCurrency {
                name: "X".into(),
                symbol: "X".into(),
                decimals: 18,
            },
            block_explorer: None,
            is_testnet: false,
            supports_eip1559: false,
        };
        assert!(reg.add_custom_chain(dup).is_err());
    }

    #[test]
    fn test_empty_registry() {
        let reg = ChainRegistry::empty();
        assert!(reg.list_chains().is_empty());
        assert!(reg.get_chain(1).is_err());
    }

    #[test]
    fn test_registry_is_clone_safe() {
        let reg = ChainRegistry::new();
        let reg2 = reg.clone();
        let custom = ChainConfig {
            chain_id: 56,
            name: "BSC".into(),
            chain_type: ChainType::Evm,
            rpc_urls: vec![],
            native_currency: NativeCurrency {
                name: "BNB".into(),
                symbol: "BNB".into(),
                decimals: 18,
            },
            block_explorer: None,
            is_testnet: false,
            supports_eip1559: false,
        };
        reg.add_custom_chain(custom).unwrap();
        // Clone shares the Arc, so both see the update
        assert!(reg2.get_chain(56).is_ok());
    }
}
