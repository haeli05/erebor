import Foundation

/// Blockchain network configuration
public struct Chain: Codable, Identifiable, Equatable {
    /// Unique chain identifier
    public let id: UInt64
    
    /// Human-readable chain name
    public let name: String
    
    /// RPC endpoint URL for connecting to the network
    public let rpcUrl: String
    
    /// Chain type (EVM, Solana, etc.)
    public let chainType: ChainType
    
    /// Native currency information
    public let nativeCurrency: NativeCurrency
    
    /// Block explorer base URL
    public let blockExplorer: String?
    
    /// Whether this is a testnet
    public let isTestnet: Bool
    
    /// Network icon/logo URL
    public let iconUrl: String?
    
    /// Average block time in seconds
    public let averageBlockTime: Double?
    
    /// Gas price configuration
    public let gasPrice: GasPriceConfig?
    
    /// Maximum gas limit for transactions
    public let maxGasLimit: String?
    
    /// Whether the chain is currently active/enabled
    public let isActive: Bool
    
    public init(
        id: UInt64,
        name: String,
        rpcUrl: String,
        chainType: ChainType,
        nativeCurrency: NativeCurrency,
        blockExplorer: String? = nil,
        isTestnet: Bool = false,
        iconUrl: String? = nil,
        averageBlockTime: Double? = nil,
        gasPrice: GasPriceConfig? = nil,
        maxGasLimit: String? = nil,
        isActive: Bool = true
    ) {
        self.id = id
        self.name = name
        self.rpcUrl = rpcUrl
        self.chainType = chainType
        self.nativeCurrency = nativeCurrency
        self.blockExplorer = blockExplorer
        self.isTestnet = isTestnet
        self.iconUrl = iconUrl
        self.averageBlockTime = averageBlockTime
        self.gasPrice = gasPrice
        self.maxGasLimit = maxGasLimit
        self.isActive = isActive
    }
}

/// Native currency of a blockchain
public struct NativeCurrency: Codable, Equatable {
    /// Currency name (e.g., "Ether")
    public let name: String
    
    /// Currency symbol (e.g., "ETH")
    public let symbol: String
    
    /// Number of decimal places
    public let decimals: Int
    
    public init(name: String, symbol: String, decimals: Int) {
        self.name = name
        self.symbol = symbol
        self.decimals = decimals
    }
}

/// Gas price configuration for EVM chains
public struct GasPriceConfig: Codable, Equatable {
    /// Default gas price (in wei)
    public let defaultGasPrice: String?
    
    /// Fast gas price (in wei)
    public let fastGasPrice: String?
    
    /// Safe gas price (in wei) 
    public let safeGasPrice: String?
    
    /// Whether to use EIP-1559 pricing
    public let supportsEIP1559: Bool
    
    /// Default max fee per gas (EIP-1559)
    public let defaultMaxFeePerGas: String?
    
    /// Default max priority fee per gas (EIP-1559)
    public let defaultMaxPriorityFeePerGas: String?
    
    public init(
        defaultGasPrice: String? = nil,
        fastGasPrice: String? = nil,
        safeGasPrice: String? = nil,
        supportsEIP1559: Bool = false,
        defaultMaxFeePerGas: String? = nil,
        defaultMaxPriorityFeePerGas: String? = nil
    ) {
        self.defaultGasPrice = defaultGasPrice
        self.fastGasPrice = fastGasPrice
        self.safeGasPrice = safeGasPrice
        self.supportsEIP1559 = supportsEIP1559
        self.defaultMaxFeePerGas = defaultMaxFeePerGas
        self.defaultMaxPriorityFeePerGas = defaultMaxPriorityFeePerGas
    }
}

// MARK: - Common Chains

public extension Chain {
    /// Ethereum Mainnet
    static let ethereum = Chain(
        id: 1,
        name: "Ethereum",
        rpcUrl: "https://mainnet.infura.io/v3/",
        chainType: .evm,
        nativeCurrency: NativeCurrency(name: "Ether", symbol: "ETH", decimals: 18),
        blockExplorer: "https://etherscan.io",
        averageBlockTime: 12.0,
        gasPrice: GasPriceConfig(supportsEIP1559: true)
    )
    
    /// Ethereum Sepolia Testnet
    static let sepolia = Chain(
        id: 11155111,
        name: "Sepolia",
        rpcUrl: "https://sepolia.infura.io/v3/",
        chainType: .evm,
        nativeCurrency: NativeCurrency(name: "Sepolia Ether", symbol: "ETH", decimals: 18),
        blockExplorer: "https://sepolia.etherscan.io",
        isTestnet: true,
        averageBlockTime: 12.0,
        gasPrice: GasPriceConfig(supportsEIP1559: true)
    )
    
    /// Polygon Mainnet
    static let polygon = Chain(
        id: 137,
        name: "Polygon",
        rpcUrl: "https://polygon-rpc.com",
        chainType: .evm,
        nativeCurrency: NativeCurrency(name: "MATIC", symbol: "MATIC", decimals: 18),
        blockExplorer: "https://polygonscan.com",
        averageBlockTime: 2.0,
        gasPrice: GasPriceConfig(supportsEIP1559: true)
    )
    
    /// Arbitrum One
    static let arbitrum = Chain(
        id: 42161,
        name: "Arbitrum One",
        rpcUrl: "https://arb1.arbitrum.io/rpc",
        chainType: .evm,
        nativeCurrency: NativeCurrency(name: "Ether", symbol: "ETH", decimals: 18),
        blockExplorer: "https://arbiscan.io",
        averageBlockTime: 0.25
    )
    
    /// Optimism Mainnet
    static let optimism = Chain(
        id: 10,
        name: "Optimism",
        rpcUrl: "https://mainnet.optimism.io",
        chainType: .evm,
        nativeCurrency: NativeCurrency(name: "Ether", symbol: "ETH", decimals: 18),
        blockExplorer: "https://optimistic.etherscan.io",
        averageBlockTime: 2.0
    )
    
    /// Base Mainnet
    static let base = Chain(
        id: 8453,
        name: "Base",
        rpcUrl: "https://mainnet.base.org",
        chainType: .evm,
        nativeCurrency: NativeCurrency(name: "Ether", symbol: "ETH", decimals: 18),
        blockExplorer: "https://basescan.org",
        averageBlockTime: 2.0
    )
    
    /// Common mainnet chains
    static let mainnetChains: [Chain] = [
        .ethereum,
        .polygon,
        .arbitrum,
        .optimism,
        .base
    ]
    
    /// Common testnet chains
    static let testnetChains: [Chain] = [
        .sepolia
    ]
    
    /// All predefined chains
    static let allChains: [Chain] = mainnetChains + testnetChains
}