import Foundation

/// Represents a blockchain wallet managed by Erebor
public struct EreborWallet: Codable, Identifiable, Equatable {
    /// Unique wallet identifier
    public let id: String
    
    /// Wallet's blockchain address
    public let address: String
    
    /// Chain ID this wallet operates on
    public let chainId: UInt64
    
    /// Type of blockchain (EVM, Solana, etc.)
    public let chainType: ChainType
    
    /// Whether this wallet was imported (vs created by Erebor)
    public let imported: Bool
    
    /// Timestamp when the wallet was created/imported
    public let createdAt: Date
    
    /// Optional wallet name/label set by user
    public let name: String?
    
    /// Whether this wallet is active/enabled
    public let isActive: Bool
    
    /// Derivation path (for hierarchical deterministic wallets)
    public let derivationPath: String?
    
    /// Cached balance information (may be stale)
    public var cachedBalance: WalletBalance?
    
    /// Shortened display version of the address
    public var displayAddress: String {
        guard address.count > 10 else { return address }
        let start = address.prefix(6)
        let end = address.suffix(4)
        return "\(start)...\(end)"
    }
    
    /// Whether this wallet supports message signing
    public var supportsMessageSigning: Bool {
        return chainType == .evm || chainType == .solana
    }
    
    /// Whether this wallet supports contract interactions
    public var supportsContracts: Bool {
        return chainType == .evm
    }
    
    public init(
        id: String,
        address: String,
        chainId: UInt64,
        chainType: ChainType,
        imported: Bool = false,
        createdAt: Date = Date(),
        name: String? = nil,
        isActive: Bool = true,
        derivationPath: String? = nil
    ) {
        self.id = id
        self.address = address
        self.chainId = chainId
        self.chainType = chainType
        self.imported = imported
        self.createdAt = createdAt
        self.name = name
        self.isActive = isActive
        self.derivationPath = derivationPath
    }
}

/// Supported blockchain types
public enum ChainType: String, Codable, CaseIterable {
    case evm = "evm"
    case solana = "solana"
    case bitcoin = "bitcoin"
    
    /// Display name for the chain type
    public var displayName: String {
        switch self {
        case .evm:
            return "Ethereum"
        case .solana:
            return "Solana"
        case .bitcoin:
            return "Bitcoin"
        }
    }
}

/// Wallet balance information
public struct WalletBalance: Codable, Equatable {
    /// Native token balance (in wei for EVM, lamports for Solana, etc.)
    public let native: String
    
    /// Native balance formatted as decimal string
    public let nativeFormatted: String
    
    /// USD value of native balance
    public let nativeUsd: String?
    
    /// Token balances (ERC-20, SPL, etc.)
    public let tokens: [TokenBalance]
    
    /// Timestamp when balance was last updated
    public let lastUpdated: Date
    
    public init(
        native: String,
        nativeFormatted: String,
        nativeUsd: String? = nil,
        tokens: [TokenBalance] = [],
        lastUpdated: Date = Date()
    ) {
        self.native = native
        self.nativeFormatted = nativeFormatted
        self.nativeUsd = nativeUsd
        self.tokens = tokens
        self.lastUpdated = lastUpdated
    }
}

/// Individual token balance
public struct TokenBalance: Codable, Equatable, Identifiable {
    /// Token contract address
    public let address: String
    
    /// Token symbol (e.g., "USDC")
    public let symbol: String
    
    /// Token name (e.g., "USD Coin")
    public let name: String
    
    /// Number of decimal places
    public let decimals: Int
    
    /// Raw balance (in smallest unit)
    public let balance: String
    
    /// Formatted balance as decimal
    public let balanceFormatted: String
    
    /// USD value of balance
    public let balanceUsd: String?
    
    /// Token logo URL
    public let logoUrl: String?
    
    public var id: String { address }
    
    public init(
        address: String,
        symbol: String,
        name: String,
        decimals: Int,
        balance: String,
        balanceFormatted: String,
        balanceUsd: String? = nil,
        logoUrl: String? = nil
    ) {
        self.address = address
        self.symbol = symbol
        self.name = name
        self.decimals = decimals
        self.balance = balance
        self.balanceFormatted = balanceFormatted
        self.balanceUsd = balanceUsd
        self.logoUrl = logoUrl
    }
}