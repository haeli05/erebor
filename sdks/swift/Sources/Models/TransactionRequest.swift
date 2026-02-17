import Foundation

/// Transaction parameters for blockchain operations
public struct TransactionRequest: Codable {
    /// Recipient address
    public let to: String
    
    /// Transaction value in wei (for EVM) or lamports (for Solana)
    public let value: String?
    
    /// Transaction data/payload (hex encoded for EVM)
    public let data: String?
    
    /// Chain ID where transaction should be executed
    public let chainId: UInt64
    
    /// Gas limit (EVM only)
    public let gasLimit: String?
    
    /// Gas price (EVM legacy transactions)
    public let gasPrice: String?
    
    /// Max fee per gas (EVM EIP-1559)
    public let maxFeePerGas: String?
    
    /// Max priority fee per gas (EVM EIP-1559)
    public let maxPriorityFeePerGas: String?
    
    /// Transaction nonce (optional, will be determined automatically if not provided)
    public let nonce: UInt64?
    
    /// Token contract address (for token transfers)
    public let tokenAddress: String?
    
    /// Token decimals (for proper amount formatting)
    public let tokenDecimals: Int?
    
    /// Human-readable description of the transaction
    public let description: String?
    
    public init(
        to: String,
        value: String? = nil,
        data: String? = nil,
        chainId: UInt64,
        gasLimit: String? = nil,
        gasPrice: String? = nil,
        maxFeePerGas: String? = nil,
        maxPriorityFeePerGas: String? = nil,
        nonce: UInt64? = nil,
        tokenAddress: String? = nil,
        tokenDecimals: Int? = nil,
        description: String? = nil
    ) {
        self.to = to
        self.value = value
        self.data = data
        self.chainId = chainId
        self.gasLimit = gasLimit
        self.gasPrice = gasPrice
        self.maxFeePerGas = maxFeePerGas
        self.maxPriorityFeePerGas = maxPriorityFeePerGas
        self.nonce = nonce
        self.tokenAddress = tokenAddress
        self.tokenDecimals = tokenDecimals
        self.description = description
    }
}

/// A signed transaction ready for broadcast
public struct SignedTransaction: Codable {
    /// Raw signed transaction data
    public let rawTransaction: String
    
    /// Transaction hash
    public let hash: String
    
    /// Original transaction request
    public let originalRequest: TransactionRequest
    
    /// Wallet ID used for signing
    public let walletId: String
    
    /// Timestamp when transaction was signed
    public let signedAt: Date
    
    public init(
        rawTransaction: String,
        hash: String,
        originalRequest: TransactionRequest,
        walletId: String,
        signedAt: Date = Date()
    ) {
        self.rawTransaction = rawTransaction
        self.hash = hash
        self.originalRequest = originalRequest
        self.walletId = walletId
        self.signedAt = signedAt
    }
}

/// Transaction receipt after broadcast
public struct TransactionReceipt: Codable {
    /// Transaction hash
    public let hash: String
    
    /// Block number where transaction was included
    public let blockNumber: UInt64
    
    /// Block hash
    public let blockHash: String
    
    /// Transaction index within the block
    public let transactionIndex: UInt64
    
    /// Transaction status
    public let status: TransactionStatus
    
    /// Gas used by the transaction
    public let gasUsed: String
    
    /// Effective gas price paid
    public let effectiveGasPrice: String?
    
    /// Contract address created (if contract creation transaction)
    public let contractAddress: String?
    
    /// Event logs emitted by the transaction
    public let logs: [TransactionLog]?
    
    /// Timestamp when receipt was received
    public let receivedAt: Date
    
    public init(
        hash: String,
        blockNumber: UInt64,
        blockHash: String,
        transactionIndex: UInt64,
        status: TransactionStatus,
        gasUsed: String,
        effectiveGasPrice: String? = nil,
        contractAddress: String? = nil,
        logs: [TransactionLog]? = nil,
        receivedAt: Date = Date()
    ) {
        self.hash = hash
        self.blockNumber = blockNumber
        self.blockHash = blockHash
        self.transactionIndex = transactionIndex
        self.status = status
        self.gasUsed = gasUsed
        self.effectiveGasPrice = effectiveGasPrice
        self.contractAddress = contractAddress
        self.logs = logs
        self.receivedAt = receivedAt
    }
}

/// Transaction execution status
public enum TransactionStatus: String, Codable {
    case pending = "pending"
    case success = "success"
    case failed = "failed"
    case cancelled = "cancelled"
    
    /// Whether the transaction is in a final state
    public var isFinal: Bool {
        return self != .pending
    }
    
    /// Whether the transaction was successful
    public var isSuccess: Bool {
        return self == .success
    }
}

/// Transaction log entry
public struct TransactionLog: Codable {
    /// Contract address that emitted the log
    public let address: String
    
    /// Log topics (indexed parameters)
    public let topics: [String]
    
    /// Log data (non-indexed parameters)
    public let data: String
    
    /// Block number
    public let blockNumber: UInt64
    
    /// Transaction hash
    public let transactionHash: String
    
    /// Transaction index
    public let transactionIndex: UInt64
    
    /// Log index within the block
    public let blockHash: String
    
    /// Log index within the transaction
    public let logIndex: UInt64
    
    /// Whether the log was removed due to chain reorganization
    public let removed: Bool
    
    public init(
        address: String,
        topics: [String],
        data: String,
        blockNumber: UInt64,
        transactionHash: String,
        transactionIndex: UInt64,
        blockHash: String,
        logIndex: UInt64,
        removed: Bool = false
    ) {
        self.address = address
        self.topics = topics
        self.data = data
        self.blockNumber = blockNumber
        self.transactionHash = transactionHash
        self.transactionIndex = transactionIndex
        self.blockHash = blockHash
        self.logIndex = logIndex
        self.removed = removed
    }
}