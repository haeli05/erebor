import Foundation

/// Manages wallet operations including creation, signing, and transactions
public class WalletManager: ObservableObject {
    private let apiClient: APIClient
    private let keychainStore: KeychainStore
    private let biometricGate: BiometricGate
    private let deviceKeyManager: DeviceKeyManager
    
    /// Available wallets for the current user
    @Published public private(set) var wallets: [EreborWallet] = []
    
    /// Currently active/selected wallet
    @Published public var activeWallet: EreborWallet?
    
    /// Loading state for wallet operations
    @Published public private(set) var isLoading: Bool = false
    
    /// Last wallet operation error
    @Published public private(set) var lastError: Error?
    
    init(apiClient: APIClient, keychainStore: KeychainStore) {
        self.apiClient = apiClient
        self.keychainStore = keychainStore
        self.biometricGate = BiometricGate()
        self.deviceKeyManager = DeviceKeyManager(keychainStore: keychainStore)
    }
    
    // MARK: - Wallet Management
    
    /// Create a new wallet
    /// - Parameter chainId: Optional chain ID for the wallet (defaults to Ethereum mainnet)
    /// - Returns: Created wallet
    public func createWallet(chainId: UInt64? = 1) async throws -> EreborWallet {
        isLoading = true
        lastError = nil
        
        defer { isLoading = false }
        
        do {
            let wallet = try await apiClient.createWallet(chainId: chainId)
            
            await MainActor.run {
                self.wallets.append(wallet)
                if self.activeWallet == nil {
                    self.activeWallet = wallet
                }
            }
            
            return wallet
        } catch {
            lastError = error
            throw error
        }
    }
    
    /// Load wallets for the current user
    /// - Returns: Array of user's wallets
    public func loadWallets() async throws -> [EreborWallet] {
        isLoading = true
        lastError = nil
        
        defer { isLoading = false }
        
        do {
            let wallets = try await apiClient.listWallets()
            
            await MainActor.run {
                self.wallets = wallets
                if self.activeWallet == nil && !wallets.isEmpty {
                    self.activeWallet = wallets.first
                }
            }
            
            return wallets
        } catch {
            lastError = error
            throw error
        }
    }
    
    /// Set the active wallet
    /// - Parameter wallet: Wallet to set as active
    public func setActiveWallet(_ wallet: EreborWallet) {
        activeWallet = wallet
    }
    
    /// Get wallet by ID
    /// - Parameter id: Wallet identifier
    /// - Returns: Wallet if found
    public func wallet(withId id: String) -> EreborWallet? {
        return wallets.first { $0.id == id }
    }
    
    // MARK: - Message Signing
    
    /// Sign a message with the specified wallet
    /// - Parameters:
    ///   - walletId: Wallet ID to use for signing
    ///   - message: Message to sign
    /// - Returns: Signature string
    public func signMessage(_ walletId: String, message: String) async throws -> String {
        guard let wallet = wallets.first(where: { $0.id == walletId }) else {
            throw WalletError.walletNotFound(walletId)
        }
        
        guard wallet.supportsMessageSigning else {
            throw WalletError.operationNotSupported("Message signing not supported for \(wallet.chainType.displayName)")
        }
        
        // Require biometric authentication
        if Erebor.shared.config?.requireBiometricForSigning == true {
            try await requireBiometricAuthentication(for: "Sign message with \(wallet.displayAddress)")
        }
        
        isLoading = true
        lastError = nil
        
        defer { isLoading = false }
        
        do {
            let signature = try await apiClient.signMessage(walletId: walletId, message: message)
            return signature
        } catch {
            lastError = error
            throw error
        }
    }
    
    /// Sign a message with the active wallet
    /// - Parameter message: Message to sign
    /// - Returns: Signature string
    public func signMessage(_ message: String) async throws -> String {
        guard let activeWallet = activeWallet else {
            throw WalletError.noActiveWallet
        }
        return try await signMessage(activeWallet.id, message: message)
    }
    
    // MARK: - Transaction Signing
    
    /// Sign a transaction with the specified wallet
    /// - Parameters:
    ///   - walletId: Wallet ID to use for signing
    ///   - transaction: Transaction to sign
    /// - Returns: Signed transaction
    public func signTransaction(_ walletId: String, transaction: TransactionRequest) async throws -> SignedTransaction {
        guard let wallet = wallets.first(where: { $0.id == walletId }) else {
            throw WalletError.walletNotFound(walletId)
        }
        
        // Validate transaction for wallet's chain
        guard wallet.chainId == transaction.chainId else {
            throw WalletError.chainMismatch(expected: wallet.chainId, actual: transaction.chainId)
        }
        
        // Require biometric authentication
        if Erebor.shared.config?.requireBiometricForSigning == true {
            try await requireBiometricAuthentication(for: "Sign transaction with \(wallet.displayAddress)")
        }
        
        isLoading = true
        lastError = nil
        
        defer { isLoading = false }
        
        do {
            let signedTxData = try await apiClient.signTransaction(walletId: walletId, transaction: transaction)
            
            let signedTransaction = SignedTransaction(
                rawTransaction: signedTxData,
                hash: calculateTransactionHash(signedTxData),
                originalRequest: transaction,
                walletId: walletId
            )
            
            return signedTransaction
        } catch {
            lastError = error
            throw error
        }
    }
    
    /// Sign a transaction with the active wallet
    /// - Parameter transaction: Transaction to sign
    /// - Returns: Signed transaction
    public func signTransaction(_ transaction: TransactionRequest) async throws -> SignedTransaction {
        guard let activeWallet = activeWallet else {
            throw WalletError.noActiveWallet
        }
        return try await signTransaction(activeWallet.id, transaction: transaction)
    }
    
    // MARK: - Transaction Sending
    
    /// Send a transaction with the specified wallet
    /// - Parameters:
    ///   - walletId: Wallet ID to use for sending
    ///   - transaction: Transaction to send
    /// - Returns: Transaction hash
    public func sendTransaction(_ walletId: String, transaction: TransactionRequest) async throws -> String {
        guard let wallet = wallets.first(where: { $0.id == walletId }) else {
            throw WalletError.walletNotFound(walletId)
        }
        
        // Validate transaction for wallet's chain
        guard wallet.chainId == transaction.chainId else {
            throw WalletError.chainMismatch(expected: wallet.chainId, actual: transaction.chainId)
        }
        
        // Require biometric authentication
        if Erebor.shared.config?.requireBiometricForSigning == true {
            try await requireBiometricAuthentication(for: "Send transaction from \(wallet.displayAddress)")
        }
        
        isLoading = true
        lastError = nil
        
        defer { isLoading = false }
        
        do {
            let txHash = try await apiClient.sendTransaction(walletId: walletId, transaction: transaction)
            return txHash
        } catch {
            lastError = error
            throw error
        }
    }
    
    /// Send a transaction with the active wallet
    /// - Parameter transaction: Transaction to send
    /// - Returns: Transaction hash
    public func sendTransaction(_ transaction: TransactionRequest) async throws -> String {
        guard let activeWallet = activeWallet else {
            throw WalletError.noActiveWallet
        }
        return try await sendTransaction(activeWallet.id, transaction: transaction)
    }
    
    // MARK: - Balance Management
    
    /// Get wallet balance
    /// - Parameter walletId: Wallet ID
    /// - Returns: Wallet balance information
    public func getWalletBalance(_ walletId: String) async throws -> WalletBalance {
        isLoading = true
        lastError = nil
        
        defer { isLoading = false }
        
        do {
            let balance = try await apiClient.getWalletBalance(walletId: walletId)
            
            // Update cached balance
            await MainActor.run {
                if let index = self.wallets.firstIndex(where: { $0.id == walletId }) {
                    var updatedWallet = self.wallets[index]
                    updatedWallet.cachedBalance = balance
                    self.wallets[index] = updatedWallet
                    
                    if self.activeWallet?.id == walletId {
                        self.activeWallet?.cachedBalance = balance
                    }
                }
            }
            
            return balance
        } catch {
            lastError = error
            throw error
        }
    }
    
    /// Get balance for the active wallet
    /// - Returns: Wallet balance information
    public func getActiveWalletBalance() async throws -> WalletBalance {
        guard let activeWallet = activeWallet else {
            throw WalletError.noActiveWallet
        }
        return try await getWalletBalance(activeWallet.id)
    }
    
    // MARK: - Private Helpers
    
    private func requireBiometricAuthentication(for reason: String) async throws {
        guard biometricGate.isAvailable else {
            throw EreborError.biometricNotAvailable
        }
        
        let success = try await biometricGate.authenticate(reason: reason)
        if !success {
            throw EreborError.userCancelled
        }
    }
    
    private func calculateTransactionHash(_ rawTransaction: String) -> String {
        // For EVM transactions, this would involve keccak256 hashing
        // For simplicity, we'll use a basic hash here
        // In production, implement proper transaction hash calculation
        return rawTransaction.sha256
    }
}

// MARK: - Error Types

public enum WalletError: LocalizedError {
    case walletNotFound(String)
    case noActiveWallet
    case operationNotSupported(String)
    case chainMismatch(expected: UInt64, actual: UInt64)
    case insufficientBalance
    case invalidTransaction(String)
    case signingFailed(Error)
    case transactionFailed(Error)
    case biometricRequired
    case networkError(Error)
    
    public var errorDescription: String? {
        switch self {
        case .walletNotFound(let id):
            return "Wallet with ID '\(id)' not found."
        case .noActiveWallet:
            return "No active wallet selected. Please create or select a wallet."
        case .operationNotSupported(let operation):
            return "Operation not supported: \(operation)"
        case .chainMismatch(let expected, let actual):
            return "Chain mismatch: expected \(expected), got \(actual)"
        case .insufficientBalance:
            return "Insufficient balance to complete the transaction."
        case .invalidTransaction(let reason):
            return "Invalid transaction: \(reason)"
        case .signingFailed(let error):
            return "Transaction signing failed: \(error.localizedDescription)"
        case .transactionFailed(let error):
            return "Transaction failed: \(error.localizedDescription)"
        case .biometricRequired:
            return "Biometric authentication is required for this operation."
        case .networkError(let error):
            return "Network error: \(error.localizedDescription)"
        }
    }
}

// MARK: - String Extension for Basic Hashing

private extension String {
    var sha256: String {
        let data = self.data(using: .utf8)!
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes {
            _ = CC_SHA256($0.baseAddress, CC_LONG(data.count), &hash)
        }
        return Data(hash).map { String(format: "%02hhx", $0) }.joined()
    }
}

import CommonCrypto