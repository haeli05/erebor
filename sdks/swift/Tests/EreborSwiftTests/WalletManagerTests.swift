import XCTest
@testable import EreborSwift

final class WalletManagerTests: XCTestCase {
    var walletManager: WalletManager!
    var mockAPIClient: MockWalletAPIClient!
    var mockKeychainStore: MockKeychainStore!
    
    override func setUp() {
        super.setUp()
        mockAPIClient = MockWalletAPIClient()
        mockKeychainStore = MockKeychainStore()
        walletManager = WalletManager(apiClient: mockAPIClient, keychainStore: mockKeychainStore)
    }
    
    override func tearDown() {
        walletManager = nil
        mockAPIClient = nil
        mockKeychainStore = nil
        super.tearDown()
    }
    
    // MARK: - Wallet Creation Tests
    
    func testCreateWallet() async throws {
        // Given
        let chainId: UInt64 = 1
        let expectedWallet = createMockWallet(chainId: chainId)
        mockAPIClient.createWalletResult = .success(expectedWallet)
        
        // When
        let wallet = try await walletManager.createWallet(chainId: chainId)
        
        // Then
        XCTAssertEqual(wallet.id, expectedWallet.id)
        XCTAssertEqual(wallet.chainId, chainId)
        XCTAssertEqual(wallet.chainType, .evm)
        XCTAssertEqual(mockAPIClient.createWalletCallCount, 1)
        XCTAssertTrue(walletManager.wallets.contains { $0.id == wallet.id })
    }
    
    func testCreateWalletWithDefaultChain() async throws {
        // Given
        let expectedWallet = createMockWallet(chainId: 1)
        mockAPIClient.createWalletResult = .success(expectedWallet)
        
        // When
        let wallet = try await walletManager.createWallet()
        
        // Then
        XCTAssertEqual(wallet.chainId, 1) // Default Ethereum mainnet
        XCTAssertEqual(walletManager.activeWallet?.id, wallet.id)
    }
    
    func testCreateWalletSetsActiveWallet() async throws {
        // Given
        XCTAssertNil(walletManager.activeWallet)
        let expectedWallet = createMockWallet()
        mockAPIClient.createWalletResult = .success(expectedWallet)
        
        // When
        let wallet = try await walletManager.createWallet()
        
        // Then
        XCTAssertEqual(walletManager.activeWallet?.id, wallet.id)
    }
    
    // MARK: - Wallet Loading Tests
    
    func testLoadWallets() async throws {
        // Given
        let wallets = [
            createMockWallet(id: "wallet-1", chainId: 1),
            createMockWallet(id: "wallet-2", chainId: 137),
            createMockWallet(id: "wallet-3", chainId: 42161)
        ]
        mockAPIClient.listWalletsResult = .success(wallets)
        
        // When
        let loadedWallets = try await walletManager.loadWallets()
        
        // Then
        XCTAssertEqual(loadedWallets.count, 3)
        XCTAssertEqual(walletManager.wallets.count, 3)
        XCTAssertEqual(mockAPIClient.listWalletsCallCount, 1)
        XCTAssertNotNil(walletManager.activeWallet)
    }
    
    func testLoadWalletsEmptyList() async throws {
        // Given
        mockAPIClient.listWalletsResult = .success([])
        
        // When
        let loadedWallets = try await walletManager.loadWallets()
        
        // Then
        XCTAssertTrue(loadedWallets.isEmpty)
        XCTAssertTrue(walletManager.wallets.isEmpty)
        XCTAssertNil(walletManager.activeWallet)
    }
    
    // MARK: - Message Signing Tests
    
    func testSignMessage() async throws {
        // Given
        let wallet = createMockWallet()
        walletManager.wallets = [wallet]
        let message = "Hello, Ethereum!"
        let expectedSignature = "0x1234567890abcdef"
        mockAPIClient.signMessageResult = .success(expectedSignature)
        
        // When
        let signature = try await walletManager.signMessage(wallet.id, message: message)
        
        // Then
        XCTAssertEqual(signature, expectedSignature)
        XCTAssertEqual(mockAPIClient.signMessageCallCount, 1)
        XCTAssertEqual(mockAPIClient.lastSignedMessage, message)
        XCTAssertEqual(mockAPIClient.lastSigningWalletId, wallet.id)
    }
    
    func testSignMessageWithActiveWallet() async throws {
        // Given
        let wallet = createMockWallet()
        walletManager.wallets = [wallet]
        walletManager.activeWallet = wallet
        let message = "Active wallet signing"
        let expectedSignature = "0xabcdef1234567890"
        mockAPIClient.signMessageResult = .success(expectedSignature)
        
        // When
        let signature = try await walletManager.signMessage(message)
        
        // Then
        XCTAssertEqual(signature, expectedSignature)
        XCTAssertEqual(mockAPIClient.lastSigningWalletId, wallet.id)
    }
    
    func testSignMessageWithNonexistentWallet() async {
        // Given
        let nonexistentWalletId = "nonexistent-wallet"
        
        // When/Then
        do {
            _ = try await walletManager.signMessage(nonexistentWalletId, message: "test")
            XCTFail("Should have thrown wallet not found error")
        } catch let error as WalletError {
            if case .walletNotFound(let id) = error {
                XCTAssertEqual(id, nonexistentWalletId)
            } else {
                XCTFail("Wrong error type: \(error)")
            }
        }
    }
    
    func testSignMessageWithNoActiveWallet() async {
        // Given
        XCTAssertNil(walletManager.activeWallet)
        
        // When/Then
        do {
            _ = try await walletManager.signMessage("test message")
            XCTFail("Should have thrown no active wallet error")
        } catch let error as WalletError {
            XCTAssertEqual(error, WalletError.noActiveWallet)
        }
    }
    
    // MARK: - Transaction Signing Tests
    
    func testSignTransaction() async throws {
        // Given
        let wallet = createMockWallet()
        walletManager.wallets = [wallet]
        let transaction = createMockTransaction(chainId: wallet.chainId)
        let expectedSignedTx = "0xsignedtransaction"
        mockAPIClient.signTransactionResult = .success(expectedSignedTx)
        
        // When
        let signedTransaction = try await walletManager.signTransaction(wallet.id, transaction: transaction)
        
        // Then
        XCTAssertEqual(signedTransaction.rawTransaction, expectedSignedTx)
        XCTAssertEqual(signedTransaction.walletId, wallet.id)
        XCTAssertEqual(signedTransaction.originalRequest.to, transaction.to)
        XCTAssertEqual(mockAPIClient.signTransactionCallCount, 1)
    }
    
    func testSignTransactionChainMismatch() async {
        // Given
        let wallet = createMockWallet(chainId: 1)
        walletManager.wallets = [wallet]
        let transaction = createMockTransaction(chainId: 137) // Different chain
        
        // When/Then
        do {
            _ = try await walletManager.signTransaction(wallet.id, transaction: transaction)
            XCTFail("Should have thrown chain mismatch error")
        } catch let error as WalletError {
            if case .chainMismatch(let expected, let actual) = error {
                XCTAssertEqual(expected, 1)
                XCTAssertEqual(actual, 137)
            } else {
                XCTFail("Wrong error type: \(error)")
            }
        }
    }
    
    // MARK: - Transaction Sending Tests
    
    func testSendTransaction() async throws {
        // Given
        let wallet = createMockWallet()
        walletManager.wallets = [wallet]
        let transaction = createMockTransaction(chainId: wallet.chainId)
        let expectedTxHash = "0xtransactionhash123"
        mockAPIClient.sendTransactionResult = .success(expectedTxHash)
        
        // When
        let txHash = try await walletManager.sendTransaction(wallet.id, transaction: transaction)
        
        // Then
        XCTAssertEqual(txHash, expectedTxHash)
        XCTAssertEqual(mockAPIClient.sendTransactionCallCount, 1)
    }
    
    // MARK: - Balance Tests
    
    func testGetWalletBalance() async throws {
        // Given
        let wallet = createMockWallet()
        walletManager.wallets = [wallet]
        let expectedBalance = createMockBalance()
        mockAPIClient.getWalletBalanceResult = .success(expectedBalance)
        
        // When
        let balance = try await walletManager.getWalletBalance(wallet.id)
        
        // Then
        XCTAssertEqual(balance.native, expectedBalance.native)
        XCTAssertEqual(balance.nativeFormatted, expectedBalance.nativeFormatted)
        XCTAssertEqual(mockAPIClient.getWalletBalanceCallCount, 1)
        
        // Check that balance is cached
        let updatedWallet = walletManager.wallets.first { $0.id == wallet.id }
        XCTAssertNotNil(updatedWallet?.cachedBalance)
    }
    
    func testGetActiveWalletBalance() async throws {
        // Given
        let wallet = createMockWallet()
        walletManager.wallets = [wallet]
        walletManager.activeWallet = wallet
        let expectedBalance = createMockBalance()
        mockAPIClient.getWalletBalanceResult = .success(expectedBalance)
        
        // When
        let balance = try await walletManager.getActiveWalletBalance()
        
        // Then
        XCTAssertEqual(balance.nativeFormatted, expectedBalance.nativeFormatted)
    }
    
    func testGetActiveWalletBalanceWithNoActiveWallet() async {
        // Given
        XCTAssertNil(walletManager.activeWallet)
        
        // When/Then
        do {
            _ = try await walletManager.getActiveWalletBalance()
            XCTFail("Should have thrown no active wallet error")
        } catch let error as WalletError {
            XCTAssertEqual(error, WalletError.noActiveWallet)
        }
    }
    
    // MARK: - Wallet Management Tests
    
    func testSetActiveWallet() {
        // Given
        let wallet1 = createMockWallet(id: "wallet-1")
        let wallet2 = createMockWallet(id: "wallet-2")
        walletManager.wallets = [wallet1, wallet2]
        walletManager.activeWallet = wallet1
        
        // When
        walletManager.setActiveWallet(wallet2)
        
        // Then
        XCTAssertEqual(walletManager.activeWallet?.id, wallet2.id)
    }
    
    func testWalletWithId() {
        // Given
        let wallet1 = createMockWallet(id: "wallet-1")
        let wallet2 = createMockWallet(id: "wallet-2")
        walletManager.wallets = [wallet1, wallet2]
        
        // When
        let foundWallet = walletManager.wallet(withId: "wallet-2")
        let notFoundWallet = walletManager.wallet(withId: "nonexistent")
        
        // Then
        XCTAssertEqual(foundWallet?.id, "wallet-2")
        XCTAssertNil(notFoundWallet)
    }
    
    // MARK: - Helper Methods
    
    private func createMockWallet(
        id: String = "test-wallet-id",
        chainId: UInt64 = 1
    ) -> EreborWallet {
        return EreborWallet(
            id: id,
            address: "0x1234567890123456789012345678901234567890",
            chainId: chainId,
            chainType: .evm,
            name: "Test Wallet"
        )
    }
    
    private func createMockTransaction(chainId: UInt64 = 1) -> TransactionRequest {
        return TransactionRequest(
            to: "0x9876543210987654321098765432109876543210",
            value: "1000000000000000000",
            chainId: chainId
        )
    }
    
    private func createMockBalance() -> WalletBalance {
        return WalletBalance(
            native: "2500000000000000000",
            nativeFormatted: "2.5",
            nativeUsd: "5000.00",
            tokens: [
                TokenBalance(
                    address: "0xA0b86a33E6041b53C8f36510423A13E0c2B0E381",
                    symbol: "USDC",
                    name: "USD Coin",
                    decimals: 6,
                    balance: "1000000000",
                    balanceFormatted: "1,000.00",
                    balanceUsd: "1000.00"
                )
            ]
        )
    }
}

// MARK: - Mock API Client

class MockWalletAPIClient: APIClient {
    var createWalletResult: Result<EreborWallet, Error> = .failure(APIError.networkError(URLError(.unknown)))
    var listWalletsResult: Result<[EreborWallet], Error> = .failure(APIError.networkError(URLError(.unknown)))
    var signMessageResult: Result<String, Error> = .failure(APIError.networkError(URLError(.unknown)))
    var signTransactionResult: Result<String, Error> = .failure(APIError.networkError(URLError(.unknown)))
    var sendTransactionResult: Result<String, Error> = .failure(APIError.networkError(URLError(.unknown)))
    var getWalletBalanceResult: Result<WalletBalance, Error> = .failure(APIError.networkError(URLError(.unknown)))
    
    var createWalletCallCount = 0
    var listWalletsCallCount = 0
    var signMessageCallCount = 0
    var signTransactionCallCount = 0
    var sendTransactionCallCount = 0
    var getWalletBalanceCallCount = 0
    
    var lastSignedMessage: String?
    var lastSigningWalletId: String?
    
    override func createWallet(chainId: UInt64?) async throws -> EreborWallet {
        createWalletCallCount += 1
        switch createWalletResult {
        case .success(let wallet):
            return wallet
        case .failure(let error):
            throw error
        }
    }
    
    override func listWallets() async throws -> [EreborWallet] {
        listWalletsCallCount += 1
        switch listWalletsResult {
        case .success(let wallets):
            return wallets
        case .failure(let error):
            throw error
        }
    }
    
    override func signMessage(walletId: String, message: String) async throws -> String {
        signMessageCallCount += 1
        lastSignedMessage = message
        lastSigningWalletId = walletId
        switch signMessageResult {
        case .success(let signature):
            return signature
        case .failure(let error):
            throw error
        }
    }
    
    override func signTransaction(walletId: String, transaction: TransactionRequest) async throws -> String {
        signTransactionCallCount += 1
        switch signTransactionResult {
        case .success(let signedTx):
            return signedTx
        case .failure(let error):
            throw error
        }
    }
    
    override func sendTransaction(walletId: String, transaction: TransactionRequest) async throws -> String {
        sendTransactionCallCount += 1
        switch sendTransactionResult {
        case .success(let txHash):
            return txHash
        case .failure(let error):
            throw error
        }
    }
    
    override func getWalletBalance(walletId: String) async throws -> WalletBalance {
        getWalletBalanceCallCount += 1
        switch getWalletBalanceResult {
        case .success(let balance):
            return balance
        case .failure(let error):
            throw error
        }
    }
}