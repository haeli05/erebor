import XCTest
@testable import EreborSwift

final class KeychainStoreTests: XCTestCase {
    var keychainStore: KeychainStore!
    
    override func setUp() {
        super.setUp()
        // Use a unique service identifier for testing to avoid conflicts
        keychainStore = KeychainStore(serviceIdentifier: "erebor-test-\(UUID().uuidString)")
    }
    
    override func tearDown() {
        // Clean up any test data
        keychainStore?.clearAll()
        keychainStore = nil
        super.tearDown()
    }
    
    // MARK: - Token Storage Tests
    
    func testSaveAndLoadTokens() {
        // Given
        let tokens = AuthTokens(
            accessToken: "test-access-token",
            refreshToken: "test-refresh-token",
            expiresIn: 3600
        )
        
        // When
        keychainStore.saveTokens(tokens)
        let loadedTokens = keychainStore.loadTokens()
        
        // Then
        XCTAssertNotNil(loadedTokens)
        XCTAssertEqual(loadedTokens?.accessToken, tokens.accessToken)
        XCTAssertEqual(loadedTokens?.refreshToken, tokens.refreshToken)
        XCTAssertEqual(loadedTokens?.expiresIn, tokens.expiresIn)
    }
    
    func testLoadTokensWhenNoneExist() {
        // When
        let tokens = keychainStore.loadTokens()
        
        // Then
        XCTAssertNil(tokens)
    }
    
    func testClearTokens() {
        // Given
        let tokens = AuthTokens(
            accessToken: "test-access-token",
            refreshToken: "test-refresh-token",
            expiresIn: 3600
        )
        keychainStore.saveTokens(tokens)
        XCTAssertNotNil(keychainStore.loadTokens())
        
        // When
        keychainStore.clearTokens()
        
        // Then
        XCTAssertNil(keychainStore.loadTokens())
    }
    
    func testOverwriteExistingTokens() {
        // Given
        let originalTokens = AuthTokens(
            accessToken: "original-access-token",
            refreshToken: "original-refresh-token",
            expiresIn: 3600
        )
        keychainStore.saveTokens(originalTokens)
        
        let newTokens = AuthTokens(
            accessToken: "new-access-token",
            refreshToken: "new-refresh-token",
            expiresIn: 7200
        )
        
        // When
        keychainStore.saveTokens(newTokens)
        let loadedTokens = keychainStore.loadTokens()
        
        // Then
        XCTAssertNotNil(loadedTokens)
        XCTAssertEqual(loadedTokens?.accessToken, newTokens.accessToken)
        XCTAssertEqual(loadedTokens?.refreshToken, newTokens.refreshToken)
        XCTAssertEqual(loadedTokens?.expiresIn, newTokens.expiresIn)
        XCTAssertNotEqual(loadedTokens?.accessToken, originalTokens.accessToken)
    }
    
    // MARK: - Device Key Share Tests
    
    func testSaveAndLoadDeviceKeyShare() {
        // Given
        let keyShareData = Data("test-key-share".utf8)
        
        // When
        do {
            try keychainStore.saveDeviceKeyShare(keyShareData, requiresBiometric: false)
            let loadedKeyShare = try keychainStore.loadDeviceKeyShare()
            
            // Then
            XCTAssertEqual(loadedKeyShare, keyShareData)
        } catch {
            XCTFail("Should not throw error: \(error)")
        }
    }
    
    func testLoadDeviceKeyShareWhenNoneExists() {
        // When/Then
        do {
            _ = try keychainStore.loadDeviceKeyShare()
            XCTFail("Should throw error when no key share exists")
        } catch let error as KeychainError {
            // Expected to throw KeychainError
            XCTAssertTrue(true, "Correctly threw KeychainError: \(error)")
        } catch {
            XCTFail("Wrong error type: \(error)")
        }
    }
    
    func testClearDeviceKeyShare() {
        // Given
        let keyShareData = Data("test-key-share".utf8)
        do {
            try keychainStore.saveDeviceKeyShare(keyShareData, requiresBiometric: false)
            _ = try keychainStore.loadDeviceKeyShare() // Verify it exists
        } catch {
            XCTFail("Setup failed: \(error)")
        }
        
        // When
        keychainStore.clearDeviceKeyShare()
        
        // Then
        do {
            _ = try keychainStore.loadDeviceKeyShare()
            XCTFail("Should throw error after clearing")
        } catch {
            // Expected to throw error
            XCTAssertTrue(true, "Correctly threw error after clearing")
        }
    }
    
    // MARK: - Item Existence Tests
    
    func testItemExistsForTokens() {
        // Given
        let tokens = AuthTokens(
            accessToken: "test-access-token",
            refreshToken: "test-refresh-token",
            expiresIn: 3600
        )
        
        // When
        let existsBeforeSaving = keychainStore.itemExists(key: "auth_tokens")
        keychainStore.saveTokens(tokens)
        let existsAfterSaving = keychainStore.itemExists(key: "auth_tokens")
        keychainStore.clearTokens()
        let existsAfterClearing = keychainStore.itemExists(key: "auth_tokens")
        
        // Then
        XCTAssertFalse(existsBeforeSaving)
        XCTAssertTrue(existsAfterSaving)
        XCTAssertFalse(existsAfterClearing)
    }
    
    func testItemExistsForDeviceKeyShare() {
        // Given
        let keyShareData = Data("test-key-share".utf8)
        
        // When
        let existsBeforeSaving = keychainStore.itemExists(key: "device_key_share")
        
        do {
            try keychainStore.saveDeviceKeyShare(keyShareData, requiresBiometric: false)
        } catch {
            XCTFail("Failed to save key share: \(error)")
        }
        
        let existsAfterSaving = keychainStore.itemExists(key: "device_key_share")
        keychainStore.clearDeviceKeyShare()
        let existsAfterClearing = keychainStore.itemExists(key: "device_key_share")
        
        // Then
        XCTAssertFalse(existsBeforeSaving)
        XCTAssertTrue(existsAfterSaving)
        XCTAssertFalse(existsAfterClearing)
    }
    
    // MARK: - Clear All Tests
    
    func testClearAll() {
        // Given
        let tokens = AuthTokens(
            accessToken: "test-access-token",
            refreshToken: "test-refresh-token",
            expiresIn: 3600
        )
        let keyShareData = Data("test-key-share".utf8)
        
        keychainStore.saveTokens(tokens)
        do {
            try keychainStore.saveDeviceKeyShare(keyShareData, requiresBiometric: false)
        } catch {
            XCTFail("Failed to save key share: \(error)")
        }
        
        // Verify items exist
        XCTAssertNotNil(keychainStore.loadTokens())
        XCTAssertNoThrow(try keychainStore.loadDeviceKeyShare())
        
        // When
        keychainStore.clearAll()
        
        // Then
        XCTAssertNil(keychainStore.loadTokens())
        XCTAssertThrowsError(try keychainStore.loadDeviceKeyShare())
    }
    
    // MARK: - Stored Items Info Tests
    
    func testGetStoredItemsInfo() {
        // Given
        let tokens = AuthTokens(
            accessToken: "test-access-token",
            refreshToken: "test-refresh-token",
            expiresIn: 3600
        )
        
        // When
        let infoBeforeSaving = keychainStore.getStoredItemsInfo()
        keychainStore.saveTokens(tokens)
        let infoAfterSaving = keychainStore.getStoredItemsInfo()
        
        // Then
        XCTAssertEqual(infoBeforeSaving["Authentication Tokens"], false)
        XCTAssertEqual(infoBeforeSaving["Device Key Share"], false)
        
        XCTAssertEqual(infoAfterSaving["Authentication Tokens"], true)
        XCTAssertEqual(infoAfterSaving["Device Key Share"], false)
    }
    
    // MARK: - Error Handling Tests
    
    func testKeychainErrorTypes() {
        let saveFailed = KeychainError.saveFailed(errSecDuplicateItem)
        let loadFailed = KeychainError.loadFailed(errSecItemNotFound)
        let deleteFailed = KeychainError.deleteFailed(errSecItemNotFound)
        
        // Test error descriptions
        XCTAssertNotNil(saveFailed.errorDescription)
        XCTAssertNotNil(loadFailed.errorDescription)
        XCTAssertNotNil(deleteFailed.errorDescription)
        
        // Test user cancellation detection
        let userCancelError = KeychainError.loadFailed(errSecUserCancel)
        XCTAssertTrue(userCancelError.isUserCancelled)
        
        let authFailedError = KeychainError.loadFailed(errSecAuthFailed)
        XCTAssertTrue(authFailedError.isUserCancelled)
        
        let otherError = KeychainError.loadFailed(errSecItemNotFound)
        XCTAssertFalse(otherError.isUserCancelled)
        
        // Test biometric unavailable detection
        let biometricUnavailableError = KeychainError.loadFailed(errSecNotAvailable)
        XCTAssertTrue(biometricUnavailableError.isBiometricUnavailable)
        
        let nonBiometricError = KeychainError.loadFailed(errSecItemNotFound)
        XCTAssertFalse(nonBiometricError.isBiometricUnavailable)
    }
    
    // MARK: - Multiple Service Identifier Tests
    
    func testMultipleKeychainStores() {
        // Given
        let store1 = KeychainStore(serviceIdentifier: "erebor-test-1")
        let store2 = KeychainStore(serviceIdentifier: "erebor-test-2")
        
        let tokens1 = AuthTokens(
            accessToken: "store1-access-token",
            refreshToken: "store1-refresh-token",
            expiresIn: 3600
        )
        
        let tokens2 = AuthTokens(
            accessToken: "store2-access-token",
            refreshToken: "store2-refresh-token",
            expiresIn: 7200
        )
        
        // When
        store1.saveTokens(tokens1)
        store2.saveTokens(tokens2)
        
        let loadedTokens1 = store1.loadTokens()
        let loadedTokens2 = store2.loadTokens()
        
        // Then
        XCTAssertEqual(loadedTokens1?.accessToken, tokens1.accessToken)
        XCTAssertEqual(loadedTokens2?.accessToken, tokens2.accessToken)
        XCTAssertNotEqual(loadedTokens1?.accessToken, loadedTokens2?.accessToken)
        
        // Cleanup
        store1.clearAll()
        store2.clearAll()
    }
    
    // MARK: - Concurrent Access Tests
    
    func testConcurrentAccess() {
        let expectation = XCTestExpectation(description: "Concurrent access completed")
        expectation.expectedFulfillmentCount = 10
        
        // When
        for i in 0..<10 {
            DispatchQueue.global().async {
                let tokens = AuthTokens(
                    accessToken: "concurrent-token-\(i)",
                    refreshToken: "concurrent-refresh-\(i)",
                    expiresIn: 3600
                )
                
                self.keychainStore.saveTokens(tokens)
                let loaded = self.keychainStore.loadTokens()
                
                // Verify something was saved and loaded
                XCTAssertNotNil(loaded)
                XCTAssertTrue(loaded?.accessToken.contains("concurrent-token") == true)
                
                expectation.fulfill()
            }
        }
        
        // Then
        wait(for: [expectation], timeout: 5.0)
        
        // Verify final state
        let finalTokens = keychainStore.loadTokens()
        XCTAssertNotNil(finalTokens)
        XCTAssertTrue(finalTokens?.accessToken.contains("concurrent-token") == true)
    }
}