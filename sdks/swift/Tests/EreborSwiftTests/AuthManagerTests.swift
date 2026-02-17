import XCTest
@testable import EreborSwift

final class AuthManagerTests: XCTestCase {
    var authManager: AuthManager!
    var mockAPIClient: MockAPIClient!
    var mockKeychainStore: MockKeychainStore!
    
    override func setUp() {
        super.setUp()
        mockAPIClient = MockAPIClient()
        mockKeychainStore = MockKeychainStore()
        authManager = AuthManager(apiClient: mockAPIClient, keychainStore: mockKeychainStore)
    }
    
    override func tearDown() {
        authManager = nil
        mockAPIClient = nil
        mockKeychainStore = nil
        super.tearDown()
    }
    
    // MARK: - Email Authentication Tests
    
    func testLoginWithEmail() async throws {
        // Given
        let email = "test@example.com"
        let expectedSession = OTPSession(
            sessionId: "session-123",
            contact: email,
            provider: .email,
            expiresAt: Date().addingTimeInterval(600)
        )
        mockAPIClient.sendEmailOTPResult = .success(expectedSession)
        
        // When
        let session = try await authManager.loginWithEmail(email)
        
        // Then
        XCTAssertEqual(session.sessionId, expectedSession.sessionId)
        XCTAssertEqual(session.contact, email)
        XCTAssertEqual(session.provider, .email)
        XCTAssertEqual(mockAPIClient.sendEmailOTPCallCount, 1)
    }
    
    func testLoginWithEmailFailure() async {
        // Given
        let email = "invalid-email"
        mockAPIClient.sendEmailOTPResult = .failure(APIError.validationError("Invalid email"))
        
        // When/Then
        do {
            _ = try await authManager.loginWithEmail(email)
            XCTFail("Should have thrown an error")
        } catch let error as APIError {
            XCTAssertEqual(error, APIError.validationError("Invalid email"))
        }
    }
    
    func testVerifyEmailOTP() async throws {
        // Given
        let session = OTPSession(
            sessionId: "session-123",
            contact: "test@example.com",
            provider: .email,
            expiresAt: Date().addingTimeInterval(600)
        )
        let code = "123456"
        let expectedResult = createMockAuthResult()
        mockAPIClient.verifyEmailOTPResult = .success(expectedResult)
        
        // When
        let result = try await authManager.verifyEmailOTP(session, code: code)
        
        // Then
        XCTAssertEqual(result.accessToken, expectedResult.accessToken)
        XCTAssertEqual(result.user.id, expectedResult.user.id)
        XCTAssertEqual(mockAPIClient.verifyEmailOTPCallCount, 1)
        XCTAssertTrue(authManager.isAuthenticated)
    }
    
    // MARK: - Phone Authentication Tests
    
    func testLoginWithPhone() async throws {
        // Given
        let phoneNumber = "+1234567890"
        let expectedSession = OTPSession(
            sessionId: "phone-session-123",
            contact: phoneNumber,
            provider: .phone,
            expiresAt: Date().addingTimeInterval(300)
        )
        mockAPIClient.sendPhoneOTPResult = .success(expectedSession)
        
        // When
        let session = try await authManager.loginWithPhone(phoneNumber)
        
        // Then
        XCTAssertEqual(session.sessionId, expectedSession.sessionId)
        XCTAssertEqual(session.contact, phoneNumber)
        XCTAssertEqual(session.provider, .phone)
    }
    
    func testVerifyPhoneOTP() async throws {
        // Given
        let session = OTPSession(
            sessionId: "phone-session-123",
            contact: "+1234567890",
            provider: .phone,
            expiresAt: Date().addingTimeInterval(300)
        )
        let code = "654321"
        let expectedResult = createMockAuthResult()
        mockAPIClient.verifyPhoneOTPResult = .success(expectedResult)
        
        // When
        let result = try await authManager.verifyPhoneOTP(session, code: code)
        
        // Then
        XCTAssertEqual(result.user.phoneNumber, "+1234567890")
        XCTAssertTrue(authManager.isAuthenticated)
    }
    
    // MARK: - Token Management Tests
    
    func testRefreshTokens() async throws {
        // Given
        let originalTokens = AuthTokens(
            accessToken: "old-access-token",
            refreshToken: "refresh-token",
            expiresIn: 3600
        )
        mockKeychainStore.tokens = originalTokens
        
        let newAuthResult = createMockAuthResult()
        mockAPIClient.refreshTokensResult = .success(newAuthResult)
        
        // When
        let result = try await authManager.refreshTokens()
        
        // Then
        XCTAssertEqual(result.accessToken, newAuthResult.accessToken)
        XCTAssertEqual(mockAPIClient.refreshTokensCallCount, 1)
        XCTAssertNotNil(mockKeychainStore.tokens)
        XCTAssertEqual(mockKeychainStore.tokens?.accessToken, newAuthResult.accessToken)
    }
    
    func testRefreshTokensFailureClearsAuthState() async {
        // Given
        let originalTokens = AuthTokens(
            accessToken: "old-access-token",
            refreshToken: "expired-refresh-token",
            expiresIn: 3600
        )
        mockKeychainStore.tokens = originalTokens
        mockAPIClient.refreshTokensResult = .failure(APIError.unauthorized)
        
        // When
        do {
            _ = try await authManager.refreshTokens()
            XCTFail("Should have thrown an error")
        } catch {
            // Then
            XCTAssertFalse(authManager.isAuthenticated)
            XCTAssertNil(authManager.currentUser)
            XCTAssertNil(mockKeychainStore.tokens)
        }
    }
    
    // MARK: - Logout Tests
    
    func testLogout() async throws {
        // Given
        setupAuthenticatedState()
        mockAPIClient.logoutResult = .success(())
        
        // When
        try await authManager.logout()
        
        // Then
        XCTAssertFalse(authManager.isAuthenticated)
        XCTAssertNil(authManager.currentUser)
        XCTAssertNil(mockKeychainStore.tokens)
        XCTAssertEqual(mockAPIClient.logoutCallCount, 1)
    }
    
    func testLogoutClearsStateEvenOnAPIFailure() async throws {
        // Given
        setupAuthenticatedState()
        mockAPIClient.logoutResult = .failure(APIError.networkError(URLError(.notConnectedToInternet)))
        
        // When
        try await authManager.logout()
        
        // Then
        XCTAssertFalse(authManager.isAuthenticated)
        XCTAssertNil(authManager.currentUser)
        XCTAssertNil(mockKeychainStore.tokens)
    }
    
    // MARK: - Account Linking Tests
    
    func testLinkAccount() async throws {
        // Given
        setupAuthenticatedState()
        let provider = AuthProvider.google
        let token = "google-oauth-token"
        let expectedAccount = LinkedAccount(
            provider: provider,
            providerUserId: "google-123",
            email: "test@gmail.com"
        )
        mockAPIClient.linkAccountResult = .success(expectedAccount)
        
        // When
        let linkedAccount = try await authManager.linkAccount(provider, token: token)
        
        // Then
        XCTAssertEqual(linkedAccount.provider, provider)
        XCTAssertEqual(linkedAccount.email, "test@gmail.com")
        XCTAssertEqual(mockAPIClient.linkAccountCallCount, 1)
    }
    
    func testLinkAccountRequiresAuthentication() async {
        // Given
        authManager.isAuthenticated = false
        
        // When/Then
        do {
            _ = try await authManager.linkAccount(.google, token: "token")
            XCTFail("Should have thrown an error")
        } catch let error as EreborError {
            XCTAssertEqual(error, EreborError.authenticationRequired)
        }
    }
    
    func testUnlinkAccount() async throws {
        // Given
        setupAuthenticatedState()
        let provider = AuthProvider.twitter
        mockAPIClient.unlinkAccountResult = .success(())
        
        // When
        try await authManager.unlinkAccount(provider)
        
        // Then
        XCTAssertEqual(mockAPIClient.unlinkAccountCallCount, 1)
        XCTAssertEqual(mockAPIClient.lastUnlinkedProvider, provider.rawValue)
    }
    
    // MARK: - Helper Methods
    
    private func setupAuthenticatedState() {
        let tokens = AuthTokens(
            accessToken: "valid-access-token",
            refreshToken: "valid-refresh-token",
            expiresIn: 3600
        )
        mockKeychainStore.tokens = tokens
        authManager.isAuthenticated = true
        authManager.currentUser = createMockUser()
    }
    
    private func createMockAuthResult() -> AuthResult {
        return AuthResult(
            accessToken: "new-access-token",
            refreshToken: "new-refresh-token",
            expiresIn: 3600,
            user: createMockUser(),
            isNewUser: false
        )
    }
    
    private func createMockUser() -> EreborUser {
        return EreborUser(
            id: "user-123",
            email: "test@example.com",
            phoneNumber: "+1234567890",
            wallets: [],
            linkedAccounts: [],
            createdAt: Date(),
            updatedAt: Date()
        )
    }
}

// MARK: - Mock Classes

class MockAPIClient: APIClient {
    var sendEmailOTPResult: Result<OTPSession, Error> = .failure(APIError.networkError(URLError(.unknown)))
    var verifyEmailOTPResult: Result<AuthResult, Error> = .failure(APIError.networkError(URLError(.unknown)))
    var sendPhoneOTPResult: Result<OTPSession, Error> = .failure(APIError.networkError(URLError(.unknown)))
    var verifyPhoneOTPResult: Result<AuthResult, Error> = .failure(APIError.networkError(URLError(.unknown)))
    var refreshTokensResult: Result<AuthResult, Error> = .failure(APIError.networkError(URLError(.unknown)))
    var logoutResult: Result<Void, Error> = .failure(APIError.networkError(URLError(.unknown)))
    var linkAccountResult: Result<LinkedAccount, Error> = .failure(APIError.networkError(URLError(.unknown)))
    var unlinkAccountResult: Result<Void, Error> = .failure(APIError.networkError(URLError(.unknown)))
    
    var sendEmailOTPCallCount = 0
    var verifyEmailOTPCallCount = 0
    var sendPhoneOTPCallCount = 0
    var verifyPhoneOTPCallCount = 0
    var refreshTokensCallCount = 0
    var logoutCallCount = 0
    var linkAccountCallCount = 0
    var unlinkAccountCallCount = 0
    var lastUnlinkedProvider: String?
    
    override func sendEmailOTP(email: String) async throws -> OTPSession {
        sendEmailOTPCallCount += 1
        switch sendEmailOTPResult {
        case .success(let session):
            return session
        case .failure(let error):
            throw error
        }
    }
    
    override func verifyEmailOTP(email: String, code: String) async throws -> AuthResult {
        verifyEmailOTPCallCount += 1
        switch verifyEmailOTPResult {
        case .success(let result):
            return result
        case .failure(let error):
            throw error
        }
    }
    
    override func sendPhoneOTP(phoneNumber: String) async throws -> OTPSession {
        sendPhoneOTPCallCount += 1
        switch sendPhoneOTPResult {
        case .success(let session):
            return session
        case .failure(let error):
            throw error
        }
    }
    
    override func verifyPhoneOTP(phoneNumber: String, code: String) async throws -> AuthResult {
        verifyPhoneOTPCallCount += 1
        switch verifyPhoneOTPResult {
        case .success(let result):
            return result
        case .failure(let error):
            throw error
        }
    }
    
    override func refreshTokens() async throws -> AuthResult {
        refreshTokensCallCount += 1
        switch refreshTokensResult {
        case .success(let result):
            return result
        case .failure(let error):
            throw error
        }
    }
    
    override func logout() async throws {
        logoutCallCount += 1
        switch logoutResult {
        case .success:
            return
        case .failure(let error):
            throw error
        }
    }
    
    override func linkAccount(provider: String, token: String) async throws -> LinkedAccount {
        linkAccountCallCount += 1
        switch linkAccountResult {
        case .success(let account):
            return account
        case .failure(let error):
            throw error
        }
    }
    
    override func unlinkAccount(provider: String) async throws {
        unlinkAccountCallCount += 1
        lastUnlinkedProvider = provider
        switch unlinkAccountResult {
        case .success:
            return
        case .failure(let error):
            throw error
        }
    }
}

class MockKeychainStore: KeychainStore {
    var tokens: AuthTokens?
    
    override func saveTokens(_ tokens: AuthTokens) {
        self.tokens = tokens
    }
    
    override func loadTokens() -> AuthTokens? {
        return tokens
    }
    
    override func clearTokens() {
        tokens = nil
    }
}