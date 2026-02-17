import Foundation
import UIKit
import AuthenticationServices

/// Manages user authentication and session state
public class AuthManager: ObservableObject {
    private let apiClient: APIClient
    private let keychainStore: KeychainStore
    
    /// Current authentication state
    @Published public private(set) var isAuthenticated: Bool = false
    
    /// Current user (if authenticated)
    @Published public private(set) var currentUser: EreborUser?
    
    /// Loading state for auth operations
    @Published public private(set) var isLoading: Bool = false
    
    /// Last authentication error
    @Published public private(set) var lastError: Error?
    
    // Authentication providers
    private lazy var appleAuthProvider = AppleAuthProvider()
    private lazy var googleAuthProvider = GoogleAuthProvider()
    private lazy var oauthBrowser = OAuthBrowser()
    
    init(apiClient: APIClient, keychainStore: KeychainStore) {
        self.apiClient = apiClient
        self.keychainStore = keychainStore
        
        // Check existing authentication state
        checkAuthenticationState()
    }
    
    // MARK: - Authentication State
    
    private func checkAuthenticationState() {
        if let tokens = keychainStore.loadTokens() {
            // Check if token needs refresh
            if tokens.shouldRefresh {
                Task {
                    try? await refreshTokens()
                }
            } else {
                // Set authenticated state
                apiClient.setTokens(tokens)
                isAuthenticated = true
                
                // Fetch current user
                Task {
                    await fetchCurrentUser()
                }
            }
        }
    }
    
    @MainActor
    private func fetchCurrentUser() async {
        do {
            currentUser = try await apiClient.getMe()
        } catch {
            // Token might be invalid, clear auth state
            await logout()
        }
    }
    
    // MARK: - Email Authentication
    
    /// Start email authentication flow
    /// - Parameter email: User's email address
    /// - Returns: OTP session for verification
    public func loginWithEmail(_ email: String) async throws -> OTPSession {
        isLoading = true
        lastError = nil
        
        defer { isLoading = false }
        
        do {
            let session = try await apiClient.sendEmailOTP(email: email)
            return session
        } catch {
            lastError = error
            throw error
        }
    }
    
    /// Verify email OTP and complete authentication
    /// - Parameters:
    ///   - session: OTP session from loginWithEmail
    ///   - code: OTP code from user
    /// - Returns: Authentication result
    public func verifyEmailOTP(_ session: OTPSession, code: String) async throws -> AuthResult {
        isLoading = true
        lastError = nil
        
        defer { isLoading = false }
        
        do {
            let result = try await apiClient.verifyEmailOTP(email: session.contact, code: code)
            await handleAuthResult(result)
            return result
        } catch {
            lastError = error
            throw error
        }
    }
    
    // MARK: - Phone Authentication
    
    /// Start phone authentication flow
    /// - Parameter phoneNumber: User's phone number
    /// - Returns: OTP session for verification
    public func loginWithPhone(_ phoneNumber: String) async throws -> OTPSession {
        isLoading = true
        lastError = nil
        
        defer { isLoading = false }
        
        do {
            let session = try await apiClient.sendPhoneOTP(phoneNumber: phoneNumber)
            return session
        } catch {
            lastError = error
            throw error
        }
    }
    
    /// Verify phone OTP and complete authentication
    /// - Parameters:
    ///   - session: OTP session from loginWithPhone
    ///   - code: OTP code from user
    /// - Returns: Authentication result
    public func verifyPhoneOTP(_ session: OTPSession, code: String) async throws -> AuthResult {
        isLoading = true
        lastError = nil
        
        defer { isLoading = false }
        
        do {
            let result = try await apiClient.verifyPhoneOTP(phoneNumber: session.contact, code: code)
            await handleAuthResult(result)
            return result
        } catch {
            lastError = error
            throw error
        }
    }
    
    // MARK: - Apple Authentication
    
    /// Authenticate using Apple Sign In
    /// - Parameter presentingViewController: View controller to present the auth flow
    /// - Returns: Authentication result
    @MainActor
    public func loginWithApple(presenting presentingViewController: UIViewController) async throws -> AuthResult {
        isLoading = true
        lastError = nil
        
        defer { isLoading = false }
        
        do {
            let appleCredential = try await appleAuthProvider.signIn()
            let result = try await apiClient.loginWithApple(
                identityToken: appleCredential.identityToken,
                authorizationCode: appleCredential.authorizationCode,
                user: appleCredential.user
            )
            await handleAuthResult(result)
            return result
        } catch {
            lastError = error
            throw error
        }
    }
    
    // MARK: - Google Authentication
    
    /// Authenticate using Google OAuth
    /// - Parameter presentingViewController: View controller to present the auth flow
    /// - Returns: Authentication result
    @MainActor
    public func loginWithGoogle(presenting presentingViewController: UIViewController) async throws -> AuthResult {
        isLoading = true
        lastError = nil
        
        defer { isLoading = false }
        
        do {
            let authCode = try await googleAuthProvider.signIn(presenting: presentingViewController)
            let result = try await apiClient.loginWithGoogle(
                authorizationCode: authCode.code,
                redirectUri: googleAuthProvider.redirectUri
            )
            await handleAuthResult(result)
            return result
        } catch {
            lastError = error
            throw error
        }
    }
    
    // MARK: - Sign-In With Ethereum (SIWE)
    
    /// Authenticate using Ethereum wallet signature
    /// - Parameters:
    ///   - message: SIWE message to sign
    ///   - signature: Signature of the message
    /// - Returns: Authentication result
    public func loginWithSIWE(message: String, signature: String) async throws -> AuthResult {
        isLoading = true
        lastError = nil
        
        defer { isLoading = false }
        
        do {
            let result = try await apiClient.verifySIWE(message: message, signature: signature)
            await handleAuthResult(result)
            return result
        } catch {
            lastError = error
            throw error
        }
    }
    
    /// Get a SIWE nonce for message construction
    /// - Returns: Nonce string
    public func getSIWENonce() async throws -> String {
        return try await apiClient.getSiweNonce()
    }
    
    // MARK: - OAuth Providers
    
    /// Authenticate using OAuth provider (Discord, GitHub, Twitter, etc.)
    /// - Parameters:
    ///   - provider: OAuth provider
    ///   - presentingViewController: View controller to present the auth flow
    /// - Returns: Authentication result
    @MainActor
    public func loginWithOAuth(
        _ provider: AuthProvider,
        presenting presentingViewController: UIViewController
    ) async throws -> AuthResult {
        guard provider.isOAuth else {
            throw AuthError.unsupportedProvider(provider)
        }
        
        isLoading = true
        lastError = nil
        
        defer { isLoading = false }
        
        do {
            let authCode = try await oauthBrowser.authenticate(
                provider: provider,
                presenting: presentingViewController
            )
            let result = try await apiClient.loginWithOAuth(
                provider: provider,
                authorizationCode: authCode.code,
                redirectUri: authCode.redirectUri
            )
            await handleAuthResult(result)
            return result
        } catch {
            lastError = error
            throw error
        }
    }
    
    // MARK: - Token Management
    
    /// Refresh authentication tokens
    /// - Returns: New authentication result
    public func refreshTokens() async throws -> AuthResult {
        do {
            let result = try await apiClient.refreshTokens()
            await handleAuthResult(result)
            return result
        } catch {
            // Refresh failed, clear auth state
            await logout()
            throw error
        }
    }
    
    /// Get current user information
    /// - Returns: Current user
    public func getCurrentUser() async throws -> EreborUser {
        if let user = currentUser {
            return user
        }
        
        let user = try await apiClient.getMe()
        await MainActor.run {
            self.currentUser = user
        }
        return user
    }
    
    // MARK: - Account Linking
    
    /// Link an external account to the current user
    /// - Parameters:
    ///   - provider: Authentication provider
    ///   - token: Provider token
    /// - Returns: Linked account information
    public func linkAccount(_ provider: AuthProvider, token: String) async throws -> LinkedAccount {
        guard isAuthenticated else {
            throw EreborError.authenticationRequired
        }
        
        return try await apiClient.linkAccount(provider: provider.rawValue, token: token)
    }
    
    /// Unlink an external account from the current user
    /// - Parameter provider: Authentication provider to unlink
    public func unlinkAccount(_ provider: AuthProvider) async throws {
        guard isAuthenticated else {
            throw EreborError.authenticationRequired
        }
        
        try await apiClient.unlinkAccount(provider: provider.rawValue)
        
        // Refresh user to update linked accounts
        await fetchCurrentUser()
    }
    
    // MARK: - Logout
    
    /// Log out the current user
    public func logout() async throws {
        isLoading = true
        
        defer { isLoading = false }
        
        // Call logout endpoint
        try? await apiClient.logout()
        
        // Clear local state
        keychainStore.clearTokens()
        apiClient.clearTokens()
        
        await MainActor.run {
            self.isAuthenticated = false
            self.currentUser = nil
            self.lastError = nil
        }
    }
    
    // MARK: - Private Helpers
    
    @MainActor
    private func handleAuthResult(_ result: AuthResult) async {
        // Save tokens
        let tokens = AuthTokens(
            accessToken: result.accessToken,
            refreshToken: result.refreshToken,
            expiresIn: result.expiresIn
        )
        keychainStore.saveTokens(tokens)
        apiClient.setTokens(tokens)
        
        // Update state
        isAuthenticated = true
        currentUser = result.user
        lastError = nil
    }
}

// MARK: - Error Types

public enum AuthError: LocalizedError {
    case unsupportedProvider(AuthProvider)
    case invalidCredentials
    case networkError(Error)
    case userCancelled
    case biometricFailed
    case tokenExpired
    case invalidOTP
    case otpExpired
    case tooManyAttempts
    case appleSignInFailed(Error)
    case googleSignInFailed(Error)
    case oauthFailed(Error)
    case siweVerificationFailed
    
    public var errorDescription: String? {
        switch self {
        case .unsupportedProvider(let provider):
            return "Authentication provider \(provider.displayName) is not supported."
        case .invalidCredentials:
            return "Invalid email or password."
        case .networkError(let error):
            return "Network error: \(error.localizedDescription)"
        case .userCancelled:
            return "Authentication was cancelled by the user."
        case .biometricFailed:
            return "Biometric authentication failed."
        case .tokenExpired:
            return "Your session has expired. Please sign in again."
        case .invalidOTP:
            return "Invalid verification code. Please check and try again."
        case .otpExpired:
            return "Verification code has expired. Please request a new one."
        case .tooManyAttempts:
            return "Too many failed attempts. Please try again later."
        case .appleSignInFailed(let error):
            return "Apple Sign In failed: \(error.localizedDescription)"
        case .googleSignInFailed(let error):
            return "Google Sign In failed: \(error.localizedDescription)"
        case .oauthFailed(let error):
            return "OAuth authentication failed: \(error.localizedDescription)"
        case .siweVerificationFailed:
            return "Ethereum wallet verification failed."
        }
    }
}