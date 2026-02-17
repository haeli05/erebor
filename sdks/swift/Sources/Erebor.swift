import Foundation
import UIKit

/// Main entry point for the Erebor SDK
/// Provides access to authentication, wallet management, and other SDK features
public class Erebor: ObservableObject {
    public static let shared = Erebor()
    
    // MARK: - Public Properties
    
    /// Current configuration
    public private(set) var config: EreborConfig?
    
    /// Authentication state
    @Published public var isAuthenticated: Bool = false
    
    /// Current authenticated user
    @Published public var user: EreborUser?
    
    /// Loading state
    @Published public var isLoading: Bool = false
    
    // MARK: - Internal Components
    
    internal var apiClient: APIClient?
    internal var authManager: AuthManager?
    internal var walletManager: WalletManager?
    internal var keychainStore: KeychainStore?
    internal var deviceKeyManager: DeviceKeyManager?
    
    private init() {
        // Private initializer to enforce singleton pattern
    }
    
    // MARK: - Configuration
    
    /// Configure the Erebor SDK with the provided settings
    /// - Parameters:
    ///   - apiUrl: Base URL of the Erebor API
    ///   - appId: Your application identifier
    ///   - config: Additional configuration options
    public func configure(apiUrl: String, appId: String, config: EreborConfig) {
        self.config = config.with(apiUrl: apiUrl, appId: appId)
        
        // Initialize core components
        self.keychainStore = KeychainStore(serviceIdentifier: "erebor-\(appId)")
        self.apiClient = APIClient(config: self.config!)
        self.authManager = AuthManager(apiClient: self.apiClient!, keychainStore: self.keychainStore!)
        self.walletManager = WalletManager(apiClient: self.apiClient!, keychainStore: self.keychainStore!)
        self.deviceKeyManager = DeviceKeyManager(keychainStore: self.keychainStore!)
        
        // Check existing authentication state
        Task {
            await checkAuthenticationState()
        }
    }
    
    // MARK: - Authentication State
    
    @MainActor
    private func checkAuthenticationState() async {
        guard let authManager = authManager else { return }
        
        isLoading = true
        
        do {
            let user = try await authManager.getCurrentUser()
            self.user = user
            self.isAuthenticated = true
        } catch {
            // User not authenticated or token expired
            self.user = nil
            self.isAuthenticated = false
        }
        
        isLoading = false
    }
    
    // MARK: - Quick Access Properties
    
    /// Access to authentication methods
    public var auth: AuthManager? {
        return authManager
    }
    
    /// Access to wallet operations
    public var wallet: WalletManager? {
        return walletManager
    }
    
    // MARK: - Convenience Methods
    
    /// Quick login with email
    /// - Parameter email: User's email address
    /// - Returns: OTP session for verification
    public func loginWithEmail(_ email: String) async throws -> OTPSession {
        guard let authManager = authManager else {
            throw EreborError.sdkNotConfigured
        }
        return try await authManager.loginWithEmail(email)
    }
    
    /// Quick logout
    public func logout() async throws {
        guard let authManager = authManager else {
            throw EreborError.sdkNotConfigured
        }
        
        try await authManager.logout()
        
        await MainActor.run {
            self.user = nil
            self.isAuthenticated = false
        }
    }
}

// MARK: - Configuration Extension

private extension EreborConfig {
    func with(apiUrl: String, appId: String) -> EreborConfig {
        return EreborConfig(
            apiUrl: apiUrl,
            appId: appId,
            loginMethods: self.loginMethods,
            chains: self.chains,
            appearance: self.appearance,
            tokenPrefix: self.tokenPrefix
        )
    }
}

// MARK: - Error Types

public enum EreborError: LocalizedError {
    case sdkNotConfigured
    case authenticationRequired
    case biometricNotAvailable
    case userCancelled
    case invalidConfiguration
    case networkError(String)
    case cryptographicError(String)
    case keychainError(String)
    
    public var errorDescription: String? {
        switch self {
        case .sdkNotConfigured:
            return "Erebor SDK not configured. Call configure() first."
        case .authenticationRequired:
            return "User authentication is required for this operation."
        case .biometricNotAvailable:
            return "Biometric authentication is not available on this device."
        case .userCancelled:
            return "Operation was cancelled by the user."
        case .invalidConfiguration:
            return "Invalid configuration provided."
        case .networkError(let message):
            return "Network error: \(message)"
        case .cryptographicError(let message):
            return "Cryptographic error: \(message)"
        case .keychainError(let message):
            return "Keychain error: \(message)"
        }
    }
}