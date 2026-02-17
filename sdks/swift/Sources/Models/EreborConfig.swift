import Foundation

/// Configuration settings for the Erebor SDK
public struct EreborConfig: Codable {
    /// Base URL of the Erebor API
    public let apiUrl: String
    
    /// Your application identifier
    public let appId: String
    
    /// Available login methods for users
    public let loginMethods: [LoginMethod]
    
    /// Supported blockchain chains
    public let chains: [Chain]?
    
    /// UI appearance customization
    public let appearance: AppearanceConfig?
    
    /// Token storage prefix (defaults to "erebor")
    public let tokenPrefix: String?
    
    /// Biometric authentication requirement for signing operations
    public let requireBiometricForSigning: Bool
    
    /// SSL certificate pinning configuration
    public let sslPinning: SSLPinningConfig?
    
    public init(
        apiUrl: String = "",
        appId: String = "",
        loginMethods: [LoginMethod] = [.email, .google, .apple],
        chains: [Chain]? = nil,
        appearance: AppearanceConfig? = nil,
        tokenPrefix: String? = "erebor",
        requireBiometricForSigning: Bool = true,
        sslPinning: SSLPinningConfig? = nil
    ) {
        self.apiUrl = apiUrl
        self.appId = appId
        self.loginMethods = loginMethods
        self.chains = chains
        self.appearance = appearance
        self.tokenPrefix = tokenPrefix
        self.requireBiometricForSigning = requireBiometricForSigning
        self.sslPinning = sslPinning
    }
}

/// UI appearance customization options
public struct AppearanceConfig: Codable {
    public let theme: Theme?
    public let logo: String?
    public let primaryColor: String?
    public let borderRadius: String?
    public let fontFamily: String?
    
    public enum Theme: String, Codable, CaseIterable {
        case light
        case dark
        case auto
    }
    
    public init(
        theme: Theme? = .auto,
        logo: String? = nil,
        primaryColor: String? = nil,
        borderRadius: String? = nil,
        fontFamily: String? = nil
    ) {
        self.theme = theme
        self.logo = logo
        self.primaryColor = primaryColor
        self.borderRadius = borderRadius
        self.fontFamily = fontFamily
    }
}

/// SSL certificate pinning configuration
public struct SSLPinningConfig: Codable {
    /// Certificate hashes to pin
    public let certificateHashes: [String]
    
    /// Whether to enforce pinning (fail if certificate doesn't match)
    public let enforceOnFailure: Bool
    
    public init(
        certificateHashes: [String],
        enforceOnFailure: Bool = true
    ) {
        self.certificateHashes = certificateHashes
        self.enforceOnFailure = enforceOnFailure
    }
}