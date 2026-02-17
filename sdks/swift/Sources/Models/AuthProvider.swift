import Foundation

/// Supported authentication providers
public enum AuthProvider: String, Codable, CaseIterable {
    case google = "google"
    case apple = "apple"
    case email = "email"
    case phone = "phone"
    case siwe = "siwe" // Sign-In With Ethereum
    case discord = "discord"
    case github = "github"
    case twitter = "twitter"
    case farcaster = "farcaster"
    case telegram = "telegram"
    
    /// Display name for the provider
    public var displayName: String {
        switch self {
        case .google:
            return "Google"
        case .apple:
            return "Apple"
        case .email:
            return "Email"
        case .phone:
            return "Phone"
        case .siwe:
            return "Ethereum Wallet"
        case .discord:
            return "Discord"
        case .github:
            return "GitHub"
        case .twitter:
            return "X (Twitter)"
        case .farcaster:
            return "Farcaster"
        case .telegram:
            return "Telegram"
        }
    }
    
    /// Whether this provider requires OTP verification
    public var requiresOTP: Bool {
        switch self {
        case .email, .phone:
            return true
        case .google, .apple, .siwe, .discord, .github, .twitter, .farcaster, .telegram:
            return false
        }
    }
    
    /// Whether this provider supports OAuth flow
    public var isOAuth: Bool {
        switch self {
        case .google, .discord, .github, .twitter, .farcaster, .telegram:
            return true
        case .apple, .email, .phone, .siwe:
            return false
        }
    }
    
    /// Whether this provider requires a native iOS implementation
    public var requiresNativeImplementation: Bool {
        switch self {
        case .apple, .siwe:
            return true
        case .google, .email, .phone, .discord, .github, .twitter, .farcaster, .telegram:
            return false
        }
    }
    
    /// Icon name/identifier for UI display
    public var iconName: String {
        return rawValue
    }
    
    /// Brand color for UI theming
    public var brandColor: String {
        switch self {
        case .google:
            return "#4285F4"
        case .apple:
            return "#000000"
        case .email:
            return "#6B7280"
        case .phone:
            return "#059669"
        case .siwe:
            return "#627EEA"
        case .discord:
            return "#5865F2"
        case .github:
            return "#181717"
        case .twitter:
            return "#1DA1F2"
        case .farcaster:
            return "#8A63D2"
        case .telegram:
            return "#0088CC"
        }
    }
}

/// Result of an authentication attempt
public struct AuthResult: Codable {
    /// Access token for API calls
    public let accessToken: String
    
    /// Refresh token for getting new access tokens
    public let refreshToken: String
    
    /// Token expiration time (seconds from now)
    public let expiresIn: Int
    
    /// Authenticated user information
    public let user: EreborUser
    
    /// Whether this is a new user registration
    public let isNewUser: Bool
    
    public init(
        accessToken: String,
        refreshToken: String,
        expiresIn: Int,
        user: EreborUser,
        isNewUser: Bool = false
    ) {
        self.accessToken = accessToken
        self.refreshToken = refreshToken
        self.expiresIn = expiresIn
        self.user = user
        self.isNewUser = isNewUser
    }
}

/// OTP session for email/phone verification
public struct OTPSession: Codable {
    /// Session identifier
    public let sessionId: String
    
    /// Email or phone number that OTP was sent to
    public let contact: String
    
    /// Provider type (email or phone)
    public let provider: AuthProvider
    
    /// Expiration time
    public let expiresAt: Date
    
    /// Whether this session can be resent
    public let canResend: Bool
    
    /// Cooldown time before resend is allowed
    public let resendCooldownSeconds: Int?
    
    public init(
        sessionId: String,
        contact: String,
        provider: AuthProvider,
        expiresAt: Date,
        canResend: Bool = true,
        resendCooldownSeconds: Int? = nil
    ) {
        self.sessionId = sessionId
        self.contact = contact
        self.provider = provider
        self.expiresAt = expiresAt
        self.canResend = canResend
        self.resendCooldownSeconds = resendCooldownSeconds
    }
}

/// Stored authentication tokens
public struct AuthTokens: Codable {
    public let accessToken: String
    public let refreshToken: String
    public let expiresIn: Int
    public let tokenType: String
    
    /// Calculate expiration date from current time
    public var expirationDate: Date {
        return Date().addingTimeInterval(TimeInterval(expiresIn))
    }
    
    /// Check if token is expired or expiring soon (within 5 minutes)
    public var shouldRefresh: Bool {
        let fiveMinutesFromNow = Date().addingTimeInterval(300)
        return expirationDate <= fiveMinutesFromNow
    }
    
    public init(
        accessToken: String,
        refreshToken: String,
        expiresIn: Int,
        tokenType: String = "Bearer"
    ) {
        self.accessToken = accessToken
        self.refreshToken = refreshToken
        self.expiresIn = expiresIn
        self.tokenType = tokenType
    }
}