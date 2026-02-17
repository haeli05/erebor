import Foundation

/// Available login methods for the Erebor SDK
public enum LoginMethod: String, Codable, CaseIterable {
    case email = "email"
    case phone = "phone"
    case google = "google"
    case apple = "apple"
    case siwe = "siwe"
    case discord = "discord"
    case github = "github"
    case twitter = "twitter"
    case farcaster = "farcaster"
    case telegram = "telegram"
    
    /// Display name for the login method
    public var displayName: String {
        switch self {
        case .email:
            return "Email"
        case .phone:
            return "Phone"
        case .google:
            return "Google"
        case .apple:
            return "Apple"
        case .siwe:
            return "Sign-In with Ethereum"
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
    
    /// Whether this method requires OTP verification
    public var requiresOTP: Bool {
        switch self {
        case .email, .phone:
            return true
        case .google, .apple, .siwe, .discord, .github, .twitter, .farcaster, .telegram:
            return false
        }
    }
    
    /// Whether this method supports OAuth flow
    public var isOAuth: Bool {
        switch self {
        case .google, .discord, .github, .twitter, .farcaster, .telegram:
            return true
        case .apple, .email, .phone, .siwe:
            return false
        }
    }
    
    /// Brand color for UI theming
    public var brandColor: String {
        switch self {
        case .email:
            return "#6B7280"
        case .phone:
            return "#059669"
        case .google:
            return "#4285F4"
        case .apple:
            return "#000000"
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
    
    /// Convert to AuthProvider
    public var authProvider: AuthProvider {
        switch self {
        case .email:
            return .email
        case .phone:
            return .phone
        case .google:
            return .google
        case .apple:
            return .apple
        case .siwe:
            return .siwe
        case .discord:
            return .discord
        case .github:
            return .github
        case .twitter:
            return .twitter
        case .farcaster:
            return .farcaster
        case .telegram:
            return .telegram
        }
    }
}

// MARK: - LoginMethod Array Extensions

public extension Array where Element == LoginMethod {
    /// Common login method combinations
    static let minimal: [LoginMethod] = [.email]
    static let social: [LoginMethod] = [.google, .apple]
    static let complete: [LoginMethod] = [.email, .google, .apple, .siwe]
    static let enterprise: [LoginMethod] = [.email, .phone, .google, .apple]
    static let web3: [LoginMethod] = [.siwe, .google, .apple]
    static let all: [LoginMethod] = LoginMethod.allCases
}