import Foundation

/// Represents a user in the Erebor system
public struct EreborUser: Codable, Identifiable, Equatable {
    /// Unique user identifier
    public let id: String
    
    /// User's email address (if provided)
    public let email: String?
    
    /// User's phone number (if provided) 
    public let phoneNumber: String?
    
    /// List of wallets owned by the user
    public let wallets: [EreborWallet]
    
    /// Linked social/external accounts
    public let linkedAccounts: [LinkedAccount]
    
    /// Timestamp when the user was created
    public let createdAt: Date
    
    /// Timestamp when the user was last updated
    public let updatedAt: Date?
    
    /// User's display name (derived from linked accounts or email)
    public var displayName: String? {
        // Try to get name from linked accounts first
        for account in linkedAccounts {
            if let username = account.username {
                return username
            }
        }
        
        // Fallback to email username
        if let email = email {
            return String(email.split(separator: "@").first ?? "")
        }
        
        return nil
    }
    
    /// User's profile picture URL (from linked accounts)
    public var profilePictureUrl: String? {
        for account in linkedAccounts {
            if let profilePicture = account.profilePictureUrl {
                return profilePicture
            }
        }
        return nil
    }
    
    /// Check if user has a specific linked account
    /// - Parameter provider: The authentication provider to check
    /// - Returns: True if the account is linked
    public func hasLinkedAccount(_ provider: AuthProvider) -> Bool {
        return linkedAccounts.contains { $0.provider == provider }
    }
    
    /// Get a specific linked account
    /// - Parameter provider: The authentication provider
    /// - Returns: The linked account if it exists
    public func linkedAccount(for provider: AuthProvider) -> LinkedAccount? {
        return linkedAccounts.first { $0.provider == provider }
    }
    
    /// Get wallet by ID
    /// - Parameter id: Wallet identifier
    /// - Returns: The wallet if it exists
    public func wallet(withId id: String) -> EreborWallet? {
        return wallets.first { $0.id == id }
    }
    
    /// Get wallets for a specific chain
    /// - Parameter chainId: Chain identifier
    /// - Returns: Array of wallets on that chain
    public func wallets(forChain chainId: UInt64) -> [EreborWallet] {
        return wallets.filter { $0.chainId == chainId }
    }
    
    /// Get the user's primary wallet (first created EVM wallet)
    public var primaryWallet: EreborWallet? {
        return wallets
            .filter { $0.chainType == .evm && !$0.imported }
            .sorted { $0.createdAt < $1.createdAt }
            .first
    }
}

/// Represents a linked external account
public struct LinkedAccount: Codable, Identifiable, Equatable {
    /// Unique identifier for this linked account
    public var id: String { "\(provider.rawValue):\(providerUserId)" }
    
    /// The authentication provider
    public let provider: AuthProvider
    
    /// User ID from the external provider
    public let providerUserId: String
    
    /// Email from the external account (if available)
    public let email: String?
    
    /// Username from the external account (if available)
    public let username: String?
    
    /// Display name from the external account
    public let displayName: String?
    
    /// Profile picture URL from the external account
    public let profilePictureUrl: String?
    
    /// Timestamp when the account was linked
    public let linkedAt: Date
    
    /// Raw provider data (for future extensibility)
    public let metadata: [String: String]?
    
    public init(
        provider: AuthProvider,
        providerUserId: String,
        email: String? = nil,
        username: String? = nil,
        displayName: String? = nil,
        profilePictureUrl: String? = nil,
        linkedAt: Date = Date(),
        metadata: [String: String]? = nil
    ) {
        self.provider = provider
        self.providerUserId = providerUserId
        self.email = email
        self.username = username
        self.displayName = displayName
        self.profilePictureUrl = profilePictureUrl
        self.linkedAt = linkedAt
        self.metadata = metadata
    }
}