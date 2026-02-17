import Foundation
import Security
import LocalAuthentication

/// Secure storage for sensitive data using iOS Keychain Services
public class KeychainStore {
    private let serviceIdentifier: String
    private let accessGroup: String?
    
    /// Initialize with service identifier and optional access group for app groups
    /// - Parameters:
    ///   - serviceIdentifier: Unique identifier for this service (e.g., "erebor-your-app-id")
    ///   - accessGroup: Optional keychain access group for sharing between apps
    init(serviceIdentifier: String, accessGroup: String? = nil) {
        self.serviceIdentifier = serviceIdentifier
        self.accessGroup = accessGroup
    }
    
    // MARK: - Token Management
    
    /// Save authentication tokens securely
    /// - Parameter tokens: Tokens to save
    func saveTokens(_ tokens: AuthTokens) {
        do {
            let data = try JSONEncoder().encode(tokens)
            try save(data: data, key: "auth_tokens")
        } catch {
            print("Failed to save tokens: \(error)")
        }
    }
    
    /// Load authentication tokens
    /// - Returns: Saved tokens or nil if not found
    func loadTokens() -> AuthTokens? {
        do {
            let data = try load(key: "auth_tokens")
            return try JSONDecoder().decode(AuthTokens.self, from: data)
        } catch {
            return nil
        }
    }
    
    /// Clear authentication tokens
    func clearTokens() {
        try? delete(key: "auth_tokens")
    }
    
    // MARK: - Device Key Share Management
    
    /// Save device key share with biometric protection
    /// - Parameters:
    ///   - keyShare: Encrypted key share data
    ///   - requiresBiometric: Whether biometric authentication is required to retrieve
    func saveDeviceKeyShare(_ keyShare: Data, requiresBiometric: Bool = true) throws {
        let accessControl = try createAccessControl(requiresBiometric: requiresBiometric)
        try save(data: keyShare, key: "device_key_share", accessControl: accessControl)
    }
    
    /// Load device key share (requires biometric authentication if configured)
    /// - Returns: Encrypted key share data
    func loadDeviceKeyShare() throws -> Data {
        return try load(key: "device_key_share")
    }
    
    /// Clear device key share
    func clearDeviceKeyShare() {
        try? delete(key: "device_key_share")
    }
    
    // MARK: - Generic Keychain Operations
    
    /// Save data to keychain
    /// - Parameters:
    ///   - data: Data to save
    ///   - key: Keychain item key
    ///   - accessControl: Optional access control (for biometric protection)
    func save(data: Data, key: String, accessControl: SecAccessControl? = nil) throws {
        // Delete existing item first
        try? delete(key: key)
        
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceIdentifier,
            kSecAttrAccount as String: key,
            kSecValueData as String: data
        ]
        
        // Add access control if provided
        if let accessControl = accessControl {
            query[kSecAttrAccessControl as String] = accessControl
        } else {
            // Use default accessibility
            query[kSecAttrAccessible as String] = kSecAttrAccessibleWhenUnlockedThisDeviceOnly
        }
        
        // Add access group if provided
        if let accessGroup = accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        
        let status = SecItemAdd(query as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw KeychainError.saveFailed(status)
        }
    }
    
    /// Load data from keychain
    /// - Parameter key: Keychain item key
    /// - Returns: Stored data
    func load(key: String) throws -> Data {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceIdentifier,
            kSecAttrAccount as String: key,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        // Add access group if provided
        if let accessGroup = accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        
        var result: AnyObject?
        let status = SecItemCopyMatching(query as CFDictionary, &result)
        
        guard status == errSecSuccess else {
            throw KeychainError.loadFailed(status)
        }
        
        guard let data = result as? Data else {
            throw KeychainError.invalidData
        }
        
        return data
    }
    
    /// Delete item from keychain
    /// - Parameter key: Keychain item key
    private func delete(key: String) throws {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceIdentifier,
            kSecAttrAccount as String: key
        ]
        
        // Add access group if provided
        if let accessGroup = accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        
        let status = SecItemDelete(query as CFDictionary)
        guard status == errSecSuccess || status == errSecItemNotFound else {
            throw KeychainError.deleteFailed(status)
        }
    }
    
    /// Check if an item exists in keychain
    /// - Parameter key: Keychain item key
    /// - Returns: True if item exists
    func itemExists(key: String) -> Bool {
        var query: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: serviceIdentifier,
            kSecAttrAccount as String: key,
            kSecMatchLimit as String: kSecMatchLimitOne
        ]
        
        // Add access group if provided
        if let accessGroup = accessGroup {
            query[kSecAttrAccessGroup as String] = accessGroup
        }
        
        let status = SecItemCopyMatching(query as CFDictionary, nil)
        return status == errSecSuccess
    }
    
    // MARK: - Access Control
    
    private func createAccessControl(requiresBiometric: Bool) throws -> SecAccessControl {
        var accessControlFlags: SecAccessControlCreateFlags = []
        
        if requiresBiometric {
            // Require biometric authentication
            accessControlFlags.insert(.biometryCurrentSet)
            // Invalidate if biometry changes
            accessControlFlags.insert(.biometryCurrentSet)
        }
        
        var error: Unmanaged<CFError>?
        guard let accessControl = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            accessControlFlags,
            &error
        ) else {
            if let error = error?.takeRetainedValue() {
                throw KeychainError.accessControlFailed(error)
            } else {
                throw KeychainError.accessControlFailed(nil)
            }
        }
        
        return accessControl
    }
    
    // MARK: - Utility Methods
    
    /// Clear all items stored by this service
    func clearAll() {
        let keys = [
            "auth_tokens",
            "device_key_share"
        ]
        
        for key in keys {
            try? delete(key: key)
        }
    }
    
    /// Get information about stored items (for debugging)
    func getStoredItemsInfo() -> [String: Bool] {
        let keys = [
            "auth_tokens": "Authentication Tokens",
            "device_key_share": "Device Key Share"
        ]
        
        var info: [String: Bool] = [:]
        for (key, description) in keys {
            info[description] = itemExists(key: key)
        }
        
        return info
    }
}

// MARK: - Error Types

public enum KeychainError: LocalizedError {
    case saveFailed(OSStatus)
    case loadFailed(OSStatus)
    case deleteFailed(OSStatus)
    case invalidData
    case accessControlFailed(CFError?)
    case biometricAuthenticationFailed
    case itemNotFound
    
    public var errorDescription: String? {
        switch self {
        case .saveFailed(let status):
            return "Failed to save item to keychain: \(status.keychainErrorDescription)"
        case .loadFailed(let status):
            return "Failed to load item from keychain: \(status.keychainErrorDescription)"
        case .deleteFailed(let status):
            return "Failed to delete item from keychain: \(status.keychainErrorDescription)"
        case .invalidData:
            return "Invalid data retrieved from keychain."
        case .accessControlFailed(let error):
            let errorMessage = error?.localizedDescription ?? "Unknown error"
            return "Failed to create access control: \(errorMessage)"
        case .biometricAuthenticationFailed:
            return "Biometric authentication failed."
        case .itemNotFound:
            return "Item not found in keychain."
        }
    }
    
    /// Whether this error indicates the user cancelled biometric authentication
    public var isUserCancelled: Bool {
        switch self {
        case .loadFailed(let status):
            return status == errSecUserCancel || status == errSecAuthFailed
        default:
            return false
        }
    }
    
    /// Whether this error indicates biometric authentication is not available
    public var isBiometricUnavailable: Bool {
        switch self {
        case .loadFailed(let status):
            return status == errSecNotAvailable
        default:
            return false
        }
    }
}

// MARK: - OSStatus Extensions

private extension OSStatus {
    var keychainErrorDescription: String {
        switch self {
        case errSecSuccess:
            return "No error."
        case errSecUnimplemented:
            return "Function or operation not implemented."
        case errSecParam:
            return "One or more parameters passed to the function were not valid."
        case errSecAllocate:
            return "Failed to allocate memory."
        case errSecNotAvailable:
            return "No trust results are available."
        case errSecAuthFailed:
            return "Authorization/authentication failed."
        case errSecDuplicateItem:
            return "The item already exists."
        case errSecItemNotFound:
            return "The item cannot be found."
        case errSecInteractionNotAllowed:
            return "Interaction with the Security Server is not allowed."
        case errSecDecode:
            return "Unable to decode the provided data."
        case errSecUserCancel:
            return "User cancelled the operation."
        default:
            return "Unknown error: \(self)"
        }
    }
}