import Foundation
import Security

/// Manages secure storage of device key shares with biometric protection
public class DeviceShareStore {
    private let keychainStore: KeychainStore
    private let biometricGate: BiometricGate
    
    init(keychainStore: KeychainStore) {
        self.keychainStore = keychainStore
        self.biometricGate = BiometricGate()
    }
    
    // MARK: - Device Share Management
    
    /// Save encrypted device key share
    /// - Parameters:
    ///   - encryptedShare: Encrypted key share data
    ///   - walletId: Wallet ID this share belongs to
    ///   - requiresBiometric: Whether biometric authentication is required for retrieval
    func saveDeviceShare(
        _ encryptedShare: Data,
        forWallet walletId: String,
        requiresBiometric: Bool = true
    ) throws {
        let shareData = DeviceShareData(
            walletId: walletId,
            encryptedShare: encryptedShare,
            createdAt: Date(),
            requiresBiometric: requiresBiometric
        )
        
        do {
            let data = try JSONEncoder().encode(shareData)
            try keychainStore.saveDeviceKeyShare(data, requiresBiometric: requiresBiometric)
        } catch {
            throw DeviceShareError.saveFailed(error)
        }
    }
    
    /// Load encrypted device key share with biometric authentication
    /// - Parameters:
    ///   - walletId: Wallet ID to load share for
    ///   - reason: Reason to show user for biometric authentication
    /// - Returns: Encrypted key share data
    func loadDeviceShare(
        forWallet walletId: String,
        reason: String = "Access your wallet key"
    ) async throws -> Data {
        do {
            let data = try keychainStore.loadDeviceKeyShare()
            let shareData = try JSONDecoder().decode(DeviceShareData.self, from: data)
            
            // Verify wallet ID matches
            guard shareData.walletId == walletId else {
                throw DeviceShareError.walletMismatch
            }
            
            // Perform additional biometric check if required
            if shareData.requiresBiometric && biometricGate.isAvailable {
                let authenticated = try await biometricGate.authenticate(reason: reason)
                if !authenticated {
                    throw DeviceShareError.biometricAuthenticationFailed
                }
            }
            
            return shareData.encryptedShare
        } catch let keychainError as KeychainError {
            if keychainError.isUserCancelled {
                throw DeviceShareError.userCancelled
            } else if keychainError.isBiometricUnavailable {
                throw DeviceShareError.biometricUnavailable
            } else {
                throw DeviceShareError.loadFailed(keychainError)
            }
        } catch {
            throw DeviceShareError.loadFailed(error)
        }
    }
    
    /// Check if device share exists for a wallet
    /// - Parameter walletId: Wallet ID to check
    /// - Returns: True if share exists
    func hasDeviceShare(forWallet walletId: String) -> Bool {
        guard let data = try? keychainStore.loadDeviceKeyShare(),
              let shareData = try? JSONDecoder().decode(DeviceShareData.self, from: data) else {
            return false
        }
        
        return shareData.walletId == walletId
    }
    
    /// Delete device share for a wallet
    /// - Parameter walletId: Wallet ID to delete share for
    func deleteDeviceShare(forWallet walletId: String) throws {
        // First verify the share belongs to this wallet
        guard hasDeviceShare(forWallet: walletId) else {
            throw DeviceShareError.shareNotFound
        }
        
        keychainStore.clearDeviceKeyShare()
    }
    
    /// Get metadata about stored device share
    /// - Returns: Share metadata or nil if no share exists
    func getDeviceShareMetadata() -> DeviceShareMetadata? {
        guard let data = try? keychainStore.loadDeviceKeyShare(),
              let shareData = try? JSONDecoder().decode(DeviceShareData.self, from: data) else {
            return nil
        }
        
        return DeviceShareMetadata(
            walletId: shareData.walletId,
            createdAt: shareData.createdAt,
            requiresBiometric: shareData.requiresBiometric,
            biometricType: biometricGate.biometricType
        )
    }
    
    // MARK: - Migration and Recovery
    
    /// Migrate device share to use biometric protection
    /// - Parameter walletId: Wallet ID to migrate
    func migrateToBiometric(forWallet walletId: String) async throws {
        guard biometricGate.isAvailable else {
            throw DeviceShareError.biometricUnavailable
        }
        
        // Load existing share without biometric requirement
        guard let data = try? keychainStore.loadDeviceKeyShare(),
              let shareData = try? JSONDecoder().decode(DeviceShareData.self, from: data),
              shareData.walletId == walletId else {
            throw DeviceShareError.shareNotFound
        }
        
        // Re-save with biometric requirement
        try saveDeviceShare(
            shareData.encryptedShare,
            forWallet: walletId,
            requiresBiometric: true
        )
    }
    
    /// Create backup of device share (for recovery purposes)
    /// - Parameter walletId: Wallet ID to backup
    /// - Returns: Encrypted backup data
    func createBackup(forWallet walletId: String) async throws -> Data {
        let shareData = try await loadDeviceShare(
            forWallet: walletId,
            reason: "Create backup of your wallet key"
        )
        
        // Additional encryption for backup
        let backup = DeviceShareBackup(
            walletId: walletId,
            encryptedShare: shareData,
            createdAt: Date(),
            backupVersion: 1
        )
        
        return try JSONEncoder().encode(backup)
    }
    
    /// Restore device share from backup
    /// - Parameters:
    ///   - backupData: Encrypted backup data
    ///   - walletId: Wallet ID to restore for
    func restoreFromBackup(_ backupData: Data, forWallet walletId: String) throws {
        let backup = try JSONDecoder().decode(DeviceShareBackup.self, from: backupData)
        
        // Verify wallet ID matches
        guard backup.walletId == walletId else {
            throw DeviceShareError.walletMismatch
        }
        
        // Save restored share
        try saveDeviceShare(
            backup.encryptedShare,
            forWallet: walletId,
            requiresBiometric: true
        )
    }
}

// MARK: - Data Models

/// Internal storage format for device key shares
private struct DeviceShareData: Codable {
    let walletId: String
    let encryptedShare: Data
    let createdAt: Date
    let requiresBiometric: Bool
}

/// Metadata about stored device share
public struct DeviceShareMetadata {
    public let walletId: String
    public let createdAt: Date
    public let requiresBiometric: Bool
    public let biometricType: BiometricType
}

/// Backup format for device key shares
private struct DeviceShareBackup: Codable {
    let walletId: String
    let encryptedShare: Data
    let createdAt: Date
    let backupVersion: Int
}

// MARK: - Error Types

public enum DeviceShareError: LocalizedError {
    case saveFailed(Error)
    case loadFailed(Error)
    case shareNotFound
    case walletMismatch
    case biometricAuthenticationFailed
    case biometricUnavailable
    case userCancelled
    case invalidBackupData
    case backupVersionMismatch
    
    public var errorDescription: String? {
        switch self {
        case .saveFailed(let error):
            return "Failed to save device key share: \(error.localizedDescription)"
        case .loadFailed(let error):
            return "Failed to load device key share: \(error.localizedDescription)"
        case .shareNotFound:
            return "Device key share not found for the specified wallet."
        case .walletMismatch:
            return "Device key share does not belong to the specified wallet."
        case .biometricAuthenticationFailed:
            return "Biometric authentication failed. Please try again."
        case .biometricUnavailable:
            return "Biometric authentication is not available on this device."
        case .userCancelled:
            return "Operation was cancelled by the user."
        case .invalidBackupData:
            return "Invalid backup data format."
        case .backupVersionMismatch:
            return "Backup version is not compatible with current implementation."
        }
    }
    
    /// Whether this error allows retry
    public var canRetry: Bool {
        switch self {
        case .biometricAuthenticationFailed, .userCancelled:
            return true
        default:
            return false
        }
    }
    
    /// Whether this error indicates a configuration issue
    public var isConfigurationError: Bool {
        switch self {
        case .biometricUnavailable:
            return true
        default:
            return false
        }
    }
}