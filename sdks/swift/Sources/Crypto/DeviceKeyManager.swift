import Foundation
import CryptoKit
import Security

/// Manages cryptographic operations for device-side key shares
public class DeviceKeyManager {
    private let keychainStore: KeychainStore
    private let deviceShareStore: DeviceShareStore
    
    init(keychainStore: KeychainStore) {
        self.keychainStore = keychainStore
        self.deviceShareStore = DeviceShareStore(keychainStore: keychainStore)
    }
    
    // MARK: - Key Share Generation
    
    /// Generate a new device key share
    /// - Parameters:
    ///   - walletId: Wallet ID this share belongs to
    ///   - password: Optional password for additional encryption
    /// - Returns: Public key for the generated key share
    func generateDeviceKeyShare(
        forWallet walletId: String,
        password: String? = nil
    ) throws -> Data {
        // Generate a random 32-byte key share
        let keyShare = generateSecureRandomBytes(count: 32)
        
        // Encrypt the key share
        let encryptedShare = try encryptKeyShare(keyShare, password: password)
        
        // Store encrypted share securely
        try deviceShareStore.saveDeviceShare(
            encryptedShare,
            forWallet: walletId,
            requiresBiometric: true
        )
        
        // Derive and return public key
        let publicKey = try derivePublicKey(from: keyShare)
        
        // Clear key share from memory
        clearMemory(keyShare)
        
        return publicKey
    }
    
    /// Check if device key share exists for wallet
    /// - Parameter walletId: Wallet ID to check
    /// - Returns: True if share exists
    func hasDeviceKeyShare(forWallet walletId: String) -> Bool {
        return deviceShareStore.hasDeviceShare(forWallet: walletId)
    }
    
    // MARK: - Key Share Usage
    
    /// Get device key share for cryptographic operations
    /// - Parameters:
    ///   - walletId: Wallet ID to get share for
    ///   - password: Optional password for decryption
    ///   - reason: Reason for biometric authentication
    /// - Returns: Decrypted key share data
    func getDeviceKeyShare(
        forWallet walletId: String,
        password: String? = nil,
        reason: String = "Access wallet key for signing"
    ) async throws -> SecureData {
        // Load encrypted share with biometric authentication
        let encryptedShare = try await deviceShareStore.loadDeviceShare(
            forWallet: walletId,
            reason: reason
        )
        
        // Decrypt the key share
        let keyShare = try decryptKeyShare(encryptedShare, password: password)
        
        return SecureData(keyShare)
    }
    
    /// Derive public key from stored key share
    /// - Parameters:
    ///   - walletId: Wallet ID
    ///   - reason: Reason for biometric authentication
    /// - Returns: Public key data
    func getPublicKey(
        forWallet walletId: String,
        reason: String = "Access wallet public key"
    ) async throws -> Data {
        let secureKeyShare = try await getDeviceKeyShare(
            forWallet: walletId,
            reason: reason
        )
        
        defer {
            secureKeyShare.clear()
        }
        
        return try derivePublicKey(from: secureKeyShare.data)
    }
    
    // MARK: - Signing Operations
    
    /// Sign data with device key share
    /// - Parameters:
    ///   - data: Data to sign
    ///   - walletId: Wallet ID to use for signing
    ///   - reason: Reason for biometric authentication
    /// - Returns: Signature data
    func sign(
        data: Data,
        withWallet walletId: String,
        reason: String = "Sign with wallet key"
    ) async throws -> Data {
        let secureKeyShare = try await getDeviceKeyShare(
            forWallet: walletId,
            reason: reason
        )
        
        defer {
            secureKeyShare.clear()
        }
        
        return try signData(data, with: secureKeyShare.data)
    }
    
    /// Sign hash with device key share
    /// - Parameters:
    ///   - hash: Hash to sign (32 bytes)
    ///   - walletId: Wallet ID to use for signing
    ///   - reason: Reason for biometric authentication
    /// - Returns: Signature data
    func signHash(
        _ hash: Data,
        withWallet walletId: String,
        reason: String = "Sign transaction"
    ) async throws -> Data {
        guard hash.count == 32 else {
            throw CryptoError.invalidHashLength
        }
        
        return try await sign(data: hash, withWallet: walletId, reason: reason)
    }
    
    // MARK: - Key Share Management
    
    /// Delete device key share
    /// - Parameter walletId: Wallet ID to delete share for
    func deleteDeviceKeyShare(forWallet walletId: String) throws {
        try deviceShareStore.deleteDeviceShare(forWallet: walletId)
    }
    
    /// Export encrypted device key share for backup
    /// - Parameters:
    ///   - walletId: Wallet ID to backup
    ///   - backupPassword: Password for backup encryption
    /// - Returns: Encrypted backup data
    func exportDeviceKeyShare(
        forWallet walletId: String,
        backupPassword: String
    ) async throws -> Data {
        return try await deviceShareStore.createBackup(forWallet: walletId)
    }
    
    /// Import device key share from backup
    /// - Parameters:
    ///   - backupData: Encrypted backup data
    ///   - walletId: Wallet ID to restore for
    ///   - backupPassword: Password for backup decryption
    func importDeviceKeyShare(
        _ backupData: Data,
        forWallet walletId: String,
        backupPassword: String
    ) throws {
        try deviceShareStore.restoreFromBackup(backupData, forWallet: walletId)
    }
    
    // MARK: - Private Cryptographic Operations
    
    private func generateSecureRandomBytes(count: Int) -> Data {
        var bytes = Data(count: count)
        let result = bytes.withUnsafeMutableBytes {
            SecRandomCopyBytes(kSecRandomDefault, count, $0.baseAddress!)
        }
        
        guard result == errSecSuccess else {
            // Fallback to CryptoKit if SecRandomCopyBytes fails
            return Data(SymmetricKey(size: .bits256).withUnsafeBytes { Data($0) })
        }
        
        return bytes
    }
    
    private func encryptKeyShare(_ keyShare: Data, password: String?) throws -> Data {
        let key: SymmetricKey
        
        if let password = password {
            // Derive key from password using PBKDF2
            key = try deriveKeyFromPassword(password)
        } else {
            // Use device-specific key
            key = try getDeviceKey()
        }
        
        // Encrypt using AES-GCM
        let sealedBox = try AES.GCM.seal(keyShare, using: key)
        
        return sealedBox.combined!
    }
    
    private func decryptKeyShare(_ encryptedShare: Data, password: String?) throws -> Data {
        let key: SymmetricKey
        
        if let password = password {
            // Derive key from password using PBKDF2
            key = try deriveKeyFromPassword(password)
        } else {
            // Use device-specific key
            key = try getDeviceKey()
        }
        
        // Decrypt using AES-GCM
        let sealedBox = try AES.GCM.SealedBox(combined: encryptedShare)
        return try AES.GCM.open(sealedBox, using: key)
    }
    
    private func deriveKeyFromPassword(_ password: String) throws -> SymmetricKey {
        let salt = "erebor.device.key.salt".data(using: .utf8)!
        let passwordData = password.data(using: .utf8)!
        
        // Use PBKDF2 with 100,000 iterations
        return try PBKDF2.derive(
            from: passwordData,
            salt: salt,
            keyLength: 32,
            iterations: 100_000
        )
    }
    
    private func getDeviceKey() throws -> SymmetricKey {
        // Try to load existing device key
        if let keyData = try? keychainStore.load(key: "device_encryption_key") {
            return SymmetricKey(data: keyData)
        }
        
        // Generate new device key
        let key = SymmetricKey(size: .bits256)
        try keychainStore.save(
            data: key.withUnsafeBytes { Data($0) },
            key: "device_encryption_key"
        )
        
        return key
    }
    
    private func derivePublicKey(from keyShare: Data) throws -> Data {
        // For secp256k1, derive public key from private key
        guard keyShare.count == 32 else {
            throw CryptoError.invalidKeyLength
        }
        
        // This is a simplified implementation
        // In production, use proper secp256k1 library
        let privateKey = try P256.Signing.PrivateKey(rawRepresentation: keyShare)
        return privateKey.publicKey.compressedRepresentation
    }
    
    private func signData(_ data: Data, with keyShare: Data) throws -> Data {
        guard keyShare.count == 32 else {
            throw CryptoError.invalidKeyLength
        }
        
        // For secp256k1 signing, this would use secp256k1 library
        // Using P256 as approximation for this example
        let privateKey = try P256.Signing.PrivateKey(rawRepresentation: keyShare)
        let signature = try privateKey.signature(for: data)
        
        return signature.derRepresentation
    }
    
    private func clearMemory(_ data: Data) {
        // Clear sensitive data from memory
        data.withUnsafeBytes { bytes in
            if let baseAddress = bytes.baseAddress {
                memset_s(UnsafeMutableRawPointer(mutating: baseAddress), bytes.count, 0, bytes.count)
            }
        }
    }
}

// MARK: - Secure Data Container

/// Container for sensitive data with automatic memory clearing
public class SecureData {
    private var _data: Data
    
    init(_ data: Data) {
        self._data = data
    }
    
    deinit {
        clear()
    }
    
    var data: Data {
        return _data
    }
    
    func clear() {
        _data.withUnsafeMutableBytes { bytes in
            if let baseAddress = bytes.baseAddress {
                memset_s(baseAddress, bytes.count, 0, bytes.count)
            }
        }
        _data = Data()
    }
}

// MARK: - PBKDF2 Implementation

private enum PBKDF2 {
    static func derive(
        from password: Data,
        salt: Data,
        keyLength: Int,
        iterations: Int
    ) throws -> SymmetricKey {
        var derivedKey = Data(count: keyLength)
        
        let result = derivedKey.withUnsafeMutableBytes { derivedKeyBytes in
            salt.withUnsafeBytes { saltBytes in
                password.withUnsafeBytes { passwordBytes in
                    CCKeyDerivationPBKDF(
                        CCPBKDFAlgorithm(kCCPBKDF2),
                        passwordBytes.baseAddress?.assumingMemoryBound(to: Int8.self),
                        password.count,
                        saltBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        salt.count,
                        CCPseudoRandomAlgorithm(kCCPRFHmacAlgSHA256),
                        UInt32(iterations),
                        derivedKeyBytes.baseAddress?.assumingMemoryBound(to: UInt8.self),
                        keyLength
                    )
                }
            }
        }
        
        guard result == kCCSuccess else {
            throw CryptoError.keyDerivationFailed
        }
        
        return SymmetricKey(data: derivedKey)
    }
}

// MARK: - Error Types

public enum CryptoError: LocalizedError {
    case invalidKeyLength
    case invalidHashLength
    case keyGenerationFailed
    case keyDerivationFailed
    case encryptionFailed
    case decryptionFailed
    case signingFailed
    case invalidSignature
    
    public var errorDescription: String? {
        switch self {
        case .invalidKeyLength:
            return "Invalid key length provided."
        case .invalidHashLength:
            return "Hash must be exactly 32 bytes."
        case .keyGenerationFailed:
            return "Failed to generate cryptographic key."
        case .keyDerivationFailed:
            return "Failed to derive key from password."
        case .encryptionFailed:
            return "Encryption operation failed."
        case .decryptionFailed:
            return "Decryption operation failed."
        case .signingFailed:
            return "Signing operation failed."
        case .invalidSignature:
            return "Invalid signature format or verification failed."
        }
    }
}

import CommonCrypto