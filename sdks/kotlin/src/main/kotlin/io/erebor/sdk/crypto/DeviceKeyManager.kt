package io.erebor.sdk.crypto

import io.erebor.sdk.storage.DeviceShareStore
import io.erebor.sdk.wallet.BiometricGate

/**
 * Manages device-side cryptographic key shares for MPC wallets.
 * 
 * This class handles the secure generation, storage, and retrieval of device key shares
 * that are used in multi-party computation (MPC) wallet operations.
 */
class DeviceKeyManager(
    private val deviceShareStore: DeviceShareStore,
    private val biometricGate: BiometricGate
) {
    
    /**
     * Generate a new device key share for a wallet.
     * 
     * @param walletId The wallet ID to generate a key share for
     * @return The generated key share (hex string)
     */
    suspend fun generateKeyShare(walletId: String): String {
        // In a real implementation, this would use proper cryptographic key generation
        // For now, we'll create a mock key share
        val keyShare = generateSecureRandomBytes(32).toHexString()
        
        deviceShareStore.storeKeyShare(walletId, keyShare)
        
        return keyShare
    }
    
    /**
     * Retrieve a device key share for a wallet.
     * Requires biometric authentication if available.
     * 
     * @param walletId The wallet ID to retrieve the key share for
     * @param requireBiometric Whether to require biometric authentication
     * @return The key share or null if not found
     */
    suspend fun getKeyShare(walletId: String, requireBiometric: Boolean = true): String? {
        return deviceShareStore.getKeyShare(walletId, requireBiometric)
    }
    
    /**
     * Delete a device key share for a wallet.
     * 
     * @param walletId The wallet ID to delete the key share for
     */
    suspend fun deleteKeyShare(walletId: String) {
        deviceShareStore.removeKeyShare(walletId)
    }
    
    /**
     * Check if a key share exists for a wallet.
     * 
     * @param walletId The wallet ID to check
     * @return True if a key share exists
     */
    fun hasKeyShare(walletId: String): Boolean {
        return deviceShareStore.hasKeyShare(walletId)
    }
    
    /**
     * Clear all stored key shares.
     * Requires biometric authentication if available.
     */
    suspend fun clearAllKeyShares() {
        deviceShareStore.clearAllKeyShares()
    }
    
    /**
     * Derive a signing key from the device key share.
     * This would typically involve MPC operations with the server.
     * 
     * @param walletId The wallet ID
     * @param derivationPath BIP-44 derivation path (optional)
     * @return Derived signing key material
     */
    suspend fun deriveSigningKey(walletId: String, derivationPath: String? = null): SigningKeyMaterial {
        val keyShare = getKeyShare(walletId) 
            ?: throw SecurityException("No key share found for wallet $walletId")
        
        // In a real implementation, this would perform MPC key derivation
        // with the Erebor backend to get the final signing key
        return SigningKeyMaterial(
            publicKey = "0x" + generateSecureRandomBytes(33).toHexString(), // Mock public key
            keyShare = keyShare,
            derivationPath = derivationPath
        )
    }
    
    private fun generateSecureRandomBytes(size: Int): ByteArray {
        val bytes = ByteArray(size)
        java.security.SecureRandom().nextBytes(bytes)
        return bytes
    }
}

/**
 * Represents signing key material derived from device key share.
 */
data class SigningKeyMaterial(
    val publicKey: String,
    val keyShare: String,
    val derivationPath: String?
)

/**
 * Extension function to convert ByteArray to hex string.
 */
private fun ByteArray.toHexString(): String {
    return joinToString("") { "%02x".format(it) }
}