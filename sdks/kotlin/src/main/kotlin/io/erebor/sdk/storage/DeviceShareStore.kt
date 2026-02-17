package io.erebor.sdk.storage

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import io.erebor.sdk.wallet.BiometricGate

/**
 * Secure storage for device key shares with optional biometric protection.
 */
class DeviceShareStore(
    context: Context, 
    private val biometricGate: BiometricGate,
    private val tokenPrefix: String = "erebor"
) {
    
    private val sharedPreferences: SharedPreferences by lazy {
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
            
        EncryptedSharedPreferences.create(
            context,
            "${tokenPrefix}_device_shares",
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }
    
    /**
     * Store a device key share for a wallet.
     */
    fun storeKeyShare(walletId: String, keyShare: String) {
        sharedPreferences.edit()
            .putString(getKeyShareKey(walletId), keyShare)
            .apply()
    }
    
    /**
     * Retrieve a device key share for a wallet.
     * May require biometric authentication if configured.
     */
    suspend fun getKeyShare(walletId: String, requireBiometric: Boolean = true): String? {
        if (requireBiometric && biometricGate.isAvailable) {
            val authenticated = biometricGate.authenticate("Authenticate to access wallet")
            if (!authenticated) {
                throw SecurityException("Biometric authentication failed")
            }
        }
        
        return sharedPreferences.getString(getKeyShareKey(walletId), null)
    }
    
    /**
     * Remove a device key share for a wallet.
     */
    suspend fun removeKeyShare(walletId: String) {
        if (biometricGate.isAvailable) {
            val authenticated = biometricGate.authenticate("Authenticate to remove wallet key")
            if (!authenticated) {
                throw SecurityException("Biometric authentication failed")
            }
        }
        
        sharedPreferences.edit()
            .remove(getKeyShareKey(walletId))
            .apply()
    }
    
    /**
     * Check if a key share exists for a wallet.
     */
    fun hasKeyShare(walletId: String): Boolean {
        return sharedPreferences.contains(getKeyShareKey(walletId))
    }
    
    /**
     * Clear all stored key shares. Requires biometric authentication if available.
     */
    suspend fun clearAllKeyShares() {
        if (biometricGate.isAvailable) {
            val authenticated = biometricGate.authenticate("Authenticate to clear all wallet keys")
            if (!authenticated) {
                throw SecurityException("Biometric authentication failed")
            }
        }
        
        sharedPreferences.edit().clear().apply()
    }
    
    private fun getKeyShareKey(walletId: String): String {
        return "key_share_$walletId"
    }
}