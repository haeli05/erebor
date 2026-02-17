package io.erebor.sdk.storage

import android.content.Context
import android.content.SharedPreferences
import androidx.security.crypto.EncryptedSharedPreferences
import androidx.security.crypto.MasterKey
import io.erebor.sdk.models.AuthTokens
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json

/**
 * Secure storage for authentication tokens using Android's EncryptedSharedPreferences.
 */
class SecureTokenStore(context: Context, private val tokenPrefix: String = "erebor") {
    
    private val json = Json { ignoreUnknownKeys = true }
    
    private val sharedPreferences: SharedPreferences by lazy {
        val masterKey = MasterKey.Builder(context)
            .setKeyScheme(MasterKey.KeyScheme.AES256_GCM)
            .build()
            
        EncryptedSharedPreferences.create(
            context,
            "${tokenPrefix}_tokens",
            masterKey,
            EncryptedSharedPreferences.PrefKeyEncryptionScheme.AES256_SIV,
            EncryptedSharedPreferences.PrefValueEncryptionScheme.AES256_GCM
        )
    }
    
    /**
     * Save authentication tokens securely.
     */
    fun saveTokens(tokens: AuthTokens) {
        try {
            val tokensJson = json.encodeToString(tokens)
            val expiryTime = System.currentTimeMillis() + (tokens.expiresIn * 1000)
            
            sharedPreferences.edit()
                .putString(KEY_TOKENS, tokensJson)
                .putLong(KEY_EXPIRY, expiryTime)
                .apply()
        } catch (e: Exception) {
            throw SecurityException("Failed to save tokens", e)
        }
    }
    
    /**
     * Load authentication tokens from secure storage.
     * Returns null if no tokens are stored or if they have expired.
     */
    fun loadTokens(): AuthTokens? {
        try {
            val tokensJson = sharedPreferences.getString(KEY_TOKENS, null) ?: return null
            val expiryTime = sharedPreferences.getLong(KEY_EXPIRY, 0)
            
            // Check if tokens have expired
            if (System.currentTimeMillis() >= expiryTime) {
                clearTokens()
                return null
            }
            
            return json.decodeFromString<AuthTokens>(tokensJson)
        } catch (e: Exception) {
            // If we can't decrypt or parse, clear the stored data
            clearTokens()
            return null
        }
    }
    
    /**
     * Clear stored authentication tokens.
     */
    fun clearTokens() {
        sharedPreferences.edit()
            .remove(KEY_TOKENS)
            .remove(KEY_EXPIRY)
            .apply()
    }
    
    /**
     * Check if stored tokens should be refreshed.
     * Returns true if tokens expire within 5 minutes.
     */
    fun shouldRefreshToken(): Boolean {
        val expiryTime = sharedPreferences.getLong(KEY_EXPIRY, 0)
        if (expiryTime == 0L) return false
        
        val now = System.currentTimeMillis()
        val fiveMinutes = 5 * 60 * 1000L
        
        return now >= (expiryTime - fiveMinutes)
    }
    
    companion object {
        private const val KEY_TOKENS = "auth_tokens"
        private const val KEY_EXPIRY = "token_expiry"
    }
}