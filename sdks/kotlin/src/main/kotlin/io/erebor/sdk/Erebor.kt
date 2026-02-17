package io.erebor.sdk

import android.content.Context
import io.erebor.sdk.auth.AuthManager
import io.erebor.sdk.models.EreborConfig
import io.erebor.sdk.models.EreborUser
import io.erebor.sdk.network.ApiClient
import io.erebor.sdk.storage.SecureTokenStore
import io.erebor.sdk.wallet.BiometricGate
import io.erebor.sdk.wallet.WalletManager
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.map

/**
 * Main entry point for the Erebor SDK.
 * 
 * Usage:
 * ```kotlin
 * val config = EreborConfig(
 *     apiUrl = "https://api.erebor.io",
 *     appId = "your-app-id",
 *     loginMethods = listOf(LoginMethod.EMAIL, LoginMethod.GOOGLE)
 * )
 * 
 * Erebor.configure(context, config)
 * 
 * if (!Erebor.isAuthenticated) {
 *     // Show login UI
 * }
 * ```
 */
object Erebor {
    private var _context: Context? = null
    private var _config: EreborConfig? = null
    private var _apiClient: ApiClient? = null
    private var _tokenStore: SecureTokenStore? = null
    private var _authManager: AuthManager? = null
    private var _walletManager: WalletManager? = null
    
    /**
     * Configure the Erebor SDK with context and configuration.
     * This must be called before using any other SDK functionality.
     */
    fun configure(context: Context, config: EreborConfig) {
        _context = context.applicationContext
        _config = config
        
        _tokenStore = SecureTokenStore(context)
        _apiClient = ApiClient(config.apiUrl, _tokenStore!!, config.tokenPrefix ?: "erebor")
        _authManager = AuthManager(_apiClient!!, _tokenStore!!)
        
        // WalletManager will be created lazily when needed
    }
    
    /**
     * Check if the SDK has been configured.
     */
    val isConfigured: Boolean
        get() = _config != null && _apiClient != null
    
    /**
     * Check if a user is currently authenticated.
     */
    val isAuthenticated: Boolean
        get() {
            ensureConfigured()
            return _tokenStore?.loadTokens() != null
        }
    
    /**
     * Get the current authenticated user, or null if not authenticated.
     */
    val user: StateFlow<EreborUser?>
        get() {
            ensureConfigured()
            return _authManager!!.authState.map { it.user }
        }
    
    /**
     * Access authentication functionality.
     */
    val auth: AuthManager
        get() {
            ensureConfigured()
            return _authManager!!
        }
    
    /**
     * Access wallet management functionality.
     */
    val wallets: WalletManager
        get() {
            ensureConfigured()
            if (_walletManager == null) {
                val context = _context!!
                val biometricGate = BiometricGate(context)
                _walletManager = WalletManager(_apiClient!!, biometricGate)
            }
            return _walletManager!!
        }
    
    /**
     * Get the current configuration.
     */
    val config: EreborConfig
        get() {
            ensureConfigured()
            return _config!!
        }
    
    private fun ensureConfigured() {
        if (!isConfigured) {
            throw IllegalStateException("Erebor SDK not configured. Call Erebor.configure() first.")
        }
    }
}