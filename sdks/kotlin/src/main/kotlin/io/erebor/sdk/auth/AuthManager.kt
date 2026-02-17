package io.erebor.sdk.auth

import android.app.Activity
import io.erebor.sdk.models.*
import io.erebor.sdk.network.ApiClient
import io.erebor.sdk.storage.SecureTokenStore
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Manages user authentication and account operations.
 */
class AuthManager(
    private val client: ApiClient,
    private val store: SecureTokenStore
) {
    
    private val _authState = MutableStateFlow(
        AuthState(
            ready = true,
            authenticated = store.loadTokens() != null,
            user = null,
            loading = false
        )
    )
    
    /**
     * Current authentication state as a flow.
     */
    val authState: StateFlow<AuthState> = _authState.asStateFlow()
    
    /**
     * Start email-based authentication by sending an OTP.
     * 
     * @param email The email address to send the OTP to
     * @return OtpSession containing session information
     */
    suspend fun loginWithEmail(email: String): OtpSession {
        _authState.value = _authState.value.copy(loading = true)
        
        try {
            client.sendEmailOtp(email)
            
            // Create a mock session since the API doesn't return session info
            val session = OtpSession(
                sessionId = "email_$email",
                contact = email,
                expiresAt = System.currentTimeMillis() + (10 * 60 * 1000) // 10 minutes
            )
            
            _authState.value = _authState.value.copy(loading = false)
            return session
        } catch (e: Exception) {
            _authState.value = _authState.value.copy(loading = false)
            throw e
        }
    }
    
    /**
     * Complete email authentication by verifying the OTP code.
     * 
     * @param session The OTP session from loginWithEmail
     * @param code The OTP code received via email
     * @return Authentication result with tokens
     */
    suspend fun verifyEmailOtp(session: OtpSession, code: String): AuthResult {
        _authState.value = _authState.value.copy(loading = true)
        
        try {
            val tokens = client.verifyEmailOtp(session.contact, code)
            val user = client.getMe()
            
            val authResult = AuthResult(
                accessToken = tokens.accessToken,
                refreshToken = tokens.refreshToken,
                userId = user.id,
                expiresIn = tokens.expiresIn
            )
            
            _authState.value = AuthState(
                ready = true,
                authenticated = true,
                user = user,
                loading = false
            )
            
            return authResult
        } catch (e: Exception) {
            _authState.value = _authState.value.copy(loading = false)
            throw e
        }
    }
    
    /**
     * Start phone-based authentication by sending an OTP.
     * 
     * @param phone The phone number to send the OTP to
     * @return OtpSession containing session information
     */
    suspend fun loginWithPhone(phone: String): OtpSession {
        _authState.value = _authState.value.copy(loading = true)
        
        try {
            client.sendPhoneOtp(phone)
            
            // Create a mock session since the API doesn't return session info
            val session = OtpSession(
                sessionId = "phone_$phone",
                contact = phone,
                expiresAt = System.currentTimeMillis() + (10 * 60 * 1000) // 10 minutes
            )
            
            _authState.value = _authState.value.copy(loading = false)
            return session
        } catch (e: Exception) {
            _authState.value = _authState.value.copy(loading = false)
            throw e
        }
    }
    
    /**
     * Complete phone authentication by verifying the OTP code.
     * 
     * @param session The OTP session from loginWithPhone
     * @param code The OTP code received via SMS
     * @return Authentication result with tokens
     */
    suspend fun verifyPhoneOtp(session: OtpSession, code: String): AuthResult {
        _authState.value = _authState.value.copy(loading = true)
        
        try {
            val tokens = client.verifyPhoneOtp(session.contact, code)
            val user = client.getMe()
            
            val authResult = AuthResult(
                accessToken = tokens.accessToken,
                refreshToken = tokens.refreshToken,
                userId = user.id,
                expiresIn = tokens.expiresIn
            )
            
            _authState.value = AuthState(
                ready = true,
                authenticated = true,
                user = user,
                loading = false
            )
            
            return authResult
        } catch (e: Exception) {
            _authState.value = _authState.value.copy(loading = false)
            throw e
        }
    }
    
    /**
     * Authenticate using Google OAuth.
     * 
     * @param activity The activity to launch the Google sign-in from
     * @return Authentication result with tokens
     */
    suspend fun loginWithGoogle(activity: Activity): AuthResult {
        _authState.value = _authState.value.copy(loading = true)
        
        try {
            val googleAuthProvider = GoogleAuthProvider()
            val authCode = googleAuthProvider.authenticate(activity)
            
            val tokens = client.googleAuth(authCode.code, authCode.redirectUri)
            val user = client.getMe()
            
            val authResult = AuthResult(
                accessToken = tokens.accessToken,
                refreshToken = tokens.refreshToken,
                userId = user.id,
                expiresIn = tokens.expiresIn
            )
            
            _authState.value = AuthState(
                ready = true,
                authenticated = true,
                user = user,
                loading = false
            )
            
            return authResult
        } catch (e: Exception) {
            _authState.value = _authState.value.copy(loading = false)
            throw e
        }
    }
    
    /**
     * Authenticate using Sign-In With Ethereum (SIWE).
     * 
     * @param message The SIWE message that was signed
     * @param signature The signature of the SIWE message
     * @return Authentication result with tokens
     */
    suspend fun loginWithSiwe(message: String, signature: String): AuthResult {
        _authState.value = _authState.value.copy(loading = true)
        
        try {
            val tokens = client.verifySiwe(message, signature)
            val user = client.getMe()
            
            val authResult = AuthResult(
                accessToken = tokens.accessToken,
                refreshToken = tokens.refreshToken,
                userId = user.id,
                expiresIn = tokens.expiresIn
            )
            
            _authState.value = AuthState(
                ready = true,
                authenticated = true,
                user = user,
                loading = false
            )
            
            return authResult
        } catch (e: Exception) {
            _authState.value = _authState.value.copy(loading = false)
            throw e
        }
    }
    
    /**
     * Get a nonce for SIWE authentication.
     * 
     * @return A nonce string to include in the SIWE message
     */
    suspend fun getSiweNonce(): String {
        return client.getSiweNonce()
    }
    
    /**
     * Refresh the current authentication tokens.
     * 
     * @return New authentication result with refreshed tokens
     */
    suspend fun refresh(): AuthResult {
        try {
            val tokens = client.refreshTokens()
            val user = client.getMe()
            
            val authResult = AuthResult(
                accessToken = tokens.accessToken,
                refreshToken = tokens.refreshToken,
                userId = user.id,
                expiresIn = tokens.expiresIn
            )
            
            _authState.value = AuthState(
                ready = true,
                authenticated = true,
                user = user,
                loading = false
            )
            
            return authResult
        } catch (e: Exception) {
            // If refresh fails, clear the auth state
            _authState.value = AuthState(
                ready = true,
                authenticated = false,
                user = null,
                loading = false
            )
            throw e
        }
    }
    
    /**
     * Log out the current user and clear all stored tokens.
     */
    suspend fun logout() {
        _authState.value = _authState.value.copy(loading = true)
        
        try {
            client.logout()
        } finally {
            _authState.value = AuthState(
                ready = true,
                authenticated = false,
                user = null,
                loading = false
            )
        }
    }
    
    /**
     * Link an external account to the current user.
     * 
     * @param provider The authentication provider (e.g., AuthProvider.GOOGLE)
     * @param token The provider's authentication token
     * @return The linked account information
     */
    suspend fun linkAccount(provider: AuthProvider, token: String): LinkedAccount {
        if (!authState.value.authenticated) {
            throw AuthException("User must be authenticated to link accounts", "NOT_AUTHENTICATED")
        }
        
        try {
            val linkedAccount = client.linkAccount(provider.name.lowercase(), token)
            
            // Refresh user data to get updated linked accounts
            val updatedUser = client.getMe()
            _authState.value = _authState.value.copy(user = updatedUser)
            
            return linkedAccount
        } catch (e: Exception) {
            throw e
        }
    }
    
    /**
     * Unlink an external account from the current user.
     * 
     * @param provider The authentication provider to unlink
     */
    suspend fun unlinkAccount(provider: AuthProvider) {
        if (!authState.value.authenticated) {
            throw AuthException("User must be authenticated to unlink accounts", "NOT_AUTHENTICATED")
        }
        
        try {
            client.unlinkAccount(provider.name.lowercase())
            
            // Refresh user data to get updated linked accounts
            val updatedUser = client.getMe()
            _authState.value = _authState.value.copy(user = updatedUser)
        } catch (e: Exception) {
            throw e
        }
    }
    
    /**
     * Load the current user if authenticated.
     * This should be called on app startup to restore authentication state.
     */
    suspend fun loadCurrentUser(): EreborUser? {
        if (store.loadTokens() == null) {
            return null
        }
        
        try {
            val user = client.getMe()
            _authState.value = AuthState(
                ready = true,
                authenticated = true,
                user = user,
                loading = false
            )
            return user
        } catch (e: Exception) {
            // If we can't load the user, clear auth state
            _authState.value = AuthState(
                ready = true,
                authenticated = false,
                user = null,
                loading = false
            )
            return null
        }
    }
}