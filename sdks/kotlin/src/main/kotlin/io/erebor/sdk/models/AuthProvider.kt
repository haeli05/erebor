package io.erebor.sdk.models

import kotlinx.serialization.Serializable

/**
 * Available authentication providers.
 */
@Serializable
enum class AuthProvider {
    GOOGLE,
    APPLE,
    TWITTER,
    DISCORD,
    GITHUB
}

/**
 * Available login methods.
 */
@Serializable
enum class LoginMethod {
    EMAIL,
    PHONE,
    GOOGLE,
    APPLE,
    TWITTER,
    DISCORD,
    GITHUB,
    SIWE // Sign-In With Ethereum
}

/**
 * Authentication result containing tokens.
 */
@Serializable
data class AuthResult(
    /**
     * JWT access token
     */
    val accessToken: String,
    
    /**
     * Refresh token for obtaining new access tokens
     */
    val refreshToken: String,
    
    /**
     * User ID
     */
    val userId: String,
    
    /**
     * Token expiry time in seconds
     */
    val expiresIn: Long
)

/**
 * Authentication tokens for storage.
 */
@Serializable
data class AuthTokens(
    /**
     * JWT access token
     */
    val accessToken: String,
    
    /**
     * Refresh token
     */
    val refreshToken: String,
    
    /**
     * Token expiry time in seconds
     */
    val expiresIn: Long
)

/**
 * Current authentication state.
 */
@Serializable
data class AuthState(
    /**
     * Whether the SDK is ready for use
     */
    val ready: Boolean,
    
    /**
     * Whether a user is authenticated
     */
    val authenticated: Boolean,
    
    /**
     * Current user information
     */
    val user: EreborUser? = null,
    
    /**
     * Whether an authentication operation is in progress
     */
    val loading: Boolean = false
)

/**
 * OTP session for email/phone authentication.
 */
@Serializable
data class OtpSession(
    /**
     * Session identifier
     */
    val sessionId: String,
    
    /**
     * Email or phone number
     */
    val contact: String,
    
    /**
     * OTP expiry time (milliseconds since epoch)
     */
    val expiresAt: Long
)