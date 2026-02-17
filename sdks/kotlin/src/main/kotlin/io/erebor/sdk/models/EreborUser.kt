package io.erebor.sdk.models

import kotlinx.serialization.Serializable

/**
 * Erebor user account information.
 */
@Serializable
data class EreborUser(
    /**
     * Unique user identifier
     */
    val id: String,
    
    /**
     * User's email address (if available)
     */
    val email: String? = null,
    
    /**
     * User's wallets
     */
    val wallets: List<EreborWallet> = emptyList(),
    
    /**
     * Linked external accounts
     */
    val linkedAccounts: List<LinkedAccount> = emptyList(),
    
    /**
     * Account creation timestamp (ISO 8601)
     */
    val createdAt: String
)

/**
 * External account linked to user.
 */
@Serializable
data class LinkedAccount(
    /**
     * Authentication provider
     */
    val provider: AuthProvider,
    
    /**
     * Provider's user ID
     */
    val providerUserId: String,
    
    /**
     * Email from the provider (if available)
     */
    val email: String? = null,
    
    /**
     * Username from the provider (if available)
     */
    val username: String? = null
)