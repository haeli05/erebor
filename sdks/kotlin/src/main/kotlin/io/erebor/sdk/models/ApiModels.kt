package io.erebor.sdk.models

import kotlinx.serialization.Serializable

/**
 * Generic API response wrapper.
 */
@Serializable
data class ApiResponse<T>(
    /**
     * Whether the request was successful
     */
    val success: Boolean,
    
    /**
     * Response data (only present if successful)
     */
    val data: T? = null,
    
    /**
     * Error message (only present if failed)
     */
    val error: String? = null,
    
    /**
     * Error code (only present if failed)
     */
    val code: String? = null
)

/**
 * Base class for all Erebor SDK exceptions.
 */
abstract class EreborException(
    message: String,
    val code: String = "UNKNOWN_ERROR",
    cause: Throwable? = null
) : Exception(message, cause)

/**
 * Authentication-related errors.
 */
class AuthException(
    message: String,
    code: String = "AUTH_ERROR",
    cause: Throwable? = null
) : EreborException(message, code, cause)

/**
 * Wallet-related errors.
 */
class WalletException(
    message: String,
    code: String = "WALLET_ERROR",
    cause: Throwable? = null
) : EreborException(message, code, cause)

/**
 * Network-related errors.
 */
class NetworkException(
    message: String,
    code: String = "NETWORK_ERROR",
    cause: Throwable? = null
) : EreborException(message, code, cause)

/**
 * Biometric authentication errors.
 */
class BiometricException(
    message: String,
    code: String = "BIOMETRIC_ERROR",
    cause: Throwable? = null
) : EreborException(message, code, cause)

/**
 * SIWE (Sign-In With Ethereum) nonce response.
 */
@Serializable
data class SiweNonceResponse(
    val nonce: String
)

/**
 * Signature response from API.
 */
@Serializable
data class SignatureResponse(
    val signature: String
)

/**
 * Signed transaction response from API.
 */
@Serializable
data class SignedTransactionResponse(
    val signedTransaction: String
)

/**
 * Transaction hash response from API.
 */
@Serializable
data class TransactionHashResponse(
    val txHash: String
)