package io.erebor.sdk.models

import kotlinx.serialization.Serializable

/**
 * Configuration for the Erebor SDK.
 */
@Serializable
data class EreborConfig(
    /**
     * The base URL of the Erebor API (e.g., "https://api.erebor.io")
     */
    val apiUrl: String,
    
    /**
     * Your application ID
     */
    val appId: String,
    
    /**
     * Available login methods for your application
     */
    val loginMethods: List<LoginMethod>,
    
    /**
     * Supported blockchain chains (optional)
     */
    val chains: List<Chain>? = null,
    
    /**
     * UI appearance configuration (optional)
     */
    val appearance: AppearanceConfig? = null,
    
    /**
     * Prefix for token storage keys (default: "erebor")
     */
    val tokenPrefix: String? = null
)

/**
 * UI appearance configuration.
 */
@Serializable
data class AppearanceConfig(
    /**
     * UI theme preference
     */
    val theme: Theme? = null,
    
    /**
     * Custom logo URL
     */
    val logo: String? = null,
    
    /**
     * Primary color (hex format)
     */
    val primaryColor: String? = null,
    
    /**
     * Border radius for UI components
     */
    val borderRadius: String? = null
)

/**
 * UI theme options.
 */
@Serializable
enum class Theme {
    LIGHT,
    DARK
}

/**
 * Blockchain chain configuration.
 */
@Serializable
data class Chain(
    /**
     * Chain ID (e.g., 1 for Ethereum mainnet)
     */
    val id: Long,
    
    /**
     * Human-readable chain name
     */
    val name: String,
    
    /**
     * RPC endpoint URL
     */
    val rpcUrl: String,
    
    /**
     * Native currency information (optional)
     */
    val nativeCurrency: NativeCurrency? = null,
    
    /**
     * Block explorer base URL (optional)
     */
    val blockExplorer: String? = null
)

/**
 * Native currency information for a blockchain.
 */
@Serializable
data class NativeCurrency(
    /**
     * Currency name (e.g., "Ether")
     */
    val name: String,
    
    /**
     * Currency symbol (e.g., "ETH")
     */
    val symbol: String,
    
    /**
     * Number of decimal places
     */
    val decimals: Int
)