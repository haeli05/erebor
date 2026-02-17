package io.erebor.sdk.models

import kotlinx.serialization.Serializable
import java.math.BigInteger

/**
 * Erebor wallet information.
 */
@Serializable
data class EreborWallet(
    /**
     * Unique wallet identifier
     */
    val id: String,
    
    /**
     * Wallet address (hex string)
     */
    val address: String,
    
    /**
     * Chain ID where this wallet operates
     */
    val chainId: Long,
    
    /**
     * Type of blockchain
     */
    val chainType: ChainType,
    
    /**
     * Whether this wallet was imported (vs generated)
     */
    val imported: Boolean? = null,
    
    /**
     * Wallet creation timestamp (ISO 8601)
     */
    val createdAt: String
)

/**
 * Supported blockchain types.
 */
@Serializable
enum class ChainType {
    EVM,    // Ethereum Virtual Machine compatible
    SOLANA  // Solana blockchain
}

/**
 * Transaction request for sending transactions.
 */
@Serializable
data class TransactionRequest(
    /**
     * Recipient address
     */
    val to: String,
    
    /**
     * Amount to send (in wei for EVM chains)
     */
    val value: String? = null,
    
    /**
     * Transaction data (hex string)
     */
    val data: String? = null,
    
    /**
     * Chain ID
     */
    val chainId: Long,
    
    /**
     * Gas limit
     */
    val gasLimit: String? = null,
    
    /**
     * Gas price (legacy)
     */
    val gasPrice: String? = null,
    
    /**
     * Maximum fee per gas (EIP-1559)
     */
    val maxFeePerGas: String? = null,
    
    /**
     * Maximum priority fee per gas (EIP-1559)
     */
    val maxPriorityFeePerGas: String? = null,
    
    /**
     * Transaction nonce
     */
    val nonce: Long? = null
)

/**
 * Signed transaction ready for broadcast.
 */
@Serializable
data class SignedTransaction(
    /**
     * Raw signed transaction (hex string)
     */
    val raw: String,
    
    /**
     * Transaction hash
     */
    val hash: String
)

/**
 * Transaction receipt after mining.
 */
@Serializable
data class TransactionReceipt(
    /**
     * Transaction hash
     */
    val hash: String,
    
    /**
     * Block number
     */
    val blockNumber: Long,
    
    /**
     * Block hash
     */
    val blockHash: String,
    
    /**
     * Transaction index within the block
     */
    val transactionIndex: Long,
    
    /**
     * Transaction status
     */
    val status: TransactionStatus,
    
    /**
     * Gas used by the transaction
     */
    val gasUsed: String
)

/**
 * Transaction status.
 */
@Serializable
enum class TransactionStatus {
    SUCCESS,
    FAILED
}

/**
 * Message signing request.
 */
@Serializable
data class SignMessageRequest(
    /**
     * Message to sign
     */
    val message: String,
    
    /**
     * Wallet ID (optional, uses active wallet if not specified)
     */
    val walletId: String? = null
)

/**
 * Policy decision for security policies.
 */
@Serializable
enum class PolicyDecision {
    ALLOW,
    DENY,
    REQUIRE_APPROVAL
}