package io.erebor.sdk.wallet

import io.erebor.sdk.models.*
import io.erebor.sdk.network.ApiClient
import kotlinx.coroutines.flow.MutableStateFlow
import kotlinx.coroutines.flow.StateFlow
import kotlinx.coroutines.flow.asStateFlow

/**
 * Manages wallet operations including creation, signing, and transactions.
 */
class WalletManager(
    private val client: ApiClient,
    private val biometric: BiometricGate
) {
    
    private val _walletsState = MutableStateFlow<List<EreborWallet>>(emptyList())
    
    /**
     * Current wallets as a flow.
     */
    val walletsState: StateFlow<List<EreborWallet>> = _walletsState.asStateFlow()
    
    private val _loading = MutableStateFlow(false)
    
    /**
     * Loading state for wallet operations.
     */
    val loading: StateFlow<Boolean> = _loading.asStateFlow()
    
    /**
     * Create a new wallet.
     * 
     * @param chainId Optional chain ID to create the wallet for. If null, creates for the default chain.
     * @return The newly created wallet
     */
    suspend fun createWallet(chainId: Long? = null): EreborWallet {
        _loading.value = true
        
        try {
            // Require biometric authentication for wallet creation
            if (biometric.isAvailable) {
                val authenticated = biometric.authenticate(
                    reason = "Authenticate to create a new wallet",
                    title = "Create Wallet",
                    subtitle = "Biometric authentication required"
                )
                if (!authenticated) {
                    throw BiometricException("Biometric authentication required for wallet creation", "BIOMETRIC_REQUIRED")
                }
            }
            
            val wallet = client.createWallet(chainId)
            
            // Refresh the wallets list
            refreshWallets()
            
            return wallet
        } catch (e: Exception) {
            throw WalletException("Failed to create wallet: ${e.message}", "WALLET_CREATION_FAILED", e)
        } finally {
            _loading.value = false
        }
    }
    
    /**
     * Get all wallets for the current user.
     * 
     * @return List of user's wallets
     */
    suspend fun listWallets(): List<EreborWallet> {
        _loading.value = true
        
        try {
            val wallets = client.listWallets()
            _walletsState.value = wallets
            return wallets
        } catch (e: Exception) {
            throw WalletException("Failed to list wallets: ${e.message}", "WALLET_LIST_FAILED", e)
        } finally {
            _loading.value = false
        }
    }
    
    /**
     * Sign a message with a specific wallet.
     * 
     * @param walletId The wallet ID to sign with
     * @param message The message to sign
     * @return The signature as a hex string
     */
    suspend fun signMessage(walletId: String, message: String): String {
        _loading.value = true
        
        try {
            // Require biometric authentication for signing
            if (biometric.isAvailable) {
                val authenticated = biometric.authenticate(
                    reason = "Authenticate to sign message",
                    title = "Sign Message",
                    subtitle = "Confirm signing of message"
                )
                if (!authenticated) {
                    throw BiometricException("Biometric authentication required for signing", "BIOMETRIC_REQUIRED")
                }
            }
            
            return client.signMessage(walletId, message)
        } catch (e: Exception) {
            throw WalletException("Failed to sign message: ${e.message}", "MESSAGE_SIGNING_FAILED", e)
        } finally {
            _loading.value = false
        }
    }
    
    /**
     * Sign a transaction with a specific wallet.
     * 
     * @param walletId The wallet ID to sign with
     * @param tx The transaction request to sign
     * @return The signed transaction ready for broadcast
     */
    suspend fun signTransaction(walletId: String, tx: TransactionRequest): SignedTransaction {
        _loading.value = true
        
        try {
            // Require biometric authentication for transaction signing
            if (biometric.isAvailable) {
                val authenticated = biometric.authenticate(
                    reason = "Authenticate to sign transaction",
                    title = "Sign Transaction",
                    subtitle = "Confirm transaction to ${tx.to}"
                )
                if (!authenticated) {
                    throw BiometricException("Biometric authentication required for transaction signing", "BIOMETRIC_REQUIRED")
                }
            }
            
            val signedTxData = client.signTransaction(walletId, tx)
            
            // Parse the signed transaction data to create a SignedTransaction object
            // This is a simplified implementation - in practice, you'd parse the actual transaction data
            return SignedTransaction(
                raw = signedTxData,
                hash = generateTransactionHash(signedTxData)
            )
        } catch (e: Exception) {
            throw WalletException("Failed to sign transaction: ${e.message}", "TRANSACTION_SIGNING_FAILED", e)
        } finally {
            _loading.value = false
        }
    }
    
    /**
     * Send a transaction (sign and broadcast).
     * 
     * @param walletId The wallet ID to send from
     * @param tx The transaction request to send
     * @return The transaction hash
     */
    suspend fun sendTransaction(walletId: String, tx: TransactionRequest): String {
        _loading.value = true
        
        try {
            // Require biometric authentication for sending transactions
            if (biometric.isAvailable) {
                val authenticated = biometric.authenticate(
                    reason = "Authenticate to send transaction",
                    title = "Send Transaction",
                    subtitle = "Confirm sending ${formatValue(tx.value)} to ${tx.to}"
                )
                if (!authenticated) {
                    throw BiometricException("Biometric authentication required for sending transactions", "BIOMETRIC_REQUIRED")
                }
            }
            
            return client.sendTransaction(walletId, tx)
        } catch (e: Exception) {
            throw WalletException("Failed to send transaction: ${e.message}", "TRANSACTION_SEND_FAILED", e)
        } finally {
            _loading.value = false
        }
    }
    
    /**
     * Get a specific wallet by ID.
     * 
     * @param walletId The wallet ID to find
     * @return The wallet or null if not found
     */
    fun getWallet(walletId: String): EreborWallet? {
        return _walletsState.value.find { it.id == walletId }
    }
    
    /**
     * Get wallets for a specific chain.
     * 
     * @param chainId The chain ID to filter by
     * @return List of wallets for the specified chain
     */
    fun getWalletsForChain(chainId: Long): List<EreborWallet> {
        return _walletsState.value.filter { it.chainId == chainId }
    }
    
    /**
     * Get the primary wallet (first wallet or specified default).
     * 
     * @return The primary wallet or null if no wallets exist
     */
    fun getPrimaryWallet(): EreborWallet? {
        return _walletsState.value.firstOrNull()
    }
    
    /**
     * Refresh the wallets list from the API.
     */
    suspend fun refreshWallets() {
        listWallets()
    }
    
    /**
     * Initialize the wallet manager by loading wallets.
     * This should be called after user authentication.
     */
    suspend fun initialize() {
        try {
            refreshWallets()
        } catch (e: Exception) {
            // Don't throw on initialization failure - just log it
            // The UI can handle empty wallet state
        }
    }
    
    private fun formatValue(value: String?): String {
        if (value.isNullOrBlank()) return "0"
        
        // Simple formatting - in practice you'd want proper decimal handling
        return try {
            val wei = value.toBigInteger()
            val eth = wei.toBigDecimal().divide(1000000000000000000.toBigDecimal())
            "${eth.stripTrailingZeros().toPlainString()} ETH"
        } catch (e: Exception) {
            value
        }
    }
    
    private fun generateTransactionHash(signedTxData: String): String {
        // This is a placeholder - in practice you'd extract the hash from the signed transaction
        // or compute it from the transaction data
        return "0x" + signedTxData.take(64)
    }
}