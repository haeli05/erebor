package io.erebor.sdk.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material.icons.Icons
import androidx.compose.material.icons.filled.Warning
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import io.erebor.sdk.models.EreborWallet
import io.erebor.sdk.models.TransactionRequest
import kotlinx.coroutines.launch
import java.math.BigDecimal
import java.math.BigInteger

/**
 * Configuration for transaction confirmation sheet.
 */
data class TransactionConfirmConfig(
    val title: String = "Confirm Transaction",
    val requireBiometric: Boolean = true,
    val showGasEstimate: Boolean = true
)

/**
 * Transaction confirmation sheet with biometric authentication.
 * 
 * @param transaction The transaction to confirm
 * @param wallet The wallet to send from
 * @param onConfirm Callback when transaction is confirmed
 * @param onDismiss Callback when sheet is dismissed
 * @param config Configuration for appearance and behavior
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun TransactionConfirmSheet(
    transaction: TransactionRequest,
    wallet: EreborWallet,
    onConfirm: suspend (TransactionRequest, EreborWallet) -> Unit,
    onDismiss: () -> Unit,
    config: TransactionConfirmConfig = TransactionConfirmConfig()
) {
    val coroutineScope = rememberCoroutineScope()
    var loading by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    
    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false)
    ) {
        Surface(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            shape = RoundedCornerShape(16.dp),
            color = MaterialTheme.colorScheme.surface
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(24.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                // Header
                Text(
                    text = config.title,
                    style = MaterialTheme.typography.headlineSmall,
                    fontWeight = FontWeight.Bold
                )
                
                // Error message
                if (error != null) {
                    Card(
                        colors = CardDefaults.cardColors(
                            containerColor = MaterialTheme.colorScheme.errorContainer
                        )
                    ) {
                        Row(
                            modifier = Modifier.padding(12.dp),
                            verticalAlignment = Alignment.CenterVertically,
                            horizontalArrangement = Arrangement.spacedBy(8.dp)
                        ) {
                            Icon(
                                imageVector = Icons.Default.Warning,
                                contentDescription = null,
                                tint = MaterialTheme.colorScheme.onErrorContainer
                            )
                            Text(
                                text = error!!,
                                color = MaterialTheme.colorScheme.onErrorContainer,
                                style = MaterialTheme.typography.bodySmall
                            )
                        }
                    }
                }
                
                // Transaction details
                Card(
                    modifier = Modifier.fillMaxWidth(),
                    colors = CardDefaults.cardColors(
                        containerColor = MaterialTheme.colorScheme.surfaceVariant
                    )
                ) {
                    Column(
                        modifier = Modifier.padding(16.dp),
                        verticalArrangement = Arrangement.spacedBy(12.dp)
                    ) {
                        TransactionDetailRow(
                            label = "From",
                            value = formatAddress(wallet.address),
                            isAddress = true
                        )
                        
                        TransactionDetailRow(
                            label = "To",
                            value = formatAddress(transaction.to),
                            isAddress = true
                        )
                        
                        if (transaction.value != null && transaction.value != "0") {
                            TransactionDetailRow(
                                label = "Amount",
                                value = formatValue(transaction.value, getChainSymbol(wallet.chainId)),
                                highlight = true
                            )
                        }
                        
                        TransactionDetailRow(
                            label = "Chain",
                            value = getChainName(wallet.chainId)
                        )
                        
                        if (config.showGasEstimate) {
                            TransactionDetailRow(
                                label = "Network Fee",
                                value = "~${formatGasFee(transaction)}"
                            )
                        }
                        
                        if (transaction.data != null && transaction.data != "0x") {
                            TransactionDetailRow(
                                label = "Data",
                                value = "${transaction.data.take(20)}...",
                                isData = true
                            )
                        }
                    }
                }
                
                // Security notice
                if (config.requireBiometric) {
                    Card(
                        colors = CardDefaults.cardColors(
                            containerColor = MaterialTheme.colorScheme.primaryContainer
                        )
                    ) {
                        Text(
                            text = "This transaction will require biometric authentication to complete.",
                            modifier = Modifier.padding(12.dp),
                            color = MaterialTheme.colorScheme.onPrimaryContainer,
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                }
                
                // Action buttons
                Row(
                    modifier = Modifier.fillMaxWidth(),
                    horizontalArrangement = Arrangement.spacedBy(12.dp)
                ) {
                    OutlinedButton(
                        onClick = onDismiss,
                        modifier = Modifier.weight(1f),
                        enabled = !loading
                    ) {
                        Text("Cancel")
                    }
                    
                    Button(
                        onClick = {
                            coroutineScope.launch {
                                try {
                                    loading = true
                                    error = null
                                    onConfirm(transaction, wallet)
                                } catch (e: Exception) {
                                    error = e.message ?: "Transaction failed"
                                } finally {
                                    loading = false
                                }
                            }
                        },
                        modifier = Modifier.weight(1f),
                        enabled = !loading
                    ) {
                        if (loading) {
                            CircularProgressIndicator(
                                modifier = Modifier.size(20.dp),
                                strokeWidth = 2.dp
                            )
                        } else {
                            Text("Confirm")
                        }
                    }
                }
            }
        }
    }
}

@Composable
private fun TransactionDetailRow(
    label: String,
    value: String,
    isAddress: Boolean = false,
    isData: Boolean = false,
    highlight: Boolean = false
) {
    Row(
        modifier = Modifier.fillMaxWidth(),
        horizontalArrangement = Arrangement.SpaceBetween,
        verticalAlignment = Alignment.Top
    ) {
        Text(
            text = label,
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant,
            modifier = Modifier.weight(0.3f)
        )
        
        Text(
            text = value,
            style = MaterialTheme.typography.bodyMedium,
            fontFamily = if (isAddress || isData) FontFamily.Monospace else FontFamily.Default,
            fontWeight = if (highlight) FontWeight.Bold else FontWeight.Normal,
            color = if (highlight) {
                MaterialTheme.colorScheme.primary
            } else {
                MaterialTheme.colorScheme.onSurface
            },
            modifier = Modifier.weight(0.7f)
        )
    }
}

private fun formatAddress(address: String): String {
    if (address.length < 10) return address
    return "${address.take(6)}...${address.takeLast(4)}"
}

private fun formatValue(value: String, symbol: String): String {
    return try {
        val wei = BigInteger(value)
        val eth = wei.toBigDecimal().divide(BigDecimal("1000000000000000000"))
        "${eth.stripTrailingZeros().toPlainString()} $symbol"
    } catch (e: Exception) {
        "$value $symbol"
    }
}

private fun formatGasFee(transaction: TransactionRequest): String {
    // Simplified gas fee calculation - in practice you'd want more sophisticated estimation
    val gasLimit = transaction.gasLimit?.toLongOrNull() ?: 21000L
    val gasPrice = transaction.gasPrice?.toLongOrNull() 
        ?: transaction.maxFeePerGas?.toLongOrNull() 
        ?: 20_000_000_000L // 20 gwei default
    
    val fee = BigInteger.valueOf(gasLimit * gasPrice)
    val ethFee = fee.toBigDecimal().divide(BigDecimal("1000000000000000000"))
    
    return "${ethFee.stripTrailingZeros().toPlainString()} ETH"
}

private fun getChainName(chainId: Long): String {
    return when (chainId) {
        1L -> "Ethereum Mainnet"
        137L -> "Polygon"
        56L -> "Binance Smart Chain"
        43114L -> "Avalanche"
        250L -> "Fantom"
        42161L -> "Arbitrum One"
        10L -> "Optimism"
        else -> "Chain $chainId"
    }
}

private fun getChainSymbol(chainId: Long): String {
    return when (chainId) {
        1L -> "ETH"
        137L -> "MATIC"
        56L -> "BNB"
        43114L -> "AVAX"
        250L -> "FTM"
        42161L -> "ETH"
        10L -> "ETH"
        else -> "ETH"
    }
}