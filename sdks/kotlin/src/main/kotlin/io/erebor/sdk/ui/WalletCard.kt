package io.erebor.sdk.ui

import androidx.compose.foundation.background
import androidx.compose.foundation.clickable
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.draw.clip
import androidx.compose.ui.graphics.Brush
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.text.font.FontFamily
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.style.TextOverflow
import androidx.compose.ui.unit.dp
import io.erebor.sdk.models.ChainType
import io.erebor.sdk.models.EreborWallet

/**
 * Configuration for wallet card appearance.
 */
data class WalletCardConfig(
    val showChainInfo: Boolean = true,
    val showFullAddress: Boolean = false,
    val enableClick: Boolean = true,
    val gradientColors: List<Color>? = null
)

/**
 * Displays a wallet as a card component.
 * 
 * @param wallet The wallet to display
 * @param config Configuration for appearance and behavior
 * @param onClick Callback when the card is clicked (optional)
 * @param modifier Modifier for the card
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun WalletCard(
    wallet: EreborWallet,
    config: WalletCardConfig = WalletCardConfig(),
    onClick: ((EreborWallet) -> Unit)? = null,
    modifier: Modifier = Modifier
) {
    val gradientColors = config.gradientColors ?: getDefaultGradientColors(wallet.chainType)
    
    Card(
        modifier = modifier
            .fillMaxWidth()
            .then(
                if (config.enableClick && onClick != null) {
                    Modifier.clickable { onClick(wallet) }
                } else {
                    Modifier
                }
            ),
        elevation = CardDefaults.cardElevation(defaultElevation = 4.dp),
        shape = RoundedCornerShape(16.dp)
    ) {
        Box(
            modifier = Modifier
                .fillMaxWidth()
                .background(
                    brush = Brush.linearGradient(gradientColors),
                    shape = RoundedCornerShape(16.dp)
                )
                .padding(20.dp)
        ) {
            Column(
                verticalArrangement = Arrangement.spacedBy(12.dp)
            ) {
                // Header with chain info
                if (config.showChainInfo) {
                    Row(
                        modifier = Modifier.fillMaxWidth(),
                        horizontalArrangement = Arrangement.SpaceBetween,
                        verticalAlignment = Alignment.CenterVertically
                    ) {
                        ChainBadge(
                            chainType = wallet.chainType,
                            chainId = wallet.chainId
                        )
                        
                        if (wallet.imported == true) {
                            Surface(
                                shape = RoundedCornerShape(8.dp),
                                color = Color.White.copy(alpha = 0.2f)
                            ) {
                                Text(
                                    text = "Imported",
                                    modifier = Modifier.padding(horizontal = 8.dp, vertical = 4.dp),
                                    style = MaterialTheme.typography.labelSmall,
                                    color = Color.White
                                )
                            }
                        }
                    }
                }
                
                // Wallet address
                Column(
                    verticalArrangement = Arrangement.spacedBy(4.dp)
                ) {
                    Text(
                        text = "Wallet Address",
                        style = MaterialTheme.typography.labelMedium,
                        color = Color.White.copy(alpha = 0.8f)
                    )
                    
                    Text(
                        text = if (config.showFullAddress) {
                            wallet.address
                        } else {
                            formatAddress(wallet.address)
                        },
                        style = MaterialTheme.typography.bodyLarge,
                        fontFamily = FontFamily.Monospace,
                        fontWeight = FontWeight.Medium,
                        color = Color.White,
                        maxLines = if (config.showFullAddress) 2 else 1,
                        overflow = TextOverflow.Ellipsis
                    )
                }
                
                // Wallet ID (for debugging/development)
                if (config.showFullAddress) {
                    Column(
                        verticalArrangement = Arrangement.spacedBy(4.dp)
                    ) {
                        Text(
                            text = "Wallet ID",
                            style = MaterialTheme.typography.labelSmall,
                            color = Color.White.copy(alpha = 0.6f)
                        )
                        
                        Text(
                            text = wallet.id,
                            style = MaterialTheme.typography.bodySmall,
                            fontFamily = FontFamily.Monospace,
                            color = Color.White.copy(alpha = 0.8f),
                            maxLines = 1,
                            overflow = TextOverflow.Ellipsis
                        )
                    }
                }
            }
        }
    }
}

/**
 * Badge component showing chain information.
 */
@Composable
private fun ChainBadge(
    chainType: ChainType,
    chainId: Long
) {
    Surface(
        shape = RoundedCornerShape(12.dp),
        color = Color.White.copy(alpha = 0.15f),
        modifier = Modifier
    ) {
        Row(
            modifier = Modifier.padding(horizontal = 12.dp, vertical = 6.dp),
            horizontalArrangement = Arrangement.spacedBy(6.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // Chain type indicator
            Box(
                modifier = Modifier
                    .size(8.dp)
                    .background(
                        color = getChainTypeColor(chainType),
                        shape = RoundedCornerShape(4.dp)
                    )
            )
            
            Text(
                text = getChainDisplayName(chainType, chainId),
                style = MaterialTheme.typography.labelMedium,
                color = Color.White,
                fontWeight = FontWeight.Medium
            )
        }
    }
}

/**
 * Compact wallet display for lists or smaller spaces.
 */
@Composable
fun CompactWalletCard(
    wallet: EreborWallet,
    onClick: ((EreborWallet) -> Unit)? = null,
    modifier: Modifier = Modifier
) {
    Card(
        modifier = modifier
            .fillMaxWidth()
            .then(
                if (onClick != null) {
                    Modifier.clickable { onClick(wallet) }
                } else {
                    Modifier
                }
            ),
        elevation = CardDefaults.cardElevation(defaultElevation = 2.dp)
    ) {
        Row(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            horizontalArrangement = Arrangement.spacedBy(12.dp),
            verticalAlignment = Alignment.CenterVertically
        ) {
            // Chain indicator
            Box(
                modifier = Modifier
                    .size(12.dp)
                    .background(
                        color = getChainTypeColor(wallet.chainType),
                        shape = RoundedCornerShape(6.dp)
                    )
            )
            
            // Address and chain info
            Column(
                modifier = Modifier.weight(1f),
                verticalArrangement = Arrangement.spacedBy(2.dp)
            ) {
                Text(
                    text = formatAddress(wallet.address),
                    style = MaterialTheme.typography.bodyMedium,
                    fontFamily = FontFamily.Monospace,
                    fontWeight = FontWeight.Medium
                )
                
                Text(
                    text = getChainDisplayName(wallet.chainType, wallet.chainId),
                    style = MaterialTheme.typography.bodySmall,
                    color = MaterialTheme.colorScheme.onSurfaceVariant
                )
            }
            
            // Import indicator
            if (wallet.imported == true) {
                Surface(
                    shape = RoundedCornerShape(4.dp),
                    color = MaterialTheme.colorScheme.primaryContainer
                ) {
                    Text(
                        text = "Imported",
                        modifier = Modifier.padding(horizontal = 6.dp, vertical = 2.dp),
                        style = MaterialTheme.typography.labelSmall,
                        color = MaterialTheme.colorScheme.onPrimaryContainer
                    )
                }
            }
        }
    }
}

private fun formatAddress(address: String): String {
    if (address.length < 10) return address
    return "${address.take(6)}...${address.takeLast(4)}"
}

private fun getDefaultGradientColors(chainType: ChainType): List<Color> {
    return when (chainType) {
        ChainType.EVM -> listOf(
            Color(0xFF667eea),
            Color(0xFF764ba2)
        )
        ChainType.SOLANA -> listOf(
            Color(0xFF9945FF),
            Color(0xFF14F195)
        )
    }
}

private fun getChainTypeColor(chainType: ChainType): Color {
    return when (chainType) {
        ChainType.EVM -> Color(0xFF627EEA)
        ChainType.SOLANA -> Color(0xFF9945FF)
    }
}

private fun getChainDisplayName(chainType: ChainType, chainId: Long): String {
    return when (chainType) {
        ChainType.EVM -> when (chainId) {
            1L -> "Ethereum"
            137L -> "Polygon"
            56L -> "BSC"
            43114L -> "Avalanche"
            250L -> "Fantom"
            42161L -> "Arbitrum"
            10L -> "Optimism"
            else -> "Chain $chainId"
        }
        ChainType.SOLANA -> "Solana"
    }
}