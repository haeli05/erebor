import React from 'react';
import {
  View,
  Text,
  TouchableOpacity,
  StyleSheet,
  Alert,
  Clipboard,
  Vibration,
  Platform
} from 'react-native';
import { WalletCardProps, AppearanceConfig } from '../types';

export function WalletCard({
  wallet,
  onPress,
  showBalance = true,
  appearance = {},
  style
}: WalletCardProps) {
  const styles = createStyles(appearance);

  const truncateAddress = (address: string, startChars: number = 6, endChars: number = 4): string => {
    if (address.length <= startChars + endChars) {
      return address;
    }
    return `${address.slice(0, startChars)}...${address.slice(-endChars)}`;
  };

  const getChainName = (chainId: number): string => {
    const chainNames: Record<number, string> = {
      1: 'Ethereum',
      10: 'Optimism',
      137: 'Polygon',
      8453: 'Base',
      42161: 'Arbitrum',
      11155111: 'Sepolia'
    };
    return chainNames[chainId] || `Chain ${chainId}`;
  };

  const copyAddress = async () => {
    try {
      if (Platform.OS === 'ios') {
        Clipboard.setString(wallet.address);
      } else {
        await Clipboard.setString(wallet.address);
      }
      
      // Haptic feedback
      if (Platform.OS === 'ios') {
        // For iOS, you'd use Haptics module
        Vibration.vibrate(50);
      } else {
        Vibration.vibrate(50);
      }

      Alert.alert('Copied!', 'Wallet address copied to clipboard');
    } catch (error) {
      console.error('Failed to copy address:', error);
      Alert.alert('Error', 'Failed to copy address');
    }
  };

  const handlePress = () => {
    if (onPress) {
      onPress(wallet);
    }
  };

  const renderChainBadge = () => (
    <View style={styles.chainBadge}>
      <Text style={styles.chainText}>{getChainName(wallet.chainId)}</Text>
    </View>
  );

  const renderBalance = () => {
    if (!showBalance) return null;

    // In a real app, you'd fetch the actual balance
    return (
      <View style={styles.balanceContainer}>
        <Text style={styles.balanceLabel}>Balance</Text>
        <Text style={styles.balanceValue}>— ETH</Text>
      </View>
    );
  };

  const renderWalletType = () => {
    const isImported = wallet.imported;
    return (
      <View style={[styles.typeBadge, isImported && styles.importedBadge]}>
        <Text style={[styles.typeText, isImported && styles.importedText]}>
          {isImported ? 'Imported' : 'Created'}
        </Text>
      </View>
    );
  };

  return (
    <TouchableOpacity
      style={[styles.container, style]}
      onPress={handlePress}
      activeOpacity={0.7}
    >
      <View style={styles.header}>
        <View style={styles.headerLeft}>
          {renderChainBadge()}
          {renderWalletType()}
        </View>
        <Text style={styles.createdDate}>
          {new Date(wallet.createdAt).toLocaleDateString()}
        </Text>
      </View>

      <View style={styles.addressContainer}>
        <Text style={styles.addressLabel}>Address</Text>
        <TouchableOpacity onPress={copyAddress} style={styles.addressRow}>
          <Text style={styles.addressText}>
            {truncateAddress(wallet.address)}
          </Text>
          <Text style={styles.copyIcon}>📋</Text>
        </TouchableOpacity>
      </View>

      {renderBalance()}

      <View style={styles.footer}>
        <Text style={styles.walletId}>ID: {wallet.id.slice(0, 8)}...</Text>
        <View style={styles.chainTypeContainer}>
          <Text style={styles.chainTypeText}>
            {wallet.chainType.toUpperCase()}
          </Text>
        </View>
      </View>
    </TouchableOpacity>
  );
}

function createStyles(appearance: AppearanceConfig) {
  const isDark = appearance.theme === 'dark';
  const primaryColor = appearance.primaryColor || '#007AFF';
  const borderRadius = parseInt(appearance.borderRadius || '12');

  return StyleSheet.create({
    container: {
      backgroundColor: isDark ? '#1C1C1E' : '#FFFFFF',
      borderRadius,
      padding: 16,
      marginVertical: 8,
      marginHorizontal: 16,
      shadowColor: '#000000',
      shadowOffset: {
        width: 0,
        height: 2,
      },
      shadowOpacity: isDark ? 0.3 : 0.1,
      shadowRadius: 3.84,
      elevation: 5,
      borderWidth: 1,
      borderColor: isDark ? '#2C2C2E' : '#E5E5E5',
    },
    header: {
      flexDirection: 'row',
      justifyContent: 'space-between',
      alignItems: 'flex-start',
      marginBottom: 12,
    },
    headerLeft: {
      flexDirection: 'row',
      alignItems: 'center',
      flex: 1,
    },
    chainBadge: {
      backgroundColor: primaryColor,
      paddingHorizontal: 8,
      paddingVertical: 4,
      borderRadius: 6,
      marginRight: 8,
    },
    chainText: {
      color: '#FFFFFF',
      fontSize: 12,
      fontWeight: '600',
    },
    typeBadge: {
      backgroundColor: isDark ? '#2C2C2E' : '#F2F2F7',
      paddingHorizontal: 8,
      paddingVertical: 4,
      borderRadius: 6,
    },
    importedBadge: {
      backgroundColor: '#FF9500',
    },
    typeText: {
      color: isDark ? '#FFFFFF' : '#000000',
      fontSize: 12,
      fontWeight: '500',
    },
    importedText: {
      color: '#FFFFFF',
    },
    createdDate: {
      color: isDark ? '#8E8E93' : '#8E8E93',
      fontSize: 12,
      fontWeight: '500',
    },
    addressContainer: {
      marginBottom: 12,
    },
    addressLabel: {
      color: isDark ? '#8E8E93' : '#8E8E93',
      fontSize: 12,
      fontWeight: '500',
      marginBottom: 4,
    },
    addressRow: {
      flexDirection: 'row',
      alignItems: 'center',
      justifyContent: 'space-between',
      paddingVertical: 8,
      paddingHorizontal: 12,
      backgroundColor: isDark ? '#2C2C2E' : '#F2F2F7',
      borderRadius: 8,
    },
    addressText: {
      color: isDark ? '#FFFFFF' : '#000000',
      fontSize: 16,
      fontWeight: '600',
      fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace',
      flex: 1,
    },
    copyIcon: {
      fontSize: 16,
      marginLeft: 8,
    },
    balanceContainer: {
      marginBottom: 12,
    },
    balanceLabel: {
      color: isDark ? '#8E8E93' : '#8E8E93',
      fontSize: 12,
      fontWeight: '500',
      marginBottom: 4,
    },
    balanceValue: {
      color: isDark ? '#FFFFFF' : '#000000',
      fontSize: 20,
      fontWeight: '700',
    },
    footer: {
      flexDirection: 'row',
      justifyContent: 'space-between',
      alignItems: 'center',
      paddingTop: 12,
      borderTopWidth: 1,
      borderTopColor: isDark ? '#2C2C2E' : '#E5E5E5',
    },
    walletId: {
      color: isDark ? '#8E8E93' : '#8E8E93',
      fontSize: 12,
      fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace',
    },
    chainTypeContainer: {
      paddingHorizontal: 6,
      paddingVertical: 2,
      backgroundColor: isDark ? '#2C2C2E' : '#E5E5E5',
      borderRadius: 4,
    },
    chainTypeText: {
      color: isDark ? '#FFFFFF' : '#000000',
      fontSize: 10,
      fontWeight: '600',
    },
  });
}