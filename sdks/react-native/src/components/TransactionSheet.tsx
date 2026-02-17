import React, { useState, useEffect } from 'react';
import {
  View,
  Text,
  Modal,
  TouchableOpacity,
  StyleSheet,
  SafeAreaView,
  ScrollView,
  ActivityIndicator,
  Alert,
  Platform
} from 'react-native';
import { useBiometrics } from '../hooks/useBiometrics';
import { TransactionSheetProps, AppearanceConfig } from '../types';

export function TransactionSheet({
  isVisible,
  transaction,
  onConfirm,
  onCancel,
  biometricRequired = true,
  appearance = {}
}: TransactionSheetProps) {
  const { available: biometricsAvailable, biometricType, authenticate } = useBiometrics();
  const [isProcessing, setIsProcessing] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [hasAuthenticated, setHasAuthenticated] = useState(false);

  const styles = createStyles(appearance);

  // Reset state when sheet is closed
  useEffect(() => {
    if (!isVisible) {
      setIsProcessing(false);
      setError(null);
      setHasAuthenticated(false);
    }
  }, [isVisible]);

  const formatValue = (value?: string): string => {
    if (!value || value === '0') return '0 ETH';
    
    try {
      // Convert wei to ETH (assuming 18 decimals)
      const ethValue = parseFloat(value) / 1e18;
      return `${ethValue.toFixed(6)} ETH`;
    } catch {
      return value;
    }
  };

  const formatGas = (gasLimit?: string, gasPrice?: string): string => {
    if (!gasLimit) return 'Unknown';
    
    try {
      const limit = parseInt(gasLimit);
      const price = gasPrice ? parseInt(gasPrice) : 20; // 20 gwei default
      const totalGwei = (limit * price) / 1e9;
      const totalEth = totalGwei / 1e9;
      
      return `${limit.toLocaleString()} (≈ ${totalEth.toFixed(6)} ETH)`;
    } catch {
      return gasLimit;
    }
  };

  const truncateAddress = (address: string): string => {
    return `${address.slice(0, 6)}...${address.slice(-4)}`;
  };

  const getChainName = (chainId: number): string => {
    const chainNames: Record<number, string> = {
      1: 'Ethereum Mainnet',
      10: 'Optimism',
      137: 'Polygon',
      8453: 'Base',
      42161: 'Arbitrum One',
      11155111: 'Sepolia Testnet'
    };
    return chainNames[chainId] || `Chain ${chainId}`;
  };

  const handleBiometricAuth = async (): Promise<boolean> => {
    if (!biometricRequired || !biometricsAvailable) {
      return true;
    }

    try {
      const success = await authenticate({
        promptMessage: 'Authenticate to confirm transaction',
        cancelButtonTitle: 'Cancel Transaction'
      });
      
      setHasAuthenticated(success);
      return success;
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Biometric authentication failed');
      return false;
    }
  };

  const handleConfirm = async () => {
    setIsProcessing(true);
    setError(null);

    try {
      // Perform biometric authentication if required
      if (biometricRequired && biometricsAvailable && !hasAuthenticated) {
        const authSuccess = await handleBiometricAuth();
        if (!authSuccess) {
          return;
        }
      }

      // Call the confirm callback
      await onConfirm();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Transaction failed');
    } finally {
      setIsProcessing(false);
    }
  };

  const renderTransactionDetails = () => (
    <View style={styles.detailsContainer}>
      <Text style={styles.sectionTitle}>Transaction Details</Text>
      
      <View style={styles.detailRow}>
        <Text style={styles.detailLabel}>To</Text>
        <TouchableOpacity onPress={() => {
          Alert.alert('Recipient Address', transaction.to);
        }}>
          <Text style={styles.detailValue}>{truncateAddress(transaction.to)}</Text>
        </TouchableOpacity>
      </View>

      <View style={styles.detailRow}>
        <Text style={styles.detailLabel}>Amount</Text>
        <Text style={styles.detailValue}>{formatValue(transaction.value)}</Text>
      </View>

      <View style={styles.detailRow}>
        <Text style={styles.detailLabel}>Network</Text>
        <Text style={styles.detailValue}>{getChainName(transaction.chainId)}</Text>
      </View>

      {transaction.gasLimit && (
        <View style={styles.detailRow}>
          <Text style={styles.detailLabel}>Gas Limit</Text>
          <Text style={styles.detailValue}>{formatGas(transaction.gasLimit, transaction.gasPrice)}</Text>
        </View>
      )}

      {transaction.gasPrice && (
        <View style={styles.detailRow}>
          <Text style={styles.detailLabel}>Gas Price</Text>
          <Text style={styles.detailValue}>{parseInt(transaction.gasPrice) / 1e9} Gwei</Text>
        </View>
      )}

      {transaction.maxFeePerGas && (
        <View style={styles.detailRow}>
          <Text style={styles.detailLabel}>Max Fee</Text>
          <Text style={styles.detailValue}>{parseInt(transaction.maxFeePerGas) / 1e9} Gwei</Text>
        </View>
      )}

      {transaction.nonce !== undefined && (
        <View style={styles.detailRow}>
          <Text style={styles.detailLabel}>Nonce</Text>
          <Text style={styles.detailValue}>{transaction.nonce}</Text>
        </View>
      )}

      {transaction.data && transaction.data !== '0x' && (
        <View style={styles.detailRow}>
          <Text style={styles.detailLabel}>Data</Text>
          <TouchableOpacity onPress={() => {
            Alert.alert('Transaction Data', transaction.data);
          }}>
            <Text style={styles.detailValue}>
              {transaction.data.length > 20 ? `${transaction.data.slice(0, 20)}...` : transaction.data}
            </Text>
          </TouchableOpacity>
        </View>
      )}
    </View>
  );

  const renderSecurityInfo = () => {
    if (!biometricRequired || !biometricsAvailable) return null;

    return (
      <View style={styles.securityContainer}>
        <Text style={styles.securityTitle}>🔒 Security</Text>
        <Text style={styles.securityText}>
          This transaction requires {biometricType === 'faceId' ? 'Face ID' : 
                                      biometricType === 'touchId' ? 'Touch ID' : 
                                      'fingerprint'} authentication
        </Text>
      </View>
    );
  };

  const renderWarnings = () => {
    const warnings = [];

    // Check for high value transaction
    if (transaction.value && parseFloat(transaction.value) > 1e18) { // > 1 ETH
      warnings.push('This is a high-value transaction. Please verify the recipient carefully.');
    }

    // Check for contract interaction
    if (transaction.data && transaction.data !== '0x') {
      warnings.push('This transaction will interact with a smart contract.');
    }

    // Check for unusual gas settings
    if (transaction.gasPrice && parseInt(transaction.gasPrice) > 100e9) { // > 100 gwei
      warnings.push('Gas price is unusually high. This transaction may be expensive.');
    }

    if (warnings.length === 0) return null;

    return (
      <View style={styles.warningContainer}>
        <Text style={styles.warningTitle}>⚠️ Please Review</Text>
        {warnings.map((warning, index) => (
          <Text key={index} style={styles.warningText}>• {warning}</Text>
        ))}
      </View>
    );
  };

  return (
    <Modal
      visible={isVisible}
      animationType="slide"
      presentationStyle="pageSheet"
      onRequestClose={onCancel}
    >
      <SafeAreaView style={styles.safeArea}>
        <View style={styles.container}>
          <View style={styles.header}>
            <TouchableOpacity
              style={styles.cancelButton}
              onPress={onCancel}
              disabled={isProcessing}
            >
              <Text style={styles.cancelButtonText}>Cancel</Text>
            </TouchableOpacity>
            <Text style={styles.headerTitle}>Confirm Transaction</Text>
            <View style={styles.headerSpacer} />
          </View>

          <ScrollView style={styles.content} showsVerticalScrollIndicator={false}>
            {renderTransactionDetails()}
            {renderWarnings()}
            {renderSecurityInfo()}

            {error && (
              <View style={styles.errorContainer}>
                <Text style={styles.errorText}>❌ {error}</Text>
              </View>
            )}
          </ScrollView>

          <View style={styles.footer}>
            <TouchableOpacity
              style={[styles.confirmButton, isProcessing && styles.disabledButton]}
              onPress={handleConfirm}
              disabled={isProcessing}
            >
              {isProcessing ? (
                <View style={styles.loadingContainer}>
                  <ActivityIndicator color="#FFFFFF" size="small" />
                  <Text style={styles.loadingText}>Processing...</Text>
                </View>
              ) : (
                <Text style={styles.confirmButtonText}>
                  {biometricRequired && biometricsAvailable && !hasAuthenticated 
                    ? `Confirm with ${biometricType === 'faceId' ? 'Face ID' : 
                                       biometricType === 'touchId' ? 'Touch ID' : 
                                       'Fingerprint'}`
                    : 'Confirm Transaction'
                  }
                </Text>
              )}
            </TouchableOpacity>
          </View>
        </View>
      </SafeAreaView>
    </Modal>
  );
}

function createStyles(appearance: AppearanceConfig) {
  const isDark = appearance.theme === 'dark';
  const primaryColor = appearance.primaryColor || '#007AFF';
  const borderRadius = parseInt(appearance.borderRadius || '12');

  return StyleSheet.create({
    safeArea: {
      flex: 1,
      backgroundColor: isDark ? '#000000' : '#FFFFFF',
    },
    container: {
      flex: 1,
    },
    header: {
      flexDirection: 'row',
      alignItems: 'center',
      justifyContent: 'space-between',
      paddingHorizontal: 20,
      paddingVertical: 15,
      borderBottomWidth: 1,
      borderBottomColor: isDark ? '#2C2C2E' : '#E5E5E5',
    },
    cancelButton: {
      padding: 5,
    },
    cancelButtonText: {
      fontSize: 16,
      color: isDark ? '#FF453A' : '#FF3B30',
    },
    headerTitle: {
      fontSize: 18,
      fontWeight: '600',
      color: isDark ? '#FFFFFF' : '#000000',
    },
    headerSpacer: {
      width: 60, // Balance the header
    },
    content: {
      flex: 1,
      paddingHorizontal: 20,
    },
    detailsContainer: {
      marginTop: 20,
      marginBottom: 20,
    },
    sectionTitle: {
      fontSize: 18,
      fontWeight: '600',
      marginBottom: 15,
      color: isDark ? '#FFFFFF' : '#000000',
    },
    detailRow: {
      flexDirection: 'row',
      justifyContent: 'space-between',
      alignItems: 'center',
      paddingVertical: 12,
      borderBottomWidth: 1,
      borderBottomColor: isDark ? '#2C2C2E' : '#F2F2F7',
    },
    detailLabel: {
      fontSize: 16,
      color: isDark ? '#8E8E93' : '#8E8E93',
      flex: 1,
    },
    detailValue: {
      fontSize: 16,
      fontWeight: '500',
      color: isDark ? '#FFFFFF' : '#000000',
      textAlign: 'right',
      flex: 1,
      fontFamily: Platform.OS === 'ios' ? 'Menlo' : 'monospace',
    },
    securityContainer: {
      backgroundColor: isDark ? '#1C2E1C' : '#F0F9F0',
      padding: 15,
      borderRadius,
      marginBottom: 20,
      borderLeftWidth: 4,
      borderLeftColor: '#34C759',
    },
    securityTitle: {
      fontSize: 16,
      fontWeight: '600',
      marginBottom: 5,
      color: isDark ? '#30D158' : '#34C759',
    },
    securityText: {
      fontSize: 14,
      color: isDark ? '#CCCCCC' : '#666666',
    },
    warningContainer: {
      backgroundColor: isDark ? '#2E1C1C' : '#FFF5F5',
      padding: 15,
      borderRadius,
      marginBottom: 20,
      borderLeftWidth: 4,
      borderLeftColor: '#FF9500',
    },
    warningTitle: {
      fontSize: 16,
      fontWeight: '600',
      marginBottom: 8,
      color: isDark ? '#FF9F0A' : '#FF9500',
    },
    warningText: {
      fontSize: 14,
      color: isDark ? '#CCCCCC' : '#666666',
      marginBottom: 4,
    },
    errorContainer: {
      backgroundColor: isDark ? '#2E1C1C' : '#FFF5F5',
      padding: 15,
      borderRadius,
      marginBottom: 20,
      borderLeftWidth: 4,
      borderLeftColor: '#FF453A',
    },
    errorText: {
      fontSize: 14,
      color: isDark ? '#FF453A' : '#FF3B30',
    },
    footer: {
      paddingHorizontal: 20,
      paddingVertical: 20,
      borderTopWidth: 1,
      borderTopColor: isDark ? '#2C2C2E' : '#E5E5E5',
    },
    confirmButton: {
      backgroundColor: primaryColor,
      paddingVertical: 16,
      borderRadius,
      alignItems: 'center',
    },
    disabledButton: {
      opacity: 0.6,
    },
    confirmButtonText: {
      fontSize: 18,
      fontWeight: '600',
      color: '#FFFFFF',
    },
    loadingContainer: {
      flexDirection: 'row',
      alignItems: 'center',
    },
    loadingText: {
      fontSize: 18,
      fontWeight: '600',
      color: '#FFFFFF',
      marginLeft: 10,
    },
  });
}