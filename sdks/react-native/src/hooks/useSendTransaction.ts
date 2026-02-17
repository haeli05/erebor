import { useState, useCallback } from 'react';
import { useEreborContext } from '../EreborProvider';
import { useBiometrics } from './useBiometrics';
import { 
  TransactionRequest, 
  TransactionConfirmationOptions,
  UseSendTransactionReturn, 
  WalletError, 
  BiometricError 
} from '../types';

export function useSendTransaction(): UseSendTransactionReturn {
  const { client, authenticated } = useEreborContext();
  const { available: biometricsAvailable, authenticate: biometricAuth } = useBiometrics();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [txHash, setTxHash] = useState<string | null>(null);

  const sendTransaction = useCallback(async (
    tx: TransactionRequest,
    walletId?: string,
    options: TransactionConfirmationOptions = {}
  ): Promise<string> => {
    if (!authenticated) {
      throw new WalletError('Authentication required to send transaction', 'AUTH_REQUIRED');
    }

    try {
      setLoading(true);
      setError(null);
      setTxHash(null);

      // Biometric authentication if required
      const requireBiometric = options.biometricRequired ?? biometricsAvailable;
      
      if (requireBiometric && biometricsAvailable) {
        try {
          const confirmationMessage = options.confirmationMessage || 
            `Authenticate to send transaction to ${tx.to}`;
            
          await biometricAuth({
            promptMessage: confirmationMessage,
            cancelButtonTitle: 'Cancel Transaction'
          });
        } catch (biometricError) {
          if (biometricError instanceof BiometricError && biometricError.code === 'USER_CANCELLED') {
            throw new WalletError('Transaction cancelled by user', 'USER_CANCELLED');
          }
          throw new WalletError('Biometric authentication failed', 'BIOMETRIC_FAILED');
        }
      }

      // Validate transaction parameters
      if (!tx.to || typeof tx.to !== 'string') {
        throw new WalletError('Invalid transaction: missing or invalid recipient address', 'INVALID_TO_ADDRESS');
      }

      if (!tx.chainId || typeof tx.chainId !== 'number') {
        throw new WalletError('Invalid transaction: missing or invalid chain ID', 'INVALID_CHAIN_ID');
      }

      if (!walletId) {
        throw new WalletError('Wallet ID is required for sending transaction', 'MISSING_WALLET_ID');
      }

      // Send the transaction
      const transactionHash = await client.sendTransaction(walletId, tx);
      
      setTxHash(transactionHash);
      return transactionHash;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to send transaction';
      setError(errorMessage);
      console.error('Transaction sending failed:', err);
      
      if (err instanceof WalletError) {
        throw err;
      }
      
      throw new WalletError(errorMessage, 'SEND_TRANSACTION_FAILED');
    } finally {
      setLoading(false);
    }
  }, [authenticated, client, biometricsAvailable, biometricAuth]);

  // Method to only sign transaction without sending
  const signTransaction = useCallback(async (
    tx: TransactionRequest,
    walletId?: string,
    options: TransactionConfirmationOptions = {}
  ): Promise<string> => {
    if (!authenticated) {
      throw new WalletError('Authentication required to sign transaction', 'AUTH_REQUIRED');
    }

    try {
      setLoading(true);
      setError(null);

      // Biometric authentication if required
      const requireBiometric = options.biometricRequired ?? biometricsAvailable;
      
      if (requireBiometric && biometricsAvailable) {
        try {
          const confirmationMessage = options.confirmationMessage || 
            `Authenticate to sign transaction`;
            
          await biometricAuth({
            promptMessage: confirmationMessage,
            cancelButtonTitle: 'Cancel Signing'
          });
        } catch (biometricError) {
          if (biometricError instanceof BiometricError && biometricError.code === 'USER_CANCELLED') {
            throw new WalletError('Transaction signing cancelled by user', 'USER_CANCELLED');
          }
          throw new WalletError('Biometric authentication failed', 'BIOMETRIC_FAILED');
        }
      }

      if (!walletId) {
        throw new WalletError('Wallet ID is required for signing transaction', 'MISSING_WALLET_ID');
      }

      const signedTransaction = await client.signTransaction(walletId, tx);
      
      return signedTransaction;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to sign transaction';
      setError(errorMessage);
      console.error('Transaction signing failed:', err);
      
      if (err instanceof WalletError) {
        throw err;
      }
      
      throw new WalletError(errorMessage, 'SIGN_TRANSACTION_FAILED');
    } finally {
      setLoading(false);
    }
  }, [authenticated, client, biometricsAvailable, biometricAuth]);

  // Estimate transaction gas
  const estimateGas = useCallback(async (
    tx: TransactionRequest,
    walletId?: string
  ): Promise<string> => {
    if (!authenticated) {
      throw new WalletError('Authentication required to estimate gas', 'AUTH_REQUIRED');
    }

    try {
      setLoading(true);
      setError(null);

      // This would typically call an API endpoint for gas estimation
      // For now, we'll throw an error indicating it's not implemented
      throw new WalletError('Gas estimation not yet implemented', 'NOT_IMPLEMENTED');
      
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to estimate gas';
      setError(errorMessage);
      console.error('Gas estimation failed:', err);
      
      if (err instanceof WalletError) {
        throw err;
      }
      
      throw new WalletError(errorMessage, 'GAS_ESTIMATION_FAILED');
    } finally {
      setLoading(false);
    }
  }, [authenticated, client]);

  // Send ETH or native token
  const sendETH = useCallback(async (
    to: string,
    amount: string, // in ETH (will be converted to wei)
    chainId: number,
    walletId?: string,
    options: TransactionConfirmationOptions = {}
  ): Promise<string> => {
    // Convert ETH to wei
    const valueInWei = (parseFloat(amount) * 1e18).toString();
    
    const tx: TransactionRequest = {
      to,
      value: valueInWei,
      chainId
    };

    return sendTransaction(tx, walletId, {
      ...options,
      confirmationMessage: options.confirmationMessage || 
        `Authenticate to send ${amount} ETH to ${to}`
    });
  }, [sendTransaction]);

  // Send ERC-20 token
  const sendToken = useCallback(async (
    tokenAddress: string,
    to: string,
    amount: string,
    decimals: number,
    chainId: number,
    walletId?: string,
    options: TransactionConfirmationOptions = {}
  ): Promise<string> => {
    // Construct ERC-20 transfer transaction data
    const transferAmount = (parseFloat(amount) * Math.pow(10, decimals)).toString(16);
    const paddedAmount = transferAmount.padStart(64, '0');
    const paddedTo = to.replace('0x', '').padStart(64, '0');
    
    // ERC-20 transfer method signature: transfer(address,uint256)
    const data = `0xa9059cbb${paddedTo}${paddedAmount}`;
    
    const tx: TransactionRequest = {
      to: tokenAddress,
      data,
      chainId
    };

    return sendTransaction(tx, walletId, {
      ...options,
      confirmationMessage: options.confirmationMessage || 
        `Authenticate to send ${amount} tokens to ${to}`
    });
  }, [sendTransaction]);

  // Clear error state
  const clearError = useCallback(() => {
    setError(null);
  }, []);

  // Reset transaction hash
  const resetTxHash = useCallback(() => {
    setTxHash(null);
  }, []);

  return {
    sendTransaction,
    signTransaction,
    estimateGas,
    sendETH,
    sendToken,
    loading,
    error,
    txHash,
    clearError,
    resetTxHash
  };
}