import { useState, useCallback } from 'react';
import { useEreborContext } from '../EreborProvider';
import { useBiometrics } from './useBiometrics';
import { UseSignMessageReturn, WalletError, BiometricError } from '../types';

export function useSignMessage(): UseSignMessageReturn {
  const { client, authenticated } = useEreborContext();
  const { available: biometricsAvailable, authenticate: biometricAuth } = useBiometrics();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const signMessage = useCallback(async (
    message: string, 
    walletId?: string,
    requireBiometric: boolean = true
  ): Promise<string> => {
    if (!authenticated) {
      throw new WalletError('Authentication required to sign message', 'AUTH_REQUIRED');
    }

    try {
      setLoading(true);
      setError(null);

      // Biometric authentication if available and required
      if (requireBiometric && biometricsAvailable) {
        try {
          await biometricAuth({
            promptMessage: 'Authenticate to sign message',
            cancelButtonTitle: 'Cancel Signing'
          });
        } catch (biometricError) {
          if (biometricError instanceof BiometricError && biometricError.code === 'USER_CANCELLED') {
            throw new WalletError('Signing cancelled by user', 'USER_CANCELLED');
          }
          throw new WalletError('Biometric authentication failed', 'BIOMETRIC_FAILED');
        }
      }

      // If no wallet ID provided, we need to get the active wallet
      if (!walletId) {
        throw new WalletError('Wallet ID is required for signing', 'MISSING_WALLET_ID');
      }

      const signature = await client.signMessage(walletId, message);
      
      return signature;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to sign message';
      setError(errorMessage);
      console.error('Message signing failed:', err);
      
      if (err instanceof WalletError) {
        throw err;
      }
      
      throw new WalletError(errorMessage, 'SIGN_MESSAGE_FAILED');
    } finally {
      setLoading(false);
    }
  }, [authenticated, client, biometricsAvailable, biometricAuth]);

  // Convenience method for signing with active wallet
  const signMessageWithActiveWallet = useCallback(async (
    message: string,
    requireBiometric: boolean = true
  ): Promise<string> => {
    // This would typically get the active wallet from useWallets hook
    // For now, we'll require explicit wallet ID
    throw new WalletError('Please specify a wallet ID for signing', 'MISSING_WALLET_ID');
  }, []);

  // Method to sign typed data (EIP-712)
  const signTypedData = useCallback(async (
    domain: any,
    types: any,
    value: any,
    walletId?: string,
    requireBiometric: boolean = true
  ): Promise<string> => {
    if (!authenticated) {
      throw new WalletError('Authentication required to sign typed data', 'AUTH_REQUIRED');
    }

    try {
      setLoading(true);
      setError(null);

      // Biometric authentication if available and required
      if (requireBiometric && biometricsAvailable) {
        try {
          await biometricAuth({
            promptMessage: 'Authenticate to sign typed data',
            cancelButtonTitle: 'Cancel Signing'
          });
        } catch (biometricError) {
          if (biometricError instanceof BiometricError && biometricError.code === 'USER_CANCELLED') {
            throw new WalletError('Signing cancelled by user', 'USER_CANCELLED');
          }
          throw new WalletError('Biometric authentication failed', 'BIOMETRIC_FAILED');
        }
      }

      if (!walletId) {
        throw new WalletError('Wallet ID is required for signing', 'MISSING_WALLET_ID');
      }

      // For typed data, we need to construct the message according to EIP-712
      const typedDataMessage = JSON.stringify({
        domain,
        types,
        value
      });

      const signature = await client.signMessage(walletId, typedDataMessage);
      
      return signature;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to sign typed data';
      setError(errorMessage);
      console.error('Typed data signing failed:', err);
      
      if (err instanceof WalletError) {
        throw err;
      }
      
      throw new WalletError(errorMessage, 'SIGN_TYPED_DATA_FAILED');
    } finally {
      setLoading(false);
    }
  }, [authenticated, client, biometricsAvailable, biometricAuth]);

  // Clear error state
  const clearError = useCallback(() => {
    setError(null);
  }, []);

  return {
    signMessage,
    signMessageWithActiveWallet,
    signTypedData,
    loading,
    error,
    clearError
  };
}