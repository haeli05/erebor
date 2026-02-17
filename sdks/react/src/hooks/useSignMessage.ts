import { useState, useCallback } from 'react';
import { useEreborContext } from '../EreborProvider';
import { useWallets } from './useWallets';
import { UseSignMessageReturn, WalletError, AuthError } from '../types';

export function useSignMessage(): UseSignMessageReturn {
  const { client, authenticated } = useEreborContext();
  const { activeWallet, wallets } = useWallets();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  const signMessage = useCallback(async (message: string, walletId?: string): Promise<string> => {
    if (!authenticated) {
      throw new AuthError('Authentication required to sign messages', 'AUTH_REQUIRED');
    }

    // Determine which wallet to use
    let targetWallet;
    if (walletId) {
      targetWallet = wallets.find(w => w.id === walletId);
      if (!targetWallet) {
        throw new WalletError('Specified wallet not found', 'WALLET_NOT_FOUND');
      }
    } else {
      targetWallet = activeWallet;
      if (!targetWallet) {
        throw new WalletError('No active wallet available', 'NO_ACTIVE_WALLET');
      }
    }

    if (!message.trim()) {
      throw new WalletError('Message cannot be empty', 'EMPTY_MESSAGE');
    }

    try {
      setLoading(true);
      setError(null);
      
      const signature = await client.signMessage(targetWallet.id, message);
      
      if (!signature) {
        throw new WalletError('No signature returned', 'SIGNATURE_FAILED');
      }
      
      return signature;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to sign message';
      setError(errorMessage);
      console.error('Message signing failed:', err);
      
      if (err instanceof AuthError || err instanceof WalletError) {
        throw err;
      }
      
      throw new WalletError(errorMessage, 'SIGN_FAILED');
    } finally {
      setLoading(false);
    }
  }, [authenticated, client, activeWallet, wallets]);

  return {
    signMessage,
    loading,
    error
  };
}