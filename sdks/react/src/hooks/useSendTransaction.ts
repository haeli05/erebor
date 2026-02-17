import { useState, useCallback } from 'react';
import { useEreborContext } from '../EreborProvider';
import { useWallets } from './useWallets';
import { TransactionRequest, UseSendTransactionReturn, WalletError, AuthError } from '../types';

export function useSendTransaction(): UseSendTransactionReturn {
  const { client, authenticated } = useEreborContext();
  const { activeWallet, wallets } = useWallets();
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [txHash, setTxHash] = useState<string | null>(null);

  const sendTransaction = useCallback(async (
    tx: TransactionRequest, 
    walletId?: string
  ): Promise<string> => {
    if (!authenticated) {
      throw new AuthError('Authentication required to send transactions', 'AUTH_REQUIRED');
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

    // Validate transaction
    if (!tx.to || !tx.to.trim()) {
      throw new WalletError('Transaction recipient address is required', 'INVALID_RECIPIENT');
    }

    if (!tx.chainId) {
      throw new WalletError('Chain ID is required', 'MISSING_CHAIN_ID');
    }

    // Check if wallet supports the chain
    if (targetWallet.chainId !== tx.chainId) {
      throw new WalletError(
        `Wallet is on chain ${targetWallet.chainId}, but transaction is for chain ${tx.chainId}`,
        'CHAIN_MISMATCH'
      );
    }

    try {
      setLoading(true);
      setError(null);
      setTxHash(null);
      
      const hash = await client.sendTransaction(targetWallet.id, tx);
      
      if (!hash) {
        throw new WalletError('No transaction hash returned', 'TRANSACTION_FAILED');
      }
      
      setTxHash(hash);
      return hash;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to send transaction';
      setError(errorMessage);
      console.error('Transaction failed:', err);
      
      if (err instanceof AuthError || err instanceof WalletError) {
        throw err;
      }
      
      throw new WalletError(errorMessage, 'SEND_FAILED');
    } finally {
      setLoading(false);
    }
  }, [authenticated, client, activeWallet, wallets]);

  return {
    sendTransaction,
    loading,
    error,
    txHash
  };
}