import { useState, useEffect, useCallback } from 'react';
import { useEreborContext } from '../EreborProvider';
import { EreborWallet, UseWalletsReturn, WalletError } from '../types';

export function useWallets(): UseWalletsReturn {
  const { client, authenticated, user } = useEreborContext();
  const [wallets, setWallets] = useState<EreborWallet[]>([]);
  const [activeWallet, setActiveWalletState] = useState<EreborWallet | null>(null);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);

  // Load wallets from user data or fetch from API
  const refreshWallets = useCallback(async () => {
    if (!authenticated) {
      setWallets([]);
      setActiveWalletState(null);
      return;
    }

    try {
      setLoading(true);
      setError(null);
      
      // Use wallets from user context if available, otherwise fetch
      let userWallets: EreborWallet[];
      if (user?.wallets) {
        userWallets = user.wallets;
      } else {
        userWallets = await client.listWallets();
      }
      
      setWallets(userWallets);
      
      // Set active wallet if none is set
      if (!activeWallet && userWallets.length > 0) {
        setActiveWalletState(userWallets[0]);
      }
      
      // Clear active wallet if it's no longer in the list
      if (activeWallet && !userWallets.find(w => w.id === activeWallet.id)) {
        setActiveWalletState(userWallets.length > 0 ? userWallets[0] : null);
      }
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to load wallets';
      setError(errorMessage);
      console.error('Failed to refresh wallets:', err);
    } finally {
      setLoading(false);
    }
  }, [authenticated, user?.wallets, client, activeWallet]);

  // Refresh wallets when auth state changes
  useEffect(() => {
    refreshWallets();
  }, [refreshWallets]);

  const createWallet = useCallback(async (chainId?: number): Promise<EreborWallet> => {
    if (!authenticated) {
      throw new WalletError('Authentication required to create wallet', 'AUTH_REQUIRED');
    }

    try {
      setLoading(true);
      setError(null);
      
      const newWallet = await client.createWallet(chainId);
      
      // Update local state
      setWallets(prev => [...prev, newWallet]);
      
      // Set as active wallet if it's the first one
      if (wallets.length === 0) {
        setActiveWalletState(newWallet);
      }
      
      return newWallet;
    } catch (err) {
      const errorMessage = err instanceof Error ? err.message : 'Failed to create wallet';
      setError(errorMessage);
      console.error('Failed to create wallet:', err);
      throw new WalletError(errorMessage, 'CREATE_FAILED');
    } finally {
      setLoading(false);
    }
  }, [authenticated, client, wallets.length]);

  const setActiveWallet = useCallback((wallet: EreborWallet) => {
    if (!wallets.find(w => w.id === wallet.id)) {
      throw new WalletError('Wallet not found in user wallets', 'WALLET_NOT_FOUND');
    }
    setActiveWalletState(wallet);
  }, [wallets]);

  return {
    wallets,
    activeWallet,
    createWallet,
    setActiveWallet,
    loading,
    error
  };
}