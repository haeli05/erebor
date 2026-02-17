import { useCallback } from 'react';
import { useErebor } from './useErebor';
import { useWallets } from './useWallets';
import { useSignMessage } from './useSignMessage';
import { useSendTransaction } from './useSendTransaction';
import { TransactionRequest, LoginMethod, LoginParams } from '../types';

/**
 * Privy compatibility hook - provides a drop-in replacement for @privy-io/react-auth
 * 
 * This hook maps Erebor's API to match Privy's interface, making migration seamless.
 * Most Privy apps should work by just changing the import:
 * 
 * Before: import { usePrivy } from '@privy-io/react-auth'
 * After:  import { usePrivy } from '@erebor/react'
 */
export function usePrivy() {
  const { user, ready, authenticated, loading, login: ereborLogin, logout } = useErebor();
  const { wallets, createWallet: ereborCreateWallet, activeWallet } = useWallets();
  const { signMessage: ereborSignMessage } = useSignMessage();
  const { sendTransaction: ereborSendTransaction } = useSendTransaction();

  // Transform Erebor user to match Privy's user structure
  const privyUser = user ? {
    id: user.id,
    email: user.email ? { address: user.email } : null,
    wallet: activeWallet ? {
      address: activeWallet.address,
      chainId: `eip155:${activeWallet.chainId}`,
      walletClient: 'unknown',
      walletClientType: 'unknown',
      connectorType: 'unknown'
    } : null,
    linkedAccounts: user.linkedAccounts.map(acc => ({
      type: acc.provider,
      subject: acc.providerUserId,
      email: acc.email,
      username: acc.username
    })),
    createdAt: new Date(user.createdAt)
  } : null;

  // Map login methods from Privy to Erebor
  const login = useCallback(async () => {
    // Privy's login() typically opens a modal
    // For simplicity, we'll default to email login
    // In a real implementation, this would open a login modal
    throw new Error('usePrivy.login() requires a login method. Use the LoginModal component or call erebor login directly.');
  }, []);

  // Enhanced login with method specification
  const loginWithEmail = useCallback(async (email: string) => {
    await ereborLogin('email', { email });
  }, [ereborLogin]);

  const loginWithGoogle = useCallback(async () => {
    // This would typically redirect to Google OAuth
    throw new Error('Google login requires OAuth redirect. Use the LoginModal component.');
  }, []);

  const loginWithWallet = useCallback(async () => {
    // This would typically connect to an external wallet for SIWE
    throw new Error('Wallet login requires SIWE flow. Use the LoginModal component.');
  }, []);

  // Create wallet (maps directly)
  const createWallet = useCallback(async (chainId?: number) => {
    const wallet = await ereborCreateWallet(chainId);
    return {
      address: wallet.address,
      chainId: `eip155:${wallet.chainId}`,
      walletClient: 'erebor',
      walletClientType: 'embedded',
      connectorType: 'embedded'
    };
  }, [ereborCreateWallet]);

  // Sign message with active wallet
  const signMessage = useCallback(async (message: string) => {
    if (!activeWallet) {
      throw new Error('No active wallet available');
    }
    return await ereborSignMessage(message);
  }, [ereborSignMessage, activeWallet]);

  // Send transaction with active wallet
  const sendTransaction = useCallback(async (tx: TransactionRequest) => {
    if (!activeWallet) {
      throw new Error('No active wallet available');
    }
    return await ereborSendTransaction(tx);
  }, [ereborSendTransaction, activeWallet]);

  // Privy-style getAccessToken
  const getAccessToken = useCallback(async () => {
    // In Erebor, tokens are managed internally
    // This is mainly for compatibility
    throw new Error('Direct token access not supported. Tokens are managed automatically.');
  }, []);

  return {
    // Core auth state (matches Privy)
    ready,
    authenticated,
    user: privyUser,
    loading,

    // Auth methods
    login,
    logout,
    
    // Convenience login methods
    loginWithEmail,
    loginWithGoogle, 
    loginWithWallet,

    // Wallet methods
    createWallet,
    signMessage,
    sendTransaction,
    
    // Token method (compatibility)
    getAccessToken,

    // Privy-specific properties (stubbed for compatibility)
    connectWallet: loginWithWallet,
    unlinkEmail: async () => { throw new Error('Use useAuth hook for account unlinking'); },
    linkEmail: async () => { throw new Error('Use useAuth hook for account linking'); },
    unlinkWallet: async () => { throw new Error('Wallet unlinking not supported'); },
    linkWallet: loginWithWallet,
    unlinkPhone: async () => { throw new Error('Phone unlinking not supported'); },
    linkPhone: async () => { throw new Error('Phone linking not supported'); },
    unlinkGoogle: async () => { throw new Error('Use useAuth hook for account unlinking'); },
    linkGoogle: async () => { throw new Error('Use useAuth hook for account linking'); },
    unlinkTwitter: async () => { throw new Error('Use useAuth hook for account unlinking'); },
    linkTwitter: async () => { throw new Error('Use useAuth hook for account linking'); },
    unlinkDiscord: async () => { throw new Error('Use useAuth hook for account unlinking'); },
    linkDiscord: async () => { throw new Error('Use useAuth hook for account linking'); },
    unlinkGithub: async () => { throw new Error('Use useAuth hook for account unlinking'); },
    linkGithub: async () => { throw new Error('Use useAuth hook for account linking'); },
    
    // Additional Erebor-specific data
    erebor: {
      wallets,
      activeWallet,
      originalUser: user
    }
  };
}