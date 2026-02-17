import { useMemo, useCallback } from 'react';
import { useErebor } from './useErebor';
import { useWallets } from './useWallets';
import { useSignMessage } from './useSignMessage';
import { useSendTransaction } from './useSendTransaction';
import { useAuth } from './useAuth';
import { EreborUser, EreborWallet, TransactionRequest, LoginMethod, MobileLoginParams } from '../types';

// Privy compatibility interface
export interface PrivyUser {
  id: string;
  email?: {
    address: string;
  };
  wallet?: {
    address: string;
    chainId: string;
    walletClientType: string;
  };
  google?: {
    email: string;
    name: string;
  };
  twitter?: {
    username: string;
  };
  discord?: {
    username: string;
  };
  github?: {
    username: string;
  };
  apple?: {
    email: string;
  };
  createdAt: Date;
}

export interface PrivyWallet {
  address: string;
  chainId: string;
  walletClientType: 'privy';
  connectorType: 'embedded';
}

export interface PrivyConnectedWallet {
  address: string;
  chainId: string;
  getEthersProvider: () => any;
  getEthersSigner: () => any;
  signMessage: (message: string) => Promise<string>;
  sendTransaction: (transaction: any) => Promise<string>;
}

export interface UsePrivyReturn {
  ready: boolean;
  authenticated: boolean;
  user: PrivyUser | null;
  login: (method?: LoginMethod, params?: MobileLoginParams) => Promise<void>;
  logout: () => Promise<void>;
  createWallet: () => Promise<PrivyWallet>;
  exportWallet: () => Promise<void>;
  connectWallet: () => Promise<void>;
  disconnectWallet: (address: string) => Promise<void>;
  linkEmail: (email: string) => Promise<void>;
  unlinkEmail: () => Promise<void>;
  linkWallet: () => Promise<void>;
  unlinkWallet: (address: string) => Promise<void>;
  linkGoogle: () => Promise<void>;
  unlinkGoogle: () => Promise<void>;
  linkTwitter: () => Promise<void>;
  unlinkTwitter: () => Promise<void>;
  linkDiscord: () => Promise<void>;
  unlinkDiscord: () => Promise<void>;
  linkGithub: () => Promise<void>;
  unlinkGithub: () => Promise<void>;
  linkApple: () => Promise<void>;
  unlinkApple: () => Promise<void>;
  signMessage: (message: string, uiOptions?: any) => Promise<string>;
  sendTransaction: (transaction: TransactionRequest, uiOptions?: any) => Promise<string>;
  // Wallet management
  wallets: PrivyWallet[];
  connectedWallet: PrivyConnectedWallet | null;
}

/**
 * Privy compatibility hook for easy migration from @privy-io/react-auth
 * 
 * This hook provides 100% API compatibility with Privy's usePrivy hook,
 * allowing for drop-in replacement when migrating to Erebor.
 */
export function usePrivy(): UsePrivyReturn {
  const { ready, authenticated, user: ereborUser, login: ereborLogin, logout } = useErebor();
  const { wallets: ereborWallets, createWallet: ereborCreateWallet } = useWallets();
  const { signMessage: ereborSignMessage } = useSignMessage();
  const { sendTransaction: ereborSendTransaction } = useSendTransaction();
  const { linkAccount, unlinkAccount, linkedAccounts } = useAuth();

  // Convert Erebor user to Privy-compatible format
  const user = useMemo((): PrivyUser | null => {
    if (!ereborUser) return null;

    const privyUser: PrivyUser = {
      id: ereborUser.id,
      createdAt: new Date(ereborUser.createdAt)
    };

    // Add email if available
    if (ereborUser.email) {
      privyUser.email = {
        address: ereborUser.email
      };
    }

    // Add primary wallet if available
    if (ereborUser.wallets.length > 0) {
      const primaryWallet = ereborUser.wallets[0];
      privyUser.wallet = {
        address: primaryWallet.address,
        chainId: primaryWallet.chainId.toString(),
        walletClientType: 'privy'
      };
    }

    // Add linked social accounts
    linkedAccounts.forEach(account => {
      switch (account.provider) {
        case 'google':
          privyUser.google = {
            email: account.email || '',
            name: account.username || ''
          };
          break;
        case 'twitter':
          privyUser.twitter = {
            username: account.username || ''
          };
          break;
        case 'discord':
          privyUser.discord = {
            username: account.username || ''
          };
          break;
        case 'github':
          privyUser.github = {
            username: account.username || ''
          };
          break;
        case 'apple':
          privyUser.apple = {
            email: account.email || ''
          };
          break;
      }
    });

    return privyUser;
  }, [ereborUser, linkedAccounts]);

  // Convert Erebor wallets to Privy-compatible format
  const wallets = useMemo((): PrivyWallet[] => {
    return ereborWallets.map(wallet => ({
      address: wallet.address,
      chainId: wallet.chainId.toString(),
      walletClientType: 'privy' as const,
      connectorType: 'embedded' as const
    }));
  }, [ereborWallets]);

  // Get connected wallet (primary wallet)
  const connectedWallet = useMemo((): PrivyConnectedWallet | null => {
    if (wallets.length === 0) return null;

    const primaryWallet = wallets[0];
    const ereborWallet = ereborWallets[0];

    return {
      address: primaryWallet.address,
      chainId: primaryWallet.chainId,
      getEthersProvider: () => {
        throw new Error('getEthersProvider not implemented in mobile SDK');
      },
      getEthersSigner: () => {
        throw new Error('getEthersSigner not implemented in mobile SDK');
      },
      signMessage: (message: string) => ereborSignMessage(message, ereborWallet.id),
      sendTransaction: (transaction: any) => ereborSendTransaction(transaction, ereborWallet.id)
    };
  }, [wallets, ereborWallets, ereborSignMessage, ereborSendTransaction]);

  // Privy-compatible login method
  const login = useCallback(async (method?: LoginMethod, params?: MobileLoginParams) => {
    if (method) {
      await ereborLogin(method, params);
    } else {
      // Default to email login if no method specified
      await ereborLogin('email', params);
    }
  }, [ereborLogin]);

  // Privy-compatible wallet creation
  const createWallet = useCallback(async (): Promise<PrivyWallet> => {
    const ereborWallet = await ereborCreateWallet();
    return {
      address: ereborWallet.address,
      chainId: ereborWallet.chainId.toString(),
      walletClientType: 'privy',
      connectorType: 'embedded'
    };
  }, [ereborCreateWallet]);

  // Social linking methods
  const linkEmail = useCallback(async (email: string) => {
    // In Erebor, email linking is part of the login process
    await ereborLogin('email', { email });
  }, [ereborLogin]);

  const unlinkEmail = useCallback(async () => {
    // Email is the primary auth method, cannot be unlinked
    throw new Error('Cannot unlink primary email address');
  }, []);

  const linkGoogle = useCallback(async () => {
    // This would need OAuth flow implementation
    throw new Error('linkGoogle requires OAuth implementation');
  }, []);

  const unlinkGoogle = useCallback(async () => {
    await unlinkAccount('google');
  }, [unlinkAccount]);

  const linkTwitter = useCallback(async () => {
    throw new Error('linkTwitter requires OAuth implementation');
  }, []);

  const unlinkTwitter = useCallback(async () => {
    await unlinkAccount('twitter');
  }, [unlinkAccount]);

  const linkDiscord = useCallback(async () => {
    throw new Error('linkDiscord requires OAuth implementation');
  }, []);

  const unlinkDiscord = useCallback(async () => {
    await unlinkAccount('discord');
  }, [unlinkAccount]);

  const linkGithub = useCallback(async () => {
    throw new Error('linkGithub requires OAuth implementation');
  }, []);

  const unlinkGithub = useCallback(async () => {
    await unlinkAccount('github');
  }, [unlinkAccount]);

  const linkApple = useCallback(async () => {
    await ereborLogin('apple');
  }, [ereborLogin]);

  const unlinkApple = useCallback(async () => {
    await unlinkAccount('apple');
  }, [unlinkAccount]);

  // Wallet connection methods (no-op in embedded wallet context)
  const exportWallet = useCallback(async () => {
    throw new Error('Wallet export not supported in embedded wallet mode');
  }, []);

  const connectWallet = useCallback(async () => {
    // In embedded wallet mode, wallets are always "connected"
    return;
  }, []);

  const disconnectWallet = useCallback(async (address: string) => {
    // In embedded wallet mode, cannot disconnect individual wallets
    throw new Error('Cannot disconnect embedded wallets');
  }, []);

  const linkWallet = useCallback(async () => {
    // Create a new embedded wallet
    await createWallet();
  }, [createWallet]);

  const unlinkWallet = useCallback(async (address: string) => {
    throw new Error('Cannot unlink embedded wallets');
  }, []);

  // Signing and transaction methods
  const signMessage = useCallback(async (message: string, uiOptions?: any): Promise<string> => {
    if (!connectedWallet) {
      throw new Error('No wallet connected');
    }
    return connectedWallet.signMessage(message);
  }, [connectedWallet]);

  const sendTransaction = useCallback(async (transaction: TransactionRequest, uiOptions?: any): Promise<string> => {
    if (!connectedWallet) {
      throw new Error('No wallet connected');
    }
    return connectedWallet.sendTransaction(transaction);
  }, [connectedWallet]);

  return {
    ready,
    authenticated,
    user,
    login,
    logout,
    createWallet,
    exportWallet,
    connectWallet,
    disconnectWallet,
    linkEmail,
    unlinkEmail,
    linkWallet,
    unlinkWallet,
    linkGoogle,
    unlinkGoogle,
    linkTwitter,
    unlinkTwitter,
    linkDiscord,
    unlinkDiscord,
    linkGithub,
    unlinkGithub,
    linkApple,
    unlinkApple,
    signMessage,
    sendTransaction,
    wallets,
    connectedWallet
  };
}