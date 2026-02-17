// Main exports
export { EreborProvider, useEreborContext } from './EreborProvider';

// Hooks
export { useErebor } from './hooks/useErebor';
export { useWallets } from './hooks/useWallets';
export { useSignMessage } from './hooks/useSignMessage';
export { useSendTransaction } from './hooks/useSendTransaction';
export { useAuth } from './hooks/useAuth';
export { useBiometrics } from './hooks/useBiometrics';
export { useDeepLink } from './hooks/useDeepLink';
export { usePrivy } from './hooks/usePrivy';

// Components
export { LoginSheet } from './components/LoginSheet';
export { WalletCard } from './components/WalletCard';
export { TransactionSheet } from './components/TransactionSheet';

// API Client
export { MobileEreborApiClient } from './api/client';

// Storage
export { SecureTokenStore } from './storage/SecureTokenStore';

// Auth modules
export { OAuthBrowser } from './auth/OAuthBrowser';
export { AppleAuth } from './auth/AppleAuth';

// Crypto modules
export { DeviceKeyManager } from './crypto/DeviceKeyManager';
export { MobileSigner } from './crypto/MobileSigner';

// Types - export all types
export type {
  // Base types from React SDK
  EreborConfig,
  AppearanceConfig,
  Chain,
  LoginMethod,
  AuthState,
  EreborUser,
  EreborWallet,
  LinkedAccount,
  TransactionRequest,
  SignMessageRequest,
  TransactionReceipt,
  AuthTokens,
  ApiResponse,
  UseEreborReturn,
  UseWalletsReturn,
  UseSignMessageReturn,
  UseSendTransactionReturn,
  UseAuthReturn,
  LoginParams,
  
  // Mobile-specific types
  MobileEreborConfig,
  BiometricType,
  SecureStorageConfig,
  DeepLinkConfig,
  BiometricAuthOptions,
  UseBiometricsReturn,
  UseDeepLinkReturn,
  MobileLoginParams,
  DeviceKeyShare,
  KeyBackupOptions,
  TransactionConfirmationOptions,
  
  // Component props
  LoginSheetProps,
  WalletCardProps,
  TransactionSheetProps,
  
  // Network and mobile-specific
  NetworkInfo,
  SSLPinningConfig,
  MobileOAuthOptions,
  AppleAuthOptions,
  AppleAuthResult,
  
  // Error types
  EreborError,
  AuthError,
  WalletError,
  NetworkError,
  BiometricError,
  SecureStorageError,
  DeepLinkError
} from './types';

// Re-export important constants and utilities
export const SDK_VERSION = '0.1.0';
export const SDK_NAME = '@erebor/react-native';

// Utility functions for mobile-specific operations
export const EreborUtils = {
  truncateAddress: (address: string, startChars: number = 6, endChars: number = 4): string => {
    if (address.length <= startChars + endChars) {
      return address;
    }
    return `${address.slice(0, startChars)}...${address.slice(-endChars)}`;
  },

  formatEthValue: (valueInWei: string): string => {
    try {
      const ethValue = parseFloat(valueInWei) / 1e18;
      return `${ethValue.toFixed(6)} ETH`;
    } catch {
      return valueInWei;
    }
  },

  getChainName: (chainId: number): string => {
    const chainNames: Record<number, string> = {
      1: 'Ethereum',
      10: 'Optimism',
      137: 'Polygon',
      8453: 'Base',
      42161: 'Arbitrum',
      11155111: 'Sepolia'
    };
    return chainNames[chainId] || `Chain ${chainId}`;
  },

  isValidAddress: (address: string): boolean => {
    return /^0x[a-fA-F0-9]{40}$/.test(address);
  },

  isValidTransactionHash: (hash: string): boolean => {
    return /^0x[a-fA-F0-9]{64}$/.test(hash);
  }
};

// Default configurations
export const DefaultConfigs = {
  appearance: {
    theme: 'light' as const,
    primaryColor: '#007AFF',
    borderRadius: '12px'
  },

  secureStorage: {
    useSecureStore: true,
    biometricProtection: false,
    fallbackToAsyncStorage: true,
    keyPrefix: 'erebor'
  },

  deepLink: {
    scheme: 'erebor',
    host: 'auth',
    pathPrefix: ''
  },

  networkTimeout: 30000
};