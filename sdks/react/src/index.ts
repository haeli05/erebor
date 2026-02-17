// Provider
export { EreborProvider } from './EreborProvider';

// Hooks
export { useErebor } from './hooks/useErebor';
export { useWallets } from './hooks/useWallets';
export { useSignMessage } from './hooks/useSignMessage';
export { useSendTransaction } from './hooks/useSendTransaction';
export { useAuth } from './hooks/useAuth';

// Privy compatibility
export { usePrivy } from './hooks/usePrivy';

// Components
export { LoginModal } from './components/LoginModal';
export { WalletButton } from './components/WalletButton';
export { TransactionStatus } from './components/TransactionStatus';

// Iframe bridge
export { IframeController } from './iframe/IframeController';

// Types
export type {
  // Configuration
  EreborConfig,
  AppearanceConfig,
  Chain,
  
  // Auth types
  LoginMethod,
  LoginParams,
  AuthState,
  
  // User types
  EreborUser,
  EreborWallet,
  LinkedAccount,
  
  // Transaction types
  TransactionRequest,
  SignMessageRequest,
  TransactionReceipt,
  
  // Hook return types
  UseEreborReturn,
  UseWalletsReturn,
  UseSignMessageReturn,
  UseSendTransactionReturn,
  UseAuthReturn,
  
  // Component props
  LoginModalProps,
  WalletButtonProps,
  TransactionStatusProps,
  
  // API types
  ApiResponse,
  AuthTokens,
  
  // Iframe types
  IframeMessage,
  SignRequest,
  DeriveRequest,
  IframeError,
  IframeBridgeConfig
} from './types';

// Re-export iframe protocol types
export type {
  IframeMessageType,
  SignResponse,
  DeriveResponse,
  PendingRequest
} from './iframe/protocol';

export {
  IframeErrorCodes,
  DEFAULT_IFRAME_CONFIG,
  generateNonce,
  isValidIframeMessage,
  createIframeError,
  createIframeMessage
} from './iframe/protocol';

// Error classes
export {
  EreborError,
  AuthError,
  WalletError,
  NetworkError
} from './types';

// API client for advanced usage
export { EreborApiClient } from './api/client';