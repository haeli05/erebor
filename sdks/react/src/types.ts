// Core configuration types
export interface EreborConfig {
  apiUrl: string;
  appId: string;
  loginMethods: LoginMethod[];
  chains?: Chain[];
  appearance?: AppearanceConfig;
  tokenPrefix?: string;
}

export interface AppearanceConfig {
  theme?: 'light' | 'dark';
  logo?: string;
  primaryColor?: string;
  borderRadius?: string;
}

export interface Chain {
  id: number;
  name: string;
  rpcUrl: string;
  nativeCurrency?: {
    name: string;
    symbol: string;
    decimals: number;
  };
  blockExplorer?: string;
}

// Authentication types
export type LoginMethod = 'email' | 'google' | 'siwe' | 'apple' | 'twitter' | 'discord' | 'github' | 'phone';

export interface AuthState {
  ready: boolean;
  authenticated: boolean;
  user: EreborUser | null;
  loading: boolean;
}

export interface EreborUser {
  id: string;
  email?: string;
  wallets: EreborWallet[];
  linkedAccounts: LinkedAccount[];
  createdAt: string;
}

export interface EreborWallet {
  id: string;
  address: string;
  chainId: number;
  chainType: 'evm' | 'solana';
  imported?: boolean;
  createdAt: string;
}

export interface LinkedAccount {
  provider: 'google' | 'twitter' | 'discord' | 'github' | 'apple';
  providerUserId: string;
  email?: string;
  username?: string;
}

// Transaction types
export interface TransactionRequest {
  to: string;
  value?: string;
  data?: string;
  chainId: number;
  gasLimit?: string;
  gasPrice?: string;
  maxFeePerGas?: string;
  maxPriorityFeePerGas?: string;
  nonce?: number;
}

export interface SignMessageRequest {
  message: string;
  walletId?: string;
}

export interface TransactionReceipt {
  hash: string;
  blockNumber: number;
  blockHash: string;
  transactionIndex: number;
  status: 'success' | 'failed';
  gasUsed: string;
}

// API response types
export interface AuthTokens {
  accessToken: string;
  refreshToken: string;
  expiresIn: number;
}

export interface ApiResponse<T = any> {
  success: boolean;
  data?: T;
  error?: string;
  code?: string;
}

// Hook return types
export interface UseEreborReturn {
  user: EreborUser | null;
  ready: boolean;
  authenticated: boolean;
  loading: boolean;
  login: (method: LoginMethod, params?: LoginParams) => Promise<void>;
  logout: () => Promise<void>;
}

export interface UseWalletsReturn {
  wallets: EreborWallet[];
  activeWallet: EreborWallet | null;
  createWallet: (chainId?: number) => Promise<EreborWallet>;
  setActiveWallet: (wallet: EreborWallet) => void;
  loading: boolean;
  error: string | null;
}

export interface UseSignMessageReturn {
  signMessage: (message: string, walletId?: string) => Promise<string>;
  loading: boolean;
  error: string | null;
}

export interface UseSendTransactionReturn {
  sendTransaction: (tx: TransactionRequest, walletId?: string) => Promise<string>;
  loading: boolean;
  error: string | null;
  txHash: string | null;
}

export interface UseAuthReturn {
  linkAccount: (provider: string, token: string) => Promise<LinkedAccount>;
  unlinkAccount: (provider: string) => Promise<void>;
  linkedAccounts: LinkedAccount[];
  loading: boolean;
  error: string | null;
}

// Login parameters
export interface LoginParams {
  email?: string;
  code?: string;
  redirectUri?: string;
  message?: string;
  signature?: string;
  walletAddress?: string;
  phoneNumber?: string;
}

// Component props
export interface LoginModalProps {
  isOpen: boolean;
  onClose: () => void;
  appearance?: AppearanceConfig;
  methods?: LoginMethod[];
}

export interface WalletButtonProps {
  appearance?: AppearanceConfig;
  text?: {
    connect?: string;
    disconnect?: string;
  };
  onClick?: () => void;
}

export interface TransactionStatusProps {
  txHash?: string;
  status: 'pending' | 'confirmed' | 'failed';
  chainId?: number;
  onClose?: () => void;
}

// Iframe bridge types
export interface IframeMessage {
  type: 'SIGN_REQUEST' | 'SIGN_RESPONSE' | 'DERIVE_REQUEST' | 'DERIVE_RESPONSE' | 'ERROR';
  nonce: string;
  payload: any;
}

export interface SignRequest {
  share: string;
  message: string;
}

export interface DeriveRequest {
  share: string;
  path: string;
}

export interface IframeError {
  code: string;
  message: string;
}

// Error types
export class EreborError extends Error {
  code: string;
  
  constructor(message: string, code: string = 'UNKNOWN_ERROR') {
    super(message);
    this.code = code;
    this.name = 'EreborError';
  }
}

export class AuthError extends EreborError {
  constructor(message: string, code: string = 'AUTH_ERROR') {
    super(message, code);
    this.name = 'AuthError';
  }
}

export class WalletError extends EreborError {
  constructor(message: string, code: string = 'WALLET_ERROR') {
    super(message, code);
    this.name = 'WalletError';
  }
}

export class NetworkError extends EreborError {
  constructor(message: string, code: string = 'NETWORK_ERROR') {
    super(message, code);
    this.name = 'NetworkError';
  }
}