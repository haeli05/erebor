// Re-export all types from React SDK
export * from './types-base';

// Mobile-specific types
export type BiometricType = 'faceId' | 'touchId' | 'fingerprint' | 'none';

export interface SecureStorageConfig {
  useSecureStore: boolean;
  biometricProtection: boolean;
  fallbackToAsyncStorage?: boolean;
  keyPrefix?: string;
}

export interface DeepLinkConfig {
  scheme: string;
  host?: string;
  pathPrefix?: string;
}

export interface MobileEreborConfig {
  apiUrl: string;
  appId: string;
  loginMethods: LoginMethod[];
  chains?: Chain[];
  appearance?: AppearanceConfig;
  tokenPrefix?: string;
  // Mobile-specific options
  secureStorage?: SecureStorageConfig;
  deepLink?: DeepLinkConfig;
  biometricAuth?: boolean;
  networkTimeout?: number;
}

export interface BiometricAuthOptions {
  promptMessage?: string;
  fallbackPrompt?: string;
  disableDeviceFallback?: boolean;
  cancelButtonTitle?: string;
}

export interface UseBiometricsReturn {
  available: boolean;
  biometricType: BiometricType;
  authenticate: (options?: BiometricAuthOptions) => Promise<boolean>;
  isAuthenticated: boolean;
}

export interface UseDeepLinkReturn {
  handleDeepLink: (url: string) => Promise<boolean>;
  registerDeepLinkListener: (callback: (url: string) => void) => () => void;
}

export interface MobileLoginParams extends LoginParams {
  biometricAuth?: boolean;
  autoPrompt?: boolean;
}

export interface DeviceKeyShare {
  id: string;
  encryptedShare: string;
  derivationPath: string;
  createdAt: string;
  lastUsed?: string;
}

export interface KeyBackupOptions {
  method: 'qr' | 'cloud' | 'manual';
  encryption?: boolean;
  biometricGated?: boolean;
}

export interface TransactionConfirmationOptions {
  biometricRequired?: boolean;
  showDetails?: boolean;
  confirmationMessage?: string;
}

// Mobile-specific component props
export interface LoginSheetProps {
  isVisible: boolean;
  onClose: () => void;
  appearance?: AppearanceConfig;
  methods?: LoginMethod[];
  biometricAuth?: boolean;
  autoFocusEmail?: boolean;
}

export interface WalletCardProps {
  wallet: EreborWallet;
  onPress?: (wallet: EreborWallet) => void;
  showBalance?: boolean;
  appearance?: AppearanceConfig;
  style?: any;
}

export interface TransactionSheetProps {
  isVisible: boolean;
  transaction: TransactionRequest;
  onConfirm: () => void;
  onCancel: () => void;
  biometricRequired?: boolean;
  appearance?: AppearanceConfig;
}

// Network and connectivity
export interface NetworkInfo {
  isConnected: boolean;
  connectionType: 'wifi' | 'cellular' | 'ethernet' | 'bluetooth' | 'wimax' | 'vpn' | 'other' | 'unknown' | 'none';
  isInternetReachable?: boolean;
}

export interface SSLPinningConfig {
  enabled: boolean;
  certificates?: string[];
  domains?: string[];
}

// OAuth mobile-specific
export interface MobileOAuthOptions {
  useSystemBrowser?: boolean;
  showInRecents?: boolean;
  promptText?: string;
  additionalScopes?: string[];
}

// Apple Sign-In specific
export interface AppleAuthOptions {
  requestedScopes?: ('email' | 'fullName')[];
  nonce?: string;
  state?: string;
}

export interface AppleAuthResult {
  identityToken: string;
  authorizationCode: string;
  email?: string;
  fullName?: {
    givenName?: string;
    familyName?: string;
  };
  user: string;
}

// Error types specific to mobile
export class BiometricError extends Error {
  code: string;
  
  constructor(message: string, code: string = 'BIOMETRIC_ERROR') {
    super(message);
    this.code = code;
    this.name = 'BiometricError';
  }
}

export class SecureStorageError extends Error {
  code: string;
  
  constructor(message: string, code: string = 'SECURE_STORAGE_ERROR') {
    super(message);
    this.code = code;
    this.name = 'SecureStorageError';
  }
}

export class DeepLinkError extends Error {
  code: string;
  
  constructor(message: string, code: string = 'DEEP_LINK_ERROR') {
    super(message);
    this.code = code;
    this.name = 'DeepLinkError';
  }
}

// Base types from React SDK
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

export interface UseEreborReturn {
  user: EreborUser | null;
  ready: boolean;
  authenticated: boolean;
  loading: boolean;
  login: (method: LoginMethod, params?: MobileLoginParams) => Promise<void>;
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
  sendTransaction: (tx: TransactionRequest, walletId?: string, options?: TransactionConfirmationOptions) => Promise<string>;
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

export interface LoginParams {
  email?: string;
  code?: string;
  redirectUri?: string;
  message?: string;
  signature?: string;
  walletAddress?: string;
  phoneNumber?: string;
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