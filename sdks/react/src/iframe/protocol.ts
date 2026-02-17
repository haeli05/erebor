// Message types for iframe communication with the vault

export interface IframeMessage {
  type: IframeMessageType;
  nonce: string;
  payload: any;
  error?: IframeError;
}

export type IframeMessageType = 
  | 'SIGN_REQUEST'
  | 'SIGN_RESPONSE' 
  | 'DERIVE_REQUEST'
  | 'DERIVE_RESPONSE'
  | 'PING'
  | 'PONG'
  | 'ERROR'
  | 'READY';

export interface SignRequest {
  share: string;
  message: string;
  walletId: string;
}

export interface SignResponse {
  signature: string;
  walletId: string;
}

export interface DeriveRequest {
  share: string;
  path: string;
  chainId?: number;
}

export interface DeriveResponse {
  address: string;
  publicKey: string;
  path: string;
  chainId?: number;
}

export interface IframeError {
  code: string;
  message: string;
  details?: any;
}

export interface PendingRequest {
  nonce: string;
  resolve: (value: any) => void;
  reject: (error: Error) => void;
  timeout: NodeJS.Timeout;
  type: IframeMessageType;
}

// Error codes for iframe operations
export const IframeErrorCodes = {
  TIMEOUT: 'TIMEOUT',
  INVALID_SHARE: 'INVALID_SHARE',
  INVALID_MESSAGE: 'INVALID_MESSAGE', 
  INVALID_PATH: 'INVALID_PATH',
  SIGNATURE_FAILED: 'SIGNATURE_FAILED',
  DERIVATION_FAILED: 'DERIVATION_FAILED',
  IFRAME_NOT_READY: 'IFRAME_NOT_READY',
  VAULT_ERROR: 'VAULT_ERROR',
  NETWORK_ERROR: 'NETWORK_ERROR',
  UNAUTHORIZED: 'UNAUTHORIZED'
} as const;

// Configuration for iframe bridge
export interface IframeBridgeConfig {
  vaultUrl: string;
  timeout: number; // milliseconds
  retryAttempts: number;
  retryDelay: number; // milliseconds
  debug?: boolean;
  allowedOrigins?: string[]; // Explicit origin whitelist for postMessage security
}

// Default configuration
export const DEFAULT_IFRAME_CONFIG: IframeBridgeConfig = {
  vaultUrl: 'https://vault.erebor.xyz',
  timeout: 30000, // 30 seconds
  retryAttempts: 3,
  retryDelay: 1000, // 1 second
  debug: false,
  allowedOrigins: ['https://vault.erebor.xyz'] // Default whitelist - configure for your vault
};

// Helper to generate unique nonces using cryptographically secure random
export function generateNonce(): string {
  // Use crypto.getRandomValues() for secure randomness instead of Math.random()
  const array = new Uint32Array(2);
  crypto.getRandomValues(array);
  const randomPart = array[0].toString(36) + array[1].toString(36);
  return randomPart + Date.now().toString(36);
}

// Helper to validate message format
export function isValidIframeMessage(data: any): data is IframeMessage {
  return (
    data &&
    typeof data === 'object' &&
    typeof data.type === 'string' &&
    typeof data.nonce === 'string' &&
    data.payload !== undefined
  );
}

// Helper to create error messages
export function createIframeError(code: string, message: string, details?: any): IframeError {
  return { code, message, details };
}

// Helper to create iframe messages
export function createIframeMessage(
  type: IframeMessageType,
  nonce: string,
  payload: any,
  error?: IframeError
): IframeMessage {
  return { type, nonce, payload, error };
}