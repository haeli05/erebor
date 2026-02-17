import NetInfo from '@react-native-community/netinfo';
import {
  ApiResponse,
  AuthTokens,
  EreborUser,
  EreborWallet,
  LinkedAccount,
  TransactionRequest,
  TransactionReceipt,
  AuthError,
  WalletError,
  NetworkError,
  NetworkInfo,
  SSLPinningConfig
} from '../types';
import { SecureTokenStore } from '../storage/SecureTokenStore';

export interface MobileApiClientOptions {
  apiUrl: string;
  tokenPrefix?: string;
  networkTimeout?: number;
  sslPinning?: SSLPinningConfig;
  secureStorage?: {
    useSecureStore?: boolean;
    biometricProtection?: boolean;
    fallbackToAsyncStorage?: boolean;
  };
}

export class MobileEreborApiClient {
  private apiUrl: string;
  private tokenStore: SecureTokenStore;
  private networkTimeout: number;
  private sslPinning: SSLPinningConfig;
  private networkInfo: NetworkInfo = {
    isConnected: false,
    connectionType: 'none'
  };

  constructor(options: MobileApiClientOptions) {
    this.apiUrl = options.apiUrl.replace(/\/$/, '');
    this.networkTimeout = options.networkTimeout || 30000;
    this.sslPinning = options.sslPinning || { enabled: false };
    
    // Initialize secure token store with mobile-specific options
    this.tokenStore = new SecureTokenStore({
      keyPrefix: options.tokenPrefix || 'erebor',
      useSecureStore: options.secureStorage?.useSecureStore ?? true,
      biometricProtection: options.secureStorage?.biometricProtection ?? false,
      fallbackToAsyncStorage: options.secureStorage?.fallbackToAsyncStorage ?? true
    });

    this.initializeNetworkMonitoring();
  }

  private initializeNetworkMonitoring(): void {
    NetInfo.fetch().then(state => {
      this.networkInfo = {
        isConnected: state.isConnected ?? false,
        connectionType: this.mapConnectionType(state.type),
        isInternetReachable: state.isInternetReachable ?? undefined
      };
    });

    // Subscribe to network changes
    NetInfo.addEventListener(state => {
      const previouslyConnected = this.networkInfo.isConnected;
      
      this.networkInfo = {
        isConnected: state.isConnected ?? false,
        connectionType: this.mapConnectionType(state.type),
        isInternetReachable: state.isInternetReachable ?? undefined
      };

      // If we've reconnected after being offline, refresh token if needed
      if (!previouslyConnected && this.networkInfo.isConnected) {
        this.handleNetworkReconnection();
      }
    });
  }

  private mapConnectionType(type: string): NetworkInfo['connectionType'] {
    const typeMap: Record<string, NetworkInfo['connectionType']> = {
      wifi: 'wifi',
      cellular: 'cellular',
      ethernet: 'ethernet',
      bluetooth: 'bluetooth',
      wimax: 'wimax',
      vpn: 'vpn',
      other: 'other',
      unknown: 'unknown',
      none: 'none'
    };
    return typeMap[type] || 'unknown';
  }

  private async handleNetworkReconnection(): Promise<void> {
    try {
      if (await this.tokenStore.shouldRefreshToken()) {
        await this.refreshTokens();
      }
    } catch (error) {
      console.warn('Failed to refresh token on reconnection:', error);
    }
  }

  private async checkNetworkConnection(): Promise<void> {
    if (!this.networkInfo.isConnected) {
      throw new NetworkError('No network connection', 'NETWORK_UNAVAILABLE');
    }

    if (this.networkInfo.isInternetReachable === false) {
      throw new NetworkError('Internet not reachable', 'INTERNET_UNREACHABLE');
    }
  }

  private async request<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<T> {
    await this.checkNetworkConnection();

    const url = `${this.apiUrl}${endpoint}`;
    const controller = new AbortController();
    const timeoutId = setTimeout(() => controller.abort(), this.networkTimeout);
    
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      'User-Agent': 'Erebor-ReactNative-SDK/0.1.0',
      ...((options.headers as Record<string, string>) || {})
    };

    // Add auth header if we have tokens
    const tokens = await this.tokenStore.getTokens();
    if (tokens?.accessToken) {
      headers['Authorization'] = `Bearer ${tokens.accessToken}`;
    }

    try {
      const requestOptions: RequestInit = {
        ...options,
        headers,
        signal: controller.signal
      };

      // Apply SSL pinning if configured
      if (this.sslPinning.enabled) {
        // Note: SSL pinning implementation would need a native module
        // This is a placeholder for the configuration
        (requestOptions as any).sslPinning = this.sslPinning;
      }

      const response = await fetch(url, requestOptions);

      clearTimeout(timeoutId);

      // Handle 401 - try to refresh token
      if (response.status === 401 && tokens?.refreshToken) {
        try {
          await this.refreshTokens();
          // Retry with new token
          const newTokens = await this.tokenStore.getTokens();
          if (newTokens?.accessToken) {
            headers['Authorization'] = `Bearer ${newTokens.accessToken}`;
          }
          
          const retryResponse = await fetch(url, {
            ...requestOptions,
            headers
          });
          
          if (!retryResponse.ok) {
            throw new AuthError('Authentication failed', 'AUTH_FAILED');
          }
          
          const result = await retryResponse.json();
          return this.handleApiResponse<T>(result);
        } catch (refreshError) {
          await this.tokenStore.clearTokens();
          throw new AuthError('Session expired', 'SESSION_EXPIRED');
        }
      }

      if (!response.ok) {
        if (response.status === 401) {
          throw new AuthError('Authentication required', 'AUTH_REQUIRED');
        }
        if (response.status === 403) {
          throw new AuthError('Access forbidden', 'ACCESS_FORBIDDEN');
        }
        if (response.status >= 500) {
          throw new NetworkError('Server error', 'SERVER_ERROR');
        }
        
        const errorData = await response.json().catch(() => ({}));
        throw new Error(errorData.error || `HTTP ${response.status}`);
      }

      const data = await response.json();
      return this.handleApiResponse<T>(data);
    } catch (error) {
      clearTimeout(timeoutId);
      
      if (error instanceof AuthError || error instanceof NetworkError) {
        throw error;
      }
      
      if (error.name === 'AbortError') {
        throw new NetworkError('Request timeout', 'REQUEST_TIMEOUT');
      }
      
      if (error instanceof TypeError && error.message.includes('fetch')) {
        throw new NetworkError('Network connection failed', 'NETWORK_ERROR');
      }
      
      throw error;
    }
  }

  private handleApiResponse<T>(response: ApiResponse<T>): T {
    if (!response.success) {
      throw new Error(response.error || 'API request failed');
    }
    return response.data as T;
  }

  // Auth methods
  async googleAuth(code: string, redirectUri: string): Promise<AuthTokens> {
    const tokens = await this.request<AuthTokens>('/auth/google', {
      method: 'POST',
      body: JSON.stringify({ code, redirectUri })
    });
    await this.tokenStore.setTokens(tokens);
    return tokens;
  }

  async appleAuth(identityToken: string, authorizationCode: string, nonce?: string): Promise<AuthTokens> {
    const tokens = await this.request<AuthTokens>('/auth/apple', {
      method: 'POST',
      body: JSON.stringify({ identityToken, authorizationCode, nonce })
    });
    await this.tokenStore.setTokens(tokens);
    return tokens;
  }

  async sendEmailOtp(email: string): Promise<void> {
    await this.request('/auth/email/send', {
      method: 'POST',
      body: JSON.stringify({ email })
    });
  }

  async verifyEmailOtp(email: string, code: string): Promise<AuthTokens> {
    const tokens = await this.request<AuthTokens>('/auth/email/verify', {
      method: 'POST',
      body: JSON.stringify({ email, code })
    });
    await this.tokenStore.setTokens(tokens);
    return tokens;
  }

  async getSiweNonce(): Promise<string> {
    const response = await this.request<{ nonce: string }>('/auth/siwe/nonce');
    return response.nonce;
  }

  async verifySiwe(message: string, signature: string): Promise<AuthTokens> {
    const tokens = await this.request<AuthTokens>('/auth/siwe/verify', {
      method: 'POST',
      body: JSON.stringify({ message, signature })
    });
    await this.tokenStore.setTokens(tokens);
    return tokens;
  }

  async refreshTokens(): Promise<AuthTokens> {
    const currentTokens = await this.tokenStore.getTokens();
    if (!currentTokens?.refreshToken) {
      throw new AuthError('No refresh token available', 'NO_REFRESH_TOKEN');
    }

    const tokens = await this.request<AuthTokens>('/auth/refresh', {
      method: 'POST',
      body: JSON.stringify({ refreshToken: currentTokens.refreshToken })
    });
    
    await this.tokenStore.rotateTokens(tokens);
    return tokens;
  }

  async logout(): Promise<void> {
    try {
      await this.request('/auth/logout', {
        method: 'POST'
      });
    } catch (error) {
      // Continue with logout even if API call fails
      console.warn('Logout API call failed:', error);
    } finally {
      await this.tokenStore.clearTokens();
    }
  }

  // User methods
  async getMe(): Promise<EreborUser> {
    return this.request<EreborUser>('/user/me');
  }

  // Wallet methods
  async createWallet(chainId?: number): Promise<EreborWallet> {
    return this.request<EreborWallet>('/wallets', {
      method: 'POST',
      body: JSON.stringify({ chainId })
    });
  }

  async listWallets(): Promise<EreborWallet[]> {
    return this.request<EreborWallet[]>('/wallets');
  }

  async signMessage(walletId: string, message: string): Promise<string> {
    const response = await this.request<{ signature: string }>(`/wallets/${walletId}/sign`, {
      method: 'POST',
      body: JSON.stringify({ message })
    });
    return response.signature;
  }

  async signTransaction(walletId: string, tx: TransactionRequest): Promise<string> {
    const response = await this.request<{ signedTransaction: string }>(`/wallets/${walletId}/sign-transaction`, {
      method: 'POST',
      body: JSON.stringify(tx)
    });
    return response.signedTransaction;
  }

  async sendTransaction(walletId: string, tx: TransactionRequest): Promise<string> {
    const response = await this.request<{ txHash: string }>(`/wallets/${walletId}/send-transaction`, {
      method: 'POST',
      body: JSON.stringify(tx)
    });
    return response.txHash;
  }

  // Account linking
  async linkAccount(provider: string, token: string): Promise<LinkedAccount> {
    return this.request<LinkedAccount>('/user/link-account', {
      method: 'POST',
      body: JSON.stringify({ provider, token })
    });
  }

  async unlinkAccount(provider: string): Promise<void> {
    await this.request(`/user/unlink-account/${provider}`, {
      method: 'DELETE'
    });
  }

  // Token and state management
  async isAuthenticated(): Promise<boolean> {
    const tokens = await this.tokenStore.getTokens();
    return !!tokens?.accessToken;
  }

  async shouldRefreshToken(): Promise<boolean> {
    return this.tokenStore.shouldRefreshToken();
  }

  // Mobile-specific utilities
  getNetworkInfo(): NetworkInfo {
    return { ...this.networkInfo };
  }

  async updateBiometricSetting(enabled: boolean): Promise<void> {
    return this.tokenStore.updateBiometricSetting(enabled);
  }

  getBiometricSetting(): boolean {
    return this.tokenStore.getBiometricSetting();
  }

  isUsingSecureStore(): boolean {
    return this.tokenStore.isUsingSecureStore();
  }

  // Manual token management (for testing/development)
  async setTokens(accessToken: string, refreshToken: string, expiresIn: number): Promise<void> {
    await this.tokenStore.setTokens({ accessToken, refreshToken, expiresIn });
  }

  async clearTokens(): Promise<void> {
    await this.tokenStore.clearTokens();
  }
}