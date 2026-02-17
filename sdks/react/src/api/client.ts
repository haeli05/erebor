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
  NetworkError
} from '../types';

export class EreborApiClient {
  private apiUrl: string;
  private accessToken: string | null = null;
  private refreshToken: string | null = null;
  private tokenPrefix: string;

  constructor(apiUrl: string, tokenPrefix: string = 'erebor') {
    this.apiUrl = apiUrl.replace(/\/$/, '');
    this.tokenPrefix = tokenPrefix;
    this.loadTokens();
  }

  private loadTokens(): void {
    try {
      this.accessToken = localStorage.getItem(`${this.tokenPrefix}_access_token`);
      this.refreshToken = localStorage.getItem(`${this.tokenPrefix}_refresh_token`);
    } catch (error) {
      // localStorage might not be available
    }
  }

  private saveTokens(tokens: AuthTokens): void {
    try {
      localStorage.setItem(`${this.tokenPrefix}_access_token`, tokens.accessToken);
      localStorage.setItem(`${this.tokenPrefix}_refresh_token`, tokens.refreshToken);
      // Store expiry time
      const expiryTime = Date.now() + (tokens.expiresIn * 1000);
      localStorage.setItem(`${this.tokenPrefix}_token_expiry`, expiryTime.toString());
      
      this.accessToken = tokens.accessToken;
      this.refreshToken = tokens.refreshToken;
    } catch (error) {
      // localStorage might not be available
    }
  }

  private clearTokens(): void {
    try {
      localStorage.removeItem(`${this.tokenPrefix}_access_token`);
      localStorage.removeItem(`${this.tokenPrefix}_refresh_token`);
      localStorage.removeItem(`${this.tokenPrefix}_token_expiry`);
    } catch (error) {
      // localStorage might not be available
    }
    
    this.accessToken = null;
    this.refreshToken = null;
  }

  private async request<T>(
    endpoint: string,
    options: RequestInit = {}
  ): Promise<T> {
    const url = `${this.apiUrl}${endpoint}`;
    
    const headers: Record<string, string> = {
      'Content-Type': 'application/json',
      ...((options.headers as Record<string, string>) || {})
    };

    // Add auth header if we have a token
    if (this.accessToken) {
      headers['Authorization'] = `Bearer ${this.accessToken}`;
    }

    try {
      const response = await fetch(url, {
        ...options,
        headers
      });

      // Handle 401 - try to refresh token
      if (response.status === 401 && this.refreshToken) {
        try {
          await this.refreshTokens();
          // Retry with new token
          headers['Authorization'] = `Bearer ${this.accessToken}`;
          const retryResponse = await fetch(url, {
            ...options,
            headers
          });
          
          if (!retryResponse.ok) {
            throw new AuthError('Authentication failed', 'AUTH_FAILED');
          }
          
          const result = await retryResponse.json();
          return this.handleApiResponse<T>(result);
        } catch (refreshError) {
          this.clearTokens();
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
      if (error instanceof AuthError || error instanceof NetworkError) {
        throw error;
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
    this.saveTokens(tokens);
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
    this.saveTokens(tokens);
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
    this.saveTokens(tokens);
    return tokens;
  }

  async refreshTokens(): Promise<AuthTokens> {
    if (!this.refreshToken) {
      throw new AuthError('No refresh token available', 'NO_REFRESH_TOKEN');
    }

    const tokens = await this.request<AuthTokens>('/auth/refresh', {
      method: 'POST',
      body: JSON.stringify({ refreshToken: this.refreshToken })
    });
    this.saveTokens(tokens);
    return tokens;
  }

  async logout(): Promise<void> {
    try {
      await this.request('/auth/logout', {
        method: 'POST'
      });
    } catch (error) {
      // Continue with logout even if API call fails
    } finally {
      this.clearTokens();
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

  // Token management
  isAuthenticated(): boolean {
    return !!this.accessToken;
  }

  shouldRefreshToken(): boolean {
    if (!this.refreshToken) return false;
    
    try {
      const expiryTime = localStorage.getItem(`${this.tokenPrefix}_token_expiry`);
      if (!expiryTime) return false;
      
      const expiry = parseInt(expiryTime);
      const now = Date.now();
      
      // Refresh if token expires within 5 minutes
      return now >= (expiry - 5 * 60 * 1000);
    } catch (error) {
      return false;
    }
  }

  // Manual token setting (for testing)
  setTokens(accessToken: string, refreshToken: string): void {
    this.accessToken = accessToken;
    this.refreshToken = refreshToken;
    
    try {
      localStorage.setItem(`${this.tokenPrefix}_access_token`, accessToken);
      localStorage.setItem(`${this.tokenPrefix}_refresh_token`, refreshToken);
    } catch (error) {
      // localStorage might not be available
    }
  }
}