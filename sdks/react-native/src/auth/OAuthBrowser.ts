import * as WebBrowser from 'expo-web-browser';
import * as Crypto from 'expo-crypto';
import { Platform } from 'react-native';
import { MobileOAuthOptions, DeepLinkError } from '../types';

export interface OAuthResult {
  code?: string;
  state?: string;
  error?: string;
  error_description?: string;
}

export interface PKCEChallenge {
  codeVerifier: string;
  codeChallenge: string;
  codeChallengeMethod: 'S256';
}

export class OAuthBrowser {
  private redirectUri: string;
  private scheme: string;

  constructor(redirectUri: string, scheme?: string) {
    this.redirectUri = redirectUri;
    this.scheme = scheme || redirectUri.split('://')[0];
    
    // Configure WebBrowser for better UX
    WebBrowser.maybeCompleteAuthSession();
  }

  // Generate PKCE challenge for secure OAuth flow
  async generatePKCEChallenge(): Promise<PKCEChallenge> {
    const codeVerifier = await this.generateCodeVerifier();
    const codeChallenge = await this.generateCodeChallenge(codeVerifier);
    
    return {
      codeVerifier,
      codeChallenge,
      codeChallengeMethod: 'S256'
    };
  }

  private async generateCodeVerifier(): Promise<string> {
    const randomBytes = await Crypto.getRandomBytesAsync(32);
    return this.base64URLEncode(randomBytes);
  }

  private async generateCodeChallenge(codeVerifier: string): Promise<string> {
    const hash = await Crypto.digestStringAsync(
      Crypto.CryptoDigestAlgorithm.SHA256,
      codeVerifier,
      { encoding: Crypto.CryptoEncoding.BASE64URL }
    );
    return hash;
  }

  private base64URLEncode(buffer: Uint8Array): string {
    const base64 = btoa(String.fromCharCode.apply(null, Array.from(buffer)));
    return base64
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }

  // Google OAuth
  async authenticateWithGoogle(
    clientId: string,
    options: MobileOAuthOptions = {}
  ): Promise<OAuthResult> {
    const { codeVerifier, codeChallenge } = await this.generatePKCEChallenge();
    const state = await Crypto.getRandomBytesAsync(16).then(bytes => 
      this.base64URLEncode(bytes)
    );

    const scopes = ['openid', 'profile', 'email', ...(options.additionalScopes || [])];
    
    const authUrl = `https://accounts.google.com/o/oauth2/v2/auth?${new URLSearchParams({
      client_id: clientId,
      redirect_uri: this.redirectUri,
      response_type: 'code',
      scope: scopes.join(' '),
      state,
      code_challenge: codeChallenge,
      code_challenge_method: 'S256',
      access_type: 'offline',
      prompt: 'consent'
    })}`;

    try {
      const result = await WebBrowser.openAuthSessionAsync(
        authUrl,
        this.redirectUri,
        {
          useProxy: options.useSystemBrowser === false,
          showInRecents: options.showInRecents ?? true,
          promptAsync: {
            promptText: options.promptText || 'Sign in with Google'
          }
        }
      );

      if (result.type === 'success' && result.url) {
        const params = this.extractUrlParams(result.url);
        
        // Verify state parameter
        if (params.state !== state) {
          throw new DeepLinkError('OAuth state mismatch', 'OAUTH_STATE_MISMATCH');
        }

        return {
          code: params.code,
          state: params.state,
          error: params.error,
          error_description: params.error_description
        };
      }

      if (result.type === 'cancel') {
        throw new DeepLinkError('OAuth cancelled by user', 'OAUTH_CANCELLED');
      }

      throw new DeepLinkError('OAuth failed', 'OAUTH_FAILED');
    } catch (error) {
      if (error instanceof DeepLinkError) {
        throw error;
      }
      
      console.error('Google OAuth error:', error);
      throw new DeepLinkError('Google OAuth failed', 'GOOGLE_OAUTH_ERROR');
    }
  }

  // Apple OAuth (will redirect to system browser)
  async authenticateWithApple(
    clientId: string,
    options: MobileOAuthOptions = {}
  ): Promise<OAuthResult> {
    // Apple requires native Sign in with Apple on iOS
    // For Android, we'll use web-based OAuth
    if (Platform.OS === 'android') {
      return this.authenticateWithAppleWeb(clientId, options);
    }

    // For iOS, recommend using expo-apple-authentication instead
    throw new DeepLinkError(
      'Use AppleAuth.authenticateWithNativeApple() for iOS. This method is for Android only.',
      'USE_NATIVE_APPLE_AUTH'
    );
  }

  private async authenticateWithAppleWeb(
    clientId: string,
    options: MobileOAuthOptions = {}
  ): Promise<OAuthResult> {
    const state = await Crypto.getRandomBytesAsync(16).then(bytes => 
      this.base64URLEncode(bytes)
    );

    const scopes = ['name', 'email', ...(options.additionalScopes || [])];
    
    const authUrl = `https://appleid.apple.com/auth/authorize?${new URLSearchParams({
      client_id: clientId,
      redirect_uri: this.redirectUri,
      response_type: 'code',
      scope: scopes.join(' '),
      state,
      response_mode: 'query'
    })}`;

    try {
      const result = await WebBrowser.openAuthSessionAsync(
        authUrl,
        this.redirectUri,
        {
          useProxy: options.useSystemBrowser === false,
          showInRecents: options.showInRecents ?? true
        }
      );

      if (result.type === 'success' && result.url) {
        const params = this.extractUrlParams(result.url);
        
        if (params.state !== state) {
          throw new DeepLinkError('OAuth state mismatch', 'OAUTH_STATE_MISMATCH');
        }

        return {
          code: params.code,
          state: params.state,
          error: params.error,
          error_description: params.error_description
        };
      }

      if (result.type === 'cancel') {
        throw new DeepLinkError('OAuth cancelled by user', 'OAUTH_CANCELLED');
      }

      throw new DeepLinkError('OAuth failed', 'OAUTH_FAILED');
    } catch (error) {
      if (error instanceof DeepLinkError) {
        throw error;
      }
      
      console.error('Apple OAuth error:', error);
      throw new DeepLinkError('Apple OAuth failed', 'APPLE_OAUTH_ERROR');
    }
  }

  // Generic OAuth for other providers
  async authenticateWithProvider(
    authUrl: string,
    options: MobileOAuthOptions = {}
  ): Promise<OAuthResult> {
    try {
      const result = await WebBrowser.openAuthSessionAsync(
        authUrl,
        this.redirectUri,
        {
          useProxy: options.useSystemBrowser === false,
          showInRecents: options.showInRecents ?? true
        }
      );

      if (result.type === 'success' && result.url) {
        const params = this.extractUrlParams(result.url);
        
        return {
          code: params.code,
          state: params.state,
          error: params.error,
          error_description: params.error_description
        };
      }

      if (result.type === 'cancel') {
        throw new DeepLinkError('OAuth cancelled by user', 'OAUTH_CANCELLED');
      }

      throw new DeepLinkError('OAuth failed', 'OAUTH_FAILED');
    } catch (error) {
      if (error instanceof DeepLinkError) {
        throw error;
      }
      
      console.error('OAuth error:', error);
      throw new DeepLinkError('OAuth authentication failed', 'OAUTH_ERROR');
    }
  }

  // Extract URL parameters from OAuth callback
  private extractUrlParams(url: string): Record<string, string> {
    try {
      const urlObj = new URL(url);
      const params: Record<string, string> = {};
      
      urlObj.searchParams.forEach((value, key) => {
        params[key] = value;
      });

      return params;
    } catch (error) {
      console.error('Failed to parse OAuth callback URL:', url, error);
      return {};
    }
  }

  // Warm up the browser for faster auth
  async warmUpBrowser(): Promise<void> {
    try {
      await WebBrowser.warmUpAsync();
    } catch (error) {
      console.warn('Browser warm up failed:', error);
    }
  }

  // Cool down the browser to free resources
  async coolDownBrowser(): Promise<void> {
    try {
      await WebBrowser.coolDownAsync();
    } catch (error) {
      console.warn('Browser cool down failed:', error);
    }
  }

  // Check if system browser is available
  async isSystemBrowserAvailable(): Promise<boolean> {
    return await WebBrowser.getCustomTabsSupportingBrowsersAsync()
      .then(browsers => browsers.length > 0)
      .catch(() => false);
  }
}