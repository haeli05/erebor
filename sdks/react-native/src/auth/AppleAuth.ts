import * as AppleAuthentication from 'expo-apple-authentication';
import * as Crypto from 'expo-crypto';
import { Platform } from 'react-native';
import { AppleAuthOptions, AppleAuthResult, AuthError } from '../types';
import { OAuthBrowser } from './OAuthBrowser';

export class AppleAuth {
  private clientId: string;
  private redirectUri: string;
  private oauthBrowser?: OAuthBrowser;

  constructor(clientId: string, redirectUri: string) {
    this.clientId = clientId;
    this.redirectUri = redirectUri;
    
    // Initialize OAuth browser for Android fallback
    if (Platform.OS === 'android') {
      this.oauthBrowser = new OAuthBrowser(redirectUri);
    }
  }

  // Check if Apple Sign-In is available on the device
  async isAvailable(): Promise<boolean> {
    try {
      if (Platform.OS === 'ios') {
        return await AppleAuthentication.isAvailableAsync();
      } else {
        // On Android, we can use web-based Apple OAuth
        return true;
      }
    } catch (error) {
      console.warn('Error checking Apple Sign-In availability:', error);
      return false;
    }
  }

  // Native Apple Sign-In (iOS only)
  async authenticateWithNativeApple(options: AppleAuthOptions = {}): Promise<AppleAuthResult> {
    if (Platform.OS !== 'ios') {
      throw new AuthError('Native Apple Sign-In is only available on iOS', 'PLATFORM_NOT_SUPPORTED');
    }

    try {
      const available = await this.isAvailable();
      if (!available) {
        throw new AuthError('Apple Sign-In is not available on this device', 'APPLE_SIGNIN_UNAVAILABLE');
      }

      // Generate nonce if not provided
      const nonce = options.nonce || await this.generateNonce();
      
      // Request authentication
      const credential = await AppleAuthentication.signInAsync({
        requestedScopes: options.requestedScopes || [
          AppleAuthentication.AppleAuthenticationScope.FULL_NAME,
          AppleAuthentication.AppleAuthenticationScope.EMAIL
        ],
        nonce
      });

      if (!credential.identityToken || !credential.authorizationCode) {
        throw new AuthError('Apple Sign-In did not return required credentials', 'INCOMPLETE_CREDENTIALS');
      }

      return {
        identityToken: credential.identityToken,
        authorizationCode: credential.authorizationCode,
        email: credential.email || undefined,
        fullName: credential.fullName ? {
          givenName: credential.fullName.givenName || undefined,
          familyName: credential.fullName.familyName || undefined
        } : undefined,
        user: credential.user
      };
    } catch (error) {
      if (error.code === 'ERR_CANCELED') {
        throw new AuthError('Apple Sign-In was cancelled by user', 'USER_CANCELLED');
      }
      
      if (error instanceof AuthError) {
        throw error;
      }
      
      console.error('Native Apple Sign-In error:', error);
      throw new AuthError('Apple Sign-In failed', 'APPLE_SIGNIN_ERROR');
    }
  }

  // Web-based Apple Sign-In (Android fallback)
  async authenticateWithWebApple(options: AppleAuthOptions = {}): Promise<{ code: string; state?: string }> {
    if (!this.oauthBrowser) {
      throw new AuthError('OAuth browser not initialized for web-based Apple Sign-In', 'OAUTH_NOT_INITIALIZED');
    }

    try {
      const result = await this.oauthBrowser.authenticateWithApple(this.clientId, {
        additionalScopes: options.requestedScopes,
        promptText: 'Sign in with Apple'
      });

      if (result.error) {
        throw new AuthError(
          result.error_description || `Apple OAuth error: ${result.error}`,
          'APPLE_OAUTH_ERROR'
        );
      }

      if (!result.code) {
        throw new AuthError('Apple OAuth did not return authorization code', 'MISSING_AUTH_CODE');
      }

      return {
        code: result.code,
        state: result.state
      };
    } catch (error) {
      if (error instanceof AuthError) {
        throw error;
      }
      
      console.error('Web Apple Sign-In error:', error);
      throw new AuthError('Apple Sign-In failed', 'APPLE_OAUTH_ERROR');
    }
  }

  // Unified Apple authentication method
  async authenticate(options: AppleAuthOptions = {}): Promise<AppleAuthResult | { code: string; state?: string }> {
    if (Platform.OS === 'ios') {
      // Use native Apple Sign-In on iOS
      return await this.authenticateWithNativeApple(options);
    } else {
      // Use web-based OAuth on Android
      return await this.authenticateWithWebApple(options);
    }
  }

  // Check credential state (iOS only)
  async getCredentialStateAsync(userID: string): Promise<AppleAuthentication.AppleAuthenticationCredentialState | null> {
    if (Platform.OS !== 'ios') {
      console.warn('Credential state checking is only available on iOS');
      return null;
    }

    try {
      return await AppleAuthentication.getCredentialStateAsync(userID);
    } catch (error) {
      console.error('Failed to get Apple credential state:', error);
      return null;
    }
  }

  // Refresh Apple credentials (iOS only)
  async refreshCredentials(userID: string): Promise<AppleAuthResult | null> {
    if (Platform.OS !== 'ios') {
      console.warn('Credential refresh is only available on iOS');
      return null;
    }

    try {
      const state = await this.getCredentialStateAsync(userID);
      
      if (state === AppleAuthentication.AppleAuthenticationCredentialState.AUTHORIZED) {
        // Credentials are still valid
        return null;
      }

      if (state === AppleAuthentication.AppleAuthenticationCredentialState.REVOKED) {
        throw new AuthError('Apple credentials have been revoked', 'CREDENTIALS_REVOKED');
      }

      if (state === AppleAuthentication.AppleAuthenticationCredentialState.NOT_FOUND) {
        throw new AuthError('Apple credentials not found', 'CREDENTIALS_NOT_FOUND');
      }

      // Try to refresh by signing in again
      return await this.authenticateWithNativeApple();
    } catch (error) {
      if (error instanceof AuthError) {
        throw error;
      }
      
      console.error('Apple credential refresh error:', error);
      throw new AuthError('Failed to refresh Apple credentials', 'REFRESH_ERROR');
    }
  }

  // Generate cryptographic nonce for security
  private async generateNonce(): Promise<string> {
    const randomBytes = await Crypto.getRandomBytesAsync(32);
    return this.base64URLEncode(randomBytes);
  }

  private base64URLEncode(buffer: Uint8Array): string {
    const base64 = btoa(String.fromCharCode.apply(null, Array.from(buffer)));
    return base64
      .replace(/\+/g, '-')
      .replace(/\//g, '_')
      .replace(/=/g, '');
  }

  // Utility method to create Apple Sign-In button
  static createSignInButton(): JSX.Element | null {
    if (Platform.OS !== 'ios') {
      return null;
    }

    return AppleAuthentication.AppleAuthenticationButton as any;
  }

  // Check if user should be prompted to upgrade to Sign in with Apple
  async shouldShowUpgradePrompt(): Promise<boolean> {
    if (Platform.OS !== 'ios') {
      return false;
    }

    try {
      // Check if device supports Apple Sign-In and user hasn't used it yet
      const isAvailable = await this.isAvailable();
      
      // You could add additional logic here to check if user has other auth methods
      // and should be prompted to upgrade to Apple Sign-In
      return isAvailable;
    } catch (error) {
      console.warn('Error checking upgrade prompt status:', error);
      return false;
    }
  }

  // Sign out of Apple ID (this doesn't actually sign out, just clears local state)
  async signOut(): Promise<void> {
    // Apple doesn't provide a sign-out API, but you can clear any stored credentials
    console.log('Apple Sign-In logout: clearing local credentials only');
  }
}