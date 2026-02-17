import * as SecureStore from 'expo-secure-store';
import AsyncStorage from '@react-native-async-storage/async-storage';
import * as LocalAuthentication from 'expo-local-authentication';
import { AuthTokens, SecureStorageConfig, SecureStorageError, BiometricError } from '../types';

export interface TokenStoreOptions {
  keyPrefix?: string;
  useSecureStore?: boolean;
  biometricProtection?: boolean;
  fallbackToAsyncStorage?: boolean;
}

export class SecureTokenStore {
  private keyPrefix: string;
  private useSecureStore: boolean;
  private biometricProtection: boolean;
  private fallbackToAsyncStorage: boolean;
  private isSecureStoreAvailable: boolean = false;

  constructor(options: TokenStoreOptions = {}) {
    this.keyPrefix = options.keyPrefix || 'erebor';
    this.useSecureStore = options.useSecureStore ?? true;
    this.biometricProtection = options.biometricProtection ?? false;
    this.fallbackToAsyncStorage = options.fallbackToAsyncStorage ?? true;

    this.checkSecureStoreAvailability();
  }

  private async checkSecureStoreAvailability(): Promise<void> {
    try {
      // Test if SecureStore is available
      await SecureStore.isAvailableAsync();
      this.isSecureStoreAvailable = true;
    } catch (error) {
      console.warn('SecureStore not available, falling back to AsyncStorage:', error);
      this.isSecureStoreAvailable = false;
    }
  }

  private getStorageKey(key: string): string {
    return `${this.keyPrefix}_${key}`;
  }

  private async checkBiometricPermission(): Promise<boolean> {
    if (!this.biometricProtection) {
      return true;
    }

    try {
      const isAvailable = await LocalAuthentication.hasHardwareAsync();
      if (!isAvailable) {
        throw new BiometricError('Biometric hardware not available', 'BIOMETRIC_UNAVAILABLE');
      }

      const isEnrolled = await LocalAuthentication.isEnrolledAsync();
      if (!isEnrolled) {
        throw new BiometricError('No biometrics enrolled on device', 'BIOMETRIC_NOT_ENROLLED');
      }

      const result = await LocalAuthentication.authenticateAsync({
        promptMessage: 'Authenticate to access your wallet',
        disableDeviceFallback: true,
        cancelLabel: 'Cancel',
      });

      if (!result.success) {
        throw new BiometricError('Biometric authentication failed', 'BIOMETRIC_AUTH_FAILED');
      }

      return true;
    } catch (error) {
      if (error instanceof BiometricError) {
        throw error;
      }
      throw new BiometricError('Biometric authentication error', 'BIOMETRIC_ERROR');
    }
  }

  private async secureStoreGet(key: string): Promise<string | null> {
    const storageKey = this.getStorageKey(key);
    
    if (this.useSecureStore && this.isSecureStoreAvailable) {
      try {
        const options: SecureStore.SecureStoreOptions = {};
        
        if (this.biometricProtection) {
          options.authenticationPrompt = 'Authenticate to access your wallet';
          options.requireAuthentication = true;
        }

        return await SecureStore.getItemAsync(storageKey, options);
      } catch (error) {
        console.warn('SecureStore get failed, trying fallback:', error);
        
        if (!this.fallbackToAsyncStorage) {
          throw new SecureStorageError('Failed to retrieve from secure storage', 'SECURE_STORE_GET_ERROR');
        }
        
        // Fallback to AsyncStorage
        return await AsyncStorage.getItem(storageKey);
      }
    } else {
      // Check biometric permission for AsyncStorage
      if (this.biometricProtection) {
        await this.checkBiometricPermission();
      }
      
      return await AsyncStorage.getItem(storageKey);
    }
  }

  private async secureStoreSet(key: string, value: string): Promise<void> {
    const storageKey = this.getStorageKey(key);
    
    if (this.useSecureStore && this.isSecureStoreAvailable) {
      try {
        const options: SecureStore.SecureStoreOptions = {};
        
        if (this.biometricProtection) {
          options.authenticationPrompt = 'Authenticate to save your wallet';
          options.requireAuthentication = true;
        }

        await SecureStore.setItemAsync(storageKey, value, options);
        return;
      } catch (error) {
        console.warn('SecureStore set failed, trying fallback:', error);
        
        if (!this.fallbackToAsyncStorage) {
          throw new SecureStorageError('Failed to save to secure storage', 'SECURE_STORE_SET_ERROR');
        }
      }
    }
    
    // Check biometric permission for AsyncStorage
    if (this.biometricProtection) {
      await this.checkBiometricPermission();
    }
    
    // Use AsyncStorage as fallback
    await AsyncStorage.setItem(storageKey, value);
  }

  private async secureStoreDelete(key: string): Promise<void> {
    const storageKey = this.getStorageKey(key);
    
    if (this.useSecureStore && this.isSecureStoreAvailable) {
      try {
        await SecureStore.deleteItemAsync(storageKey);
        return;
      } catch (error) {
        console.warn('SecureStore delete failed, trying fallback:', error);
      }
    }
    
    // Fallback to AsyncStorage
    await AsyncStorage.removeItem(storageKey);
  }

  async getTokens(): Promise<AuthTokens | null> {
    try {
      const accessToken = await this.secureStoreGet('access_token');
      const refreshToken = await this.secureStoreGet('refresh_token');
      const expiryTimeStr = await this.secureStoreGet('token_expiry');

      if (!accessToken || !refreshToken) {
        return null;
      }

      const expiresIn = expiryTimeStr 
        ? Math.max(0, parseInt(expiryTimeStr) - Date.now()) / 1000 
        : 0;

      return {
        accessToken,
        refreshToken,
        expiresIn
      };
    } catch (error) {
      console.error('Failed to get tokens:', error);
      throw error;
    }
  }

  async setTokens(tokens: AuthTokens): Promise<void> {
    try {
      await Promise.all([
        this.secureStoreSet('access_token', tokens.accessToken),
        this.secureStoreSet('refresh_token', tokens.refreshToken),
        this.secureStoreSet('token_expiry', (Date.now() + tokens.expiresIn * 1000).toString())
      ]);
    } catch (error) {
      console.error('Failed to save tokens:', error);
      throw error;
    }
  }

  async clearTokens(): Promise<void> {
    try {
      await Promise.all([
        this.secureStoreDelete('access_token'),
        this.secureStoreDelete('refresh_token'),
        this.secureStoreDelete('token_expiry')
      ]);
    } catch (error) {
      console.error('Failed to clear tokens:', error);
      // Don't throw error for cleanup operations
    }
  }

  async hasTokens(): Promise<boolean> {
    try {
      const tokens = await this.getTokens();
      return !!tokens;
    } catch (error) {
      return false;
    }
  }

  async shouldRefreshToken(): Promise<boolean> {
    try {
      const expiryTimeStr = await this.secureStoreGet('token_expiry');
      if (!expiryTimeStr) return false;
      
      const expiryTime = parseInt(expiryTimeStr);
      const now = Date.now();
      
      // Refresh if token expires within 5 minutes
      return now >= (expiryTime - 5 * 60 * 1000);
    } catch (error) {
      return false;
    }
  }

  async rotateTokens(newTokens: AuthTokens): Promise<void> {
    // Atomic token rotation for security
    const oldTokens = await this.getTokens();
    
    try {
      await this.setTokens(newTokens);
    } catch (error) {
      // If setting new tokens fails, restore old tokens
      if (oldTokens) {
        try {
          await this.setTokens(oldTokens);
        } catch (restoreError) {
          console.error('Failed to restore tokens after rotation failure:', restoreError);
        }
      }
      throw error;
    }
  }

  // Utility methods for configuration
  async updateBiometricSetting(enabled: boolean): Promise<void> {
    if (enabled && !(await LocalAuthentication.hasHardwareAsync())) {
      throw new BiometricError('Biometric hardware not available', 'BIOMETRIC_UNAVAILABLE');
    }
    
    if (enabled && !(await LocalAuthentication.isEnrolledAsync())) {
      throw new BiometricError('No biometrics enrolled on device', 'BIOMETRIC_NOT_ENROLLED');
    }
    
    this.biometricProtection = enabled;
    
    // If enabling biometric protection, re-store tokens with new protection
    if (enabled) {
      const tokens = await this.getTokens();
      if (tokens) {
        await this.setTokens(tokens);
      }
    }
  }

  getBiometricSetting(): boolean {
    return this.biometricProtection;
  }

  isUsingSecureStore(): boolean {
    return this.useSecureStore && this.isSecureStoreAvailable;
  }
}