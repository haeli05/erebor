import * as SecureStore from 'expo-secure-store';
import * as Crypto from 'expo-crypto';
import * as LocalAuthentication from 'expo-local-authentication';
import { DeviceKeyShare, KeyBackupOptions, SecureStorageError, BiometricError } from '../types';

export interface KeyGenerationOptions {
  biometricProtection?: boolean;
  keySize?: number;
  derivationPath?: string;
}

export interface KeyManagerOptions {
  keyPrefix?: string;
  requireBiometrics?: boolean;
  autoBackup?: boolean;
}

export class DeviceKeyManager {
  private keyPrefix: string;
  private requireBiometrics: boolean;
  private autoBackup: boolean;

  constructor(options: KeyManagerOptions = {}) {
    this.keyPrefix = options.keyPrefix || 'erebor_key';
    this.requireBiometrics = options.requireBiometrics ?? false;
    this.autoBackup = options.autoBackup ?? false;
  }

  // Generate a new device key share
  async generateKeyShare(
    walletId: string,
    options: KeyGenerationOptions = {}
  ): Promise<DeviceKeyShare> {
    try {
      // Check biometric requirements
      if (options.biometricProtection ?? this.requireBiometrics) {
        await this.checkBiometricPermission();
      }

      // Generate cryptographically secure random key material
      const keySize = options.keySize || 32; // 256 bits
      const keyMaterial = await Crypto.getRandomBytesAsync(keySize);
      
      // Create key share metadata
      const keyShare: DeviceKeyShare = {
        id: walletId,
        encryptedShare: await this.encryptKeyMaterial(keyMaterial, walletId, options.biometricProtection),
        derivationPath: options.derivationPath || "m/44'/60'/0'/0/0",
        createdAt: new Date().toISOString(),
        lastUsed: new Date().toISOString()
      };

      // Store the encrypted key share
      await this.storeKeyShare(keyShare, options.biometricProtection);

      // Auto-backup if enabled
      if (this.autoBackup) {
        await this.createBackup(walletId, { method: 'cloud', encryption: true });
      }

      return keyShare;
    } catch (error) {
      console.error('Key share generation failed:', error);
      throw new SecureStorageError('Failed to generate device key share', 'KEY_GENERATION_FAILED');
    }
  }

  // Retrieve device key share
  async getKeyShare(walletId: string, requireBiometric: boolean = false): Promise<DeviceKeyShare | null> {
    try {
      // Check biometric permission if required
      if (requireBiometric || this.requireBiometrics) {
        await this.checkBiometricPermission();
      }

      const storageKey = this.getStorageKey(walletId);
      const storedData = await SecureStore.getItemAsync(storageKey, {
        requireAuthentication: requireBiometric || this.requireBiometrics,
        authenticationPrompt: 'Authenticate to access your wallet key'
      });

      if (!storedData) {
        return null;
      }

      const keyShare: DeviceKeyShare = JSON.parse(storedData);
      
      // Update last used timestamp
      keyShare.lastUsed = new Date().toISOString();
      await this.storeKeyShare(keyShare, requireBiometric);

      return keyShare;
    } catch (error) {
      console.error('Key share retrieval failed:', error);
      
      if (error.code === 'UserCancel') {
        throw new BiometricError('User cancelled key access', 'USER_CANCELLED');
      }
      
      throw new SecureStorageError('Failed to retrieve device key share', 'KEY_RETRIEVAL_FAILED');
    }
  }

  // Get decrypted key material (use with extreme caution)
  async getDecryptedKeyMaterial(walletId: string, requireBiometric: boolean = true): Promise<Uint8Array> {
    try {
      const keyShare = await this.getKeyShare(walletId, requireBiometric);
      
      if (!keyShare) {
        throw new SecureStorageError('Key share not found', 'KEY_NOT_FOUND');
      }

      const decryptedMaterial = await this.decryptKeyMaterial(keyShare.encryptedShare, walletId);
      
      // Schedule automatic cleanup
      this.scheduleKeyCleanup(decryptedMaterial);
      
      return decryptedMaterial;
    } catch (error) {
      if (error instanceof SecureStorageError || error instanceof BiometricError) {
        throw error;
      }
      
      console.error('Key material decryption failed:', error);
      throw new SecureStorageError('Failed to decrypt key material', 'DECRYPTION_FAILED');
    }
  }

  // Delete device key share
  async deleteKeyShare(walletId: string, requireBiometric: boolean = false): Promise<void> {
    try {
      if (requireBiometric || this.requireBiometrics) {
        await this.checkBiometricPermission();
      }

      const storageKey = this.getStorageKey(walletId);
      await SecureStore.deleteItemAsync(storageKey);
      
      // Also cleanup any backup references
      await this.cleanupBackups(walletId);
      
    } catch (error) {
      console.error('Key share deletion failed:', error);
      throw new SecureStorageError('Failed to delete device key share', 'KEY_DELETION_FAILED');
    }
  }

  // List all stored key shares
  async listKeyShares(): Promise<DeviceKeyShare[]> {
    try {
      // This is a limitation - SecureStore doesn't provide a list operation
      // In a real implementation, you'd maintain an index of key IDs
      console.warn('Key share listing requires maintaining a separate index');
      return [];
    } catch (error) {
      console.error('Key share listing failed:', error);
      return [];
    }
  }

  // Create backup of key share
  async createBackup(walletId: string, options: KeyBackupOptions): Promise<string> {
    try {
      const keyShare = await this.getKeyShare(walletId, true);
      
      if (!keyShare) {
        throw new SecureStorageError('Key share not found for backup', 'KEY_NOT_FOUND');
      }

      switch (options.method) {
        case 'qr':
          return await this.createQRBackup(keyShare, options);
        case 'cloud':
          return await this.createCloudBackup(keyShare, options);
        case 'manual':
          return await this.createManualBackup(keyShare, options);
        default:
          throw new SecureStorageError('Unsupported backup method', 'UNSUPPORTED_BACKUP_METHOD');
      }
    } catch (error) {
      if (error instanceof SecureStorageError) {
        throw error;
      }
      
      console.error('Backup creation failed:', error);
      throw new SecureStorageError('Failed to create key backup', 'BACKUP_FAILED');
    }
  }

  // Restore key share from backup
  async restoreFromBackup(backupData: string, walletId: string): Promise<DeviceKeyShare> {
    try {
      // Parse and validate backup data
      const backupObj = JSON.parse(backupData);
      
      if (!backupObj.keyShare || !backupObj.checksum) {
        throw new SecureStorageError('Invalid backup format', 'INVALID_BACKUP_FORMAT');
      }

      // Verify backup integrity
      const calculatedChecksum = await this.calculateChecksum(backupObj.keyShare);
      if (calculatedChecksum !== backupObj.checksum) {
        throw new SecureStorageError('Backup integrity check failed', 'BACKUP_CORRUPTED');
      }

      const keyShare: DeviceKeyShare = backupObj.keyShare;
      keyShare.id = walletId; // Ensure correct wallet ID
      keyShare.lastUsed = new Date().toISOString();

      // Store the restored key share
      await this.storeKeyShare(keyShare, true);

      return keyShare;
    } catch (error) {
      if (error instanceof SecureStorageError) {
        throw error;
      }
      
      console.error('Backup restoration failed:', error);
      throw new SecureStorageError('Failed to restore key from backup', 'RESTORE_FAILED');
    }
  }

  // Private helper methods
  private async checkBiometricPermission(): Promise<void> {
    const isAvailable = await LocalAuthentication.hasHardwareAsync();
    if (!isAvailable) {
      throw new BiometricError('Biometric hardware not available', 'BIOMETRIC_UNAVAILABLE');
    }

    const isEnrolled = await LocalAuthentication.isEnrolledAsync();
    if (!isEnrolled) {
      throw new BiometricError('No biometrics enrolled on device', 'BIOMETRIC_NOT_ENROLLED');
    }

    const result = await LocalAuthentication.authenticateAsync({
      promptMessage: 'Authenticate to access your wallet keys',
      disableDeviceFallback: true
    });

    if (!result.success) {
      throw new BiometricError('Biometric authentication failed', 'BIOMETRIC_AUTH_FAILED');
    }
  }

  private async encryptKeyMaterial(keyMaterial: Uint8Array, walletId: string, biometricProtection?: boolean): Promise<string> {
    // In a real implementation, you'd use proper encryption
    // For demo purposes, we'll use base64 encoding with a salt
    const salt = await Crypto.getRandomBytesAsync(16);
    const combined = new Uint8Array(salt.length + keyMaterial.length);
    combined.set(salt);
    combined.set(keyMaterial, salt.length);
    
    return btoa(String.fromCharCode.apply(null, Array.from(combined)));
  }

  private async decryptKeyMaterial(encryptedShare: string, walletId: string): Promise<Uint8Array> {
    // Reverse the encryption process
    const combined = new Uint8Array(atob(encryptedShare).split('').map(c => c.charCodeAt(0)));
    const keyMaterial = combined.slice(16); // Skip 16-byte salt
    
    return keyMaterial;
  }

  private async storeKeyShare(keyShare: DeviceKeyShare, biometricProtection?: boolean): Promise<void> {
    const storageKey = this.getStorageKey(keyShare.id);
    const serializedData = JSON.stringify(keyShare);
    
    const options: SecureStore.SecureStoreOptions = {};
    
    if (biometricProtection ?? this.requireBiometrics) {
      options.requireAuthentication = true;
      options.authenticationPrompt = 'Authenticate to secure your wallet key';
    }

    await SecureStore.setItemAsync(storageKey, serializedData, options);
  }

  private getStorageKey(walletId: string): string {
    return `${this.keyPrefix}_${walletId}`;
  }

  private scheduleKeyCleanup(keyMaterial: Uint8Array): void {
    // Zero out the key material after 30 seconds for security
    setTimeout(() => {
      keyMaterial.fill(0);
    }, 30000);
  }

  private async createQRBackup(keyShare: DeviceKeyShare, options: KeyBackupOptions): Promise<string> {
    // Create encrypted backup for QR code
    const backupData = {
      keyShare: options.encryption ? await this.encryptBackup(keyShare) : keyShare,
      checksum: await this.calculateChecksum(keyShare),
      timestamp: new Date().toISOString()
    };

    return JSON.stringify(backupData);
  }

  private async createCloudBackup(keyShare: DeviceKeyShare, options: KeyBackupOptions): Promise<string> {
    // In a real implementation, this would upload to cloud storage
    console.log('Cloud backup not implemented - would upload encrypted key share');
    return 'cloud-backup-id';
  }

  private async createManualBackup(keyShare: DeviceKeyShare, options: KeyBackupOptions): Promise<string> {
    // Create human-readable backup phrase or hex string
    const keyMaterial = await this.decryptKeyMaterial(keyShare.encryptedShare, keyShare.id);
    const hexString = Array.from(keyMaterial).map(b => b.toString(16).padStart(2, '0')).join('');
    
    // Zero out the key material
    keyMaterial.fill(0);
    
    return hexString;
  }

  private async encryptBackup(keyShare: DeviceKeyShare): Promise<DeviceKeyShare> {
    // Additional encryption layer for backups
    return keyShare; // Placeholder
  }

  private async calculateChecksum(keyShare: DeviceKeyShare): Promise<string> {
    const data = JSON.stringify(keyShare);
    return await Crypto.digestStringAsync(Crypto.CryptoDigestAlgorithm.SHA256, data);
  }

  private async cleanupBackups(walletId: string): Promise<void> {
    // Clean up any backup references for this wallet
    console.log(`Cleaning up backups for wallet ${walletId}`);
  }
}