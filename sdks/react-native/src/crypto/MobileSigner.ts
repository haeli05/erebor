import * as Crypto from 'expo-crypto';
import { DeviceKeyManager } from './DeviceKeyManager';
import { TransactionRequest, BiometricError, WalletError } from '../types';

export interface SigningOptions {
  requireBiometric?: boolean;
  autoZeroize?: boolean;
  timeout?: number;
}

export interface SigningResult {
  signature: string;
  recoveryId?: number;
  messageHash: string;
}

export interface KeyRecoveryOptions {
  deviceShare: Uint8Array;
  serverShare: Uint8Array;
  derivationPath?: string;
}

export class MobileSigner {
  private deviceKeyManager: DeviceKeyManager;
  private activeKeys: Map<string, { key: Uint8Array; timestamp: number }> = new Map();

  constructor(keyManager?: DeviceKeyManager) {
    this.deviceKeyManager = keyManager || new DeviceKeyManager();
    
    // Auto-cleanup active keys every minute
    setInterval(() => this.cleanupExpiredKeys(), 60000);
  }

  // Sign a transaction with device-side key reconstruction
  async signTransaction(
    walletId: string,
    transaction: TransactionRequest,
    serverShare: Uint8Array,
    options: SigningOptions = {}
  ): Promise<SigningResult> {
    const autoZeroize = options.autoZeroize ?? true;
    const timeout = options.timeout ?? 30000;

    try {
      // Get device key share with biometric protection
      const deviceShare = await this.deviceKeyManager.getDecryptedKeyMaterial(
        walletId, 
        options.requireBiometric ?? true
      );

      // Reconstruct the full private key in memory
      const privateKey = this.reconstructPrivateKey({ deviceShare, serverShare });

      // Sign the transaction
      const result = await this.performTransactionSigning(privateKey, transaction);

      // Immediately zero out key material
      if (autoZeroize) {
        this.zeroizeKeyMaterial(privateKey, deviceShare, serverShare);
      }

      return result;
    } catch (error) {
      console.error('Transaction signing failed:', error);
      
      if (error instanceof BiometricError) {
        throw error;
      }
      
      throw new WalletError('Failed to sign transaction', 'SIGNING_FAILED');
    }
  }

  // Sign a message with device-side key reconstruction
  async signMessage(
    walletId: string,
    message: string,
    serverShare: Uint8Array,
    options: SigningOptions = {}
  ): Promise<SigningResult> {
    const autoZeroize = options.autoZeroize ?? true;

    try {
      // Get device key share with biometric protection
      const deviceShare = await this.deviceKeyManager.getDecryptedKeyMaterial(
        walletId,
        options.requireBiometric ?? true
      );

      // Reconstruct the full private key in memory
      const privateKey = this.reconstructPrivateKey({ deviceShare, serverShare });

      // Sign the message
      const result = await this.performMessageSigning(privateKey, message);

      // Immediately zero out key material
      if (autoZeroize) {
        this.zeroizeKeyMaterial(privateKey, deviceShare, serverShare);
      }

      return result;
    } catch (error) {
      console.error('Message signing failed:', error);
      
      if (error instanceof BiometricError) {
        throw error;
      }
      
      throw new WalletError('Failed to sign message', 'SIGNING_FAILED');
    }
  }

  // Sign typed data (EIP-712) with device-side key reconstruction
  async signTypedData(
    walletId: string,
    domain: any,
    types: any,
    value: any,
    serverShare: Uint8Array,
    options: SigningOptions = {}
  ): Promise<SigningResult> {
    const autoZeroize = options.autoZeroize ?? true;

    try {
      // Get device key share with biometric protection
      const deviceShare = await this.deviceKeyManager.getDecryptedKeyMaterial(
        walletId,
        options.requireBiometric ?? true
      );

      // Reconstruct the full private key in memory
      const privateKey = this.reconstructPrivateKey({ deviceShare, serverShare });

      // Sign the typed data
      const result = await this.performTypedDataSigning(privateKey, domain, types, value);

      // Immediately zero out key material
      if (autoZeroize) {
        this.zeroizeKeyMaterial(privateKey, deviceShare, serverShare);
      }

      return result;
    } catch (error) {
      console.error('Typed data signing failed:', error);
      
      if (error instanceof BiometricError) {
        throw error;
      }
      
      throw new WalletError('Failed to sign typed data', 'SIGNING_FAILED');
    }
  }

  // Batch signing operations (for efficiency)
  async batchSign(
    walletId: string,
    operations: Array<{
      type: 'transaction' | 'message' | 'typedData';
      data: any;
    }>,
    serverShare: Uint8Array,
    options: SigningOptions = {}
  ): Promise<SigningResult[]> {
    try {
      // Get device key share once for all operations
      const deviceShare = await this.deviceKeyManager.getDecryptedKeyMaterial(
        walletId,
        options.requireBiometric ?? true
      );

      // Reconstruct the private key once
      const privateKey = this.reconstructPrivateKey({ deviceShare, serverShare });

      const results: SigningResult[] = [];

      // Perform all signing operations
      for (const operation of operations) {
        let result: SigningResult;

        switch (operation.type) {
          case 'transaction':
            result = await this.performTransactionSigning(privateKey, operation.data);
            break;
          case 'message':
            result = await this.performMessageSigning(privateKey, operation.data);
            break;
          case 'typedData':
            const { domain, types, value } = operation.data;
            result = await this.performTypedDataSigning(privateKey, domain, types, value);
            break;
          default:
            throw new WalletError(`Unsupported operation type: ${operation.type}`, 'UNSUPPORTED_OPERATION');
        }

        results.push(result);
      }

      // Zero out key material
      this.zeroizeKeyMaterial(privateKey, deviceShare, serverShare);

      return results;
    } catch (error) {
      console.error('Batch signing failed:', error);
      
      if (error instanceof BiometricError) {
        throw error;
      }
      
      throw new WalletError('Failed to perform batch signing', 'BATCH_SIGNING_FAILED');
    }
  }

  // Private key reconstruction from shares
  private reconstructPrivateKey(options: KeyRecoveryOptions): Uint8Array {
    const { deviceShare, serverShare } = options;

    // XOR the two shares to reconstruct the private key
    // This is a simplified approach - in production, you'd use more sophisticated techniques
    if (deviceShare.length !== serverShare.length) {
      throw new WalletError('Key shares have mismatched lengths', 'INVALID_KEY_SHARES');
    }

    const privateKey = new Uint8Array(deviceShare.length);
    for (let i = 0; i < deviceShare.length; i++) {
      privateKey[i] = deviceShare[i] ^ serverShare[i];
    }

    return privateKey;
  }

  // Perform actual transaction signing
  private async performTransactionSigning(
    privateKey: Uint8Array,
    transaction: TransactionRequest
  ): Promise<SigningResult> {
    try {
      // Create the transaction hash for signing
      const transactionHash = await this.createTransactionHash(transaction);
      
      // Sign the hash (this is simplified - in production, use proper ECDSA)
      const signature = await this.signHash(privateKey, transactionHash);
      
      return {
        signature,
        messageHash: transactionHash
      };
    } catch (error) {
      console.error('Transaction signing error:', error);
      throw new WalletError('Failed to sign transaction hash', 'TRANSACTION_SIGNING_ERROR');
    }
  }

  // Perform actual message signing
  private async performMessageSigning(
    privateKey: Uint8Array,
    message: string
  ): Promise<SigningResult> {
    try {
      // Create message hash (Ethereum signed message format)
      const messageHash = await this.createMessageHash(message);
      
      // Sign the hash
      const signature = await this.signHash(privateKey, messageHash);
      
      return {
        signature,
        messageHash
      };
    } catch (error) {
      console.error('Message signing error:', error);
      throw new WalletError('Failed to sign message hash', 'MESSAGE_SIGNING_ERROR');
    }
  }

  // Perform typed data signing (EIP-712)
  private async performTypedDataSigning(
    privateKey: Uint8Array,
    domain: any,
    types: any,
    value: any
  ): Promise<SigningResult> {
    try {
      // Create EIP-712 hash
      const typedDataHash = await this.createTypedDataHash(domain, types, value);
      
      // Sign the hash
      const signature = await this.signHash(privateKey, typedDataHash);
      
      return {
        signature,
        messageHash: typedDataHash
      };
    } catch (error) {
      console.error('Typed data signing error:', error);
      throw new WalletError('Failed to sign typed data hash', 'TYPED_DATA_SIGNING_ERROR');
    }
  }

  // Create transaction hash for signing
  private async createTransactionHash(transaction: TransactionRequest): Promise<string> {
    // This is simplified - in production, use proper RLP encoding
    const txString = JSON.stringify({
      to: transaction.to,
      value: transaction.value || '0',
      data: transaction.data || '0x',
      chainId: transaction.chainId,
      gasLimit: transaction.gasLimit,
      gasPrice: transaction.gasPrice,
      nonce: transaction.nonce
    });

    return await Crypto.digestStringAsync(
      Crypto.CryptoDigestAlgorithm.SHA256,
      txString,
      { encoding: Crypto.CryptoEncoding.HEX }
    );
  }

  // Create message hash (Ethereum format)
  private async createMessageHash(message: string): Promise<string> {
    // Ethereum signed message format: \x19Ethereum Signed Message:\n{length}{message}
    const prefix = `\x19Ethereum Signed Message:\n${message.length}`;
    const fullMessage = prefix + message;

    return await Crypto.digestStringAsync(
      Crypto.CryptoDigestAlgorithm.SHA256,
      fullMessage,
      { encoding: Crypto.CryptoEncoding.HEX }
    );
  }

  // Create EIP-712 typed data hash
  private async createTypedDataHash(domain: any, types: any, value: any): Promise<string> {
    // This is simplified - in production, implement proper EIP-712 encoding
    const typedDataString = JSON.stringify({
      domain,
      types,
      value
    });

    const prefix = '\x19\x01';
    const fullMessage = prefix + typedDataString;

    return await Crypto.digestStringAsync(
      Crypto.CryptoDigestAlgorithm.SHA256,
      fullMessage,
      { encoding: Crypto.CryptoEncoding.HEX }
    );
  }

  // Sign a hash with private key
  private async signHash(privateKey: Uint8Array, hash: string): Promise<string> {
    // This is a placeholder - in production, use proper ECDSA signing
    // You'd typically use a native crypto library here
    
    const combinedData = Array.from(privateKey).concat(hash.split(''));
    const signatureHash = await Crypto.digestStringAsync(
      Crypto.CryptoDigestAlgorithm.SHA256,
      combinedData.join(''),
      { encoding: Crypto.CryptoEncoding.HEX }
    );

    // Format as Ethereum signature (v, r, s)
    return '0x' + signatureHash + '1b'; // Append recovery ID
  }

  // Securely zero out key material
  private zeroizeKeyMaterial(...arrays: Uint8Array[]): void {
    arrays.forEach(array => {
      if (array) {
        array.fill(0);
      }
    });
  }

  // Clean up expired keys from memory
  private cleanupExpiredKeys(): void {
    const now = Date.now();
    const expiredKeys: string[] = [];

    this.activeKeys.forEach((keyData, walletId) => {
      // Clean up keys older than 5 minutes
      if (now - keyData.timestamp > 5 * 60 * 1000) {
        keyData.key.fill(0); // Zero out the key
        expiredKeys.push(walletId);
      }
    });

    expiredKeys.forEach(walletId => {
      this.activeKeys.delete(walletId);
    });

    if (expiredKeys.length > 0) {
      console.log(`Cleaned up ${expiredKeys.length} expired keys`);
    }
  }

  // Get signing statistics
  getSigningStats(): { activeKeys: number; totalSigned: number } {
    return {
      activeKeys: this.activeKeys.size,
      totalSigned: 0 // Could track this if needed
    };
  }

  // Force cleanup of all active keys (for security)
  forceCleanupAllKeys(): void {
    this.activeKeys.forEach(keyData => {
      keyData.key.fill(0);
    });
    this.activeKeys.clear();
    console.log('All active keys have been cleaned up');
  }
}