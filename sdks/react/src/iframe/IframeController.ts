import {
  IframeMessage,
  IframeMessageType,
  SignRequest,
  SignResponse,
  DeriveRequest,
  DeriveResponse,
  IframeError,
  PendingRequest,
  IframeBridgeConfig,
  DEFAULT_IFRAME_CONFIG,
  IframeErrorCodes,
  generateNonce,
  isValidIframeMessage,
  createIframeError,
  createIframeMessage
} from './protocol';

export class IframeController {
  private iframe: HTMLIFrameElement | null = null;
  private config: IframeBridgeConfig;
  private pendingRequests = new Map<string, PendingRequest>();
  private isReady = false;
  private readyPromise: Promise<void>;
  private readyResolve?: () => void;
  private messageListener?: (event: MessageEvent) => void;

  constructor(config: Partial<IframeBridgeConfig> = {}) {
    this.config = { ...DEFAULT_IFRAME_CONFIG, ...config };
    
    // Create promise that resolves when iframe is ready
    this.readyPromise = new Promise((resolve) => {
      this.readyResolve = resolve;
    });

    this.setupMessageListener();
  }

  private setupMessageListener(): void {
    this.messageListener = (event: MessageEvent) => {
      // Verify origin for security
      const vaultOrigin = new URL(this.config.vaultUrl).origin;
      if (event.origin !== vaultOrigin) {
        if (this.config.debug) {
          console.warn('Ignoring message from unauthorized origin:', event.origin);
        }
        return;
      }

      if (!isValidIframeMessage(event.data)) {
        if (this.config.debug) {
          console.warn('Ignoring invalid iframe message:', event.data);
        }
        return;
      }

      this.handleIframeMessage(event.data);
    };

    window.addEventListener('message', this.messageListener);
  }

  private handleIframeMessage(message: IframeMessage): void {
    if (this.config.debug) {
      console.log('Received iframe message:', message);
    }

    switch (message.type) {
      case 'READY':
        this.isReady = true;
        if (this.readyResolve) {
          this.readyResolve();
        }
        break;

      case 'PONG':
        // Handle ping response
        this.resolvePendingRequest(message.nonce, message.payload);
        break;

      case 'SIGN_RESPONSE':
      case 'DERIVE_RESPONSE':
        if (message.error) {
          this.rejectPendingRequest(message.nonce, new Error(message.error.message));
        } else {
          this.resolvePendingRequest(message.nonce, message.payload);
        }
        break;

      case 'ERROR':
        this.rejectPendingRequest(message.nonce, new Error(message.error?.message || 'Unknown iframe error'));
        break;

      default:
        console.warn('Unknown iframe message type:', message.type);
    }
  }

  private resolvePendingRequest(nonce: string, result: any): void {
    const request = this.pendingRequests.get(nonce);
    if (request) {
      clearTimeout(request.timeout);
      this.pendingRequests.delete(nonce);
      request.resolve(result);
    }
  }

  private rejectPendingRequest(nonce: string, error: Error): void {
    const request = this.pendingRequests.get(nonce);
    if (request) {
      clearTimeout(request.timeout);
      this.pendingRequests.delete(nonce);
      request.reject(error);
    }
  }

  private async sendMessage(
    type: IframeMessageType,
    payload: any,
    expectResponse = true
  ): Promise<any> {
    if (!this.iframe || !this.isReady) {
      throw new Error('Iframe not ready. Call initialize() first.');
    }

    const nonce = generateNonce();
    const message = createIframeMessage(type, nonce, payload);

    if (this.config.debug) {
      console.log('Sending iframe message:', message);
    }

    // Send message to iframe
    this.iframe.contentWindow?.postMessage(message, this.config.vaultUrl);

    if (!expectResponse) {
      return;
    }

    // Return promise that resolves when response is received
    return new Promise((resolve, reject) => {
      const timeout = setTimeout(() => {
        this.pendingRequests.delete(nonce);
        reject(new Error(`Request timeout after ${this.config.timeout}ms`));
      }, this.config.timeout);

      this.pendingRequests.set(nonce, {
        nonce,
        resolve,
        reject,
        timeout,
        type
      });
    });
  }

  async initialize(): Promise<void> {
    if (this.iframe) {
      return this.readyPromise;
    }

    // Create invisible iframe
    this.iframe = document.createElement('iframe');
    this.iframe.src = this.config.vaultUrl;
    this.iframe.style.display = 'none';
    this.iframe.style.position = 'absolute';
    this.iframe.style.left = '-9999px';
    this.iframe.style.width = '1px';
    this.iframe.style.height = '1px';
    
    // Add to DOM
    document.body.appendChild(this.iframe);

    // Wait for iframe to load and signal ready
    const readyTimeout = setTimeout(() => {
      if (this.readyResolve) {
        this.readyResolve = undefined;
      }
      throw new Error('Iframe failed to initialize within timeout');
    }, this.config.timeout);

    try {
      await this.readyPromise;
      clearTimeout(readyTimeout);
    } catch (error) {
      clearTimeout(readyTimeout);
      this.destroy();
      throw error;
    }
  }

  async ping(): Promise<boolean> {
    try {
      await this.sendMessage('PING', {});
      return true;
    } catch (error) {
      if (this.config.debug) {
        console.error('Ping failed:', error);
      }
      return false;
    }
  }

  async signInIframe(share: string, message: string, walletId: string): Promise<string> {
    if (!share || !message || !walletId) {
      throw new Error('Share, message, and walletId are required for signing');
    }

    const request: SignRequest = { share, message, walletId };
    
    try {
      const response: SignResponse = await this.sendMessage('SIGN_REQUEST', request);
      return response.signature;
    } catch (error) {
      if (this.config.debug) {
        console.error('Iframe signing failed:', error);
      }
      throw error;
    }
  }

  async deriveInIframe(share: string, path: string, chainId?: number): Promise<DeriveResponse> {
    if (!share || !path) {
      throw new Error('Share and derivation path are required');
    }

    const request: DeriveRequest = { share, path, chainId };
    
    try {
      const response: DeriveResponse = await this.sendMessage('DERIVE_REQUEST', request);
      return response;
    } catch (error) {
      if (this.config.debug) {
        console.error('Iframe derivation failed:', error);
      }
      throw error;
    }
  }

  isInitialized(): boolean {
    return this.isReady && !!this.iframe;
  }

  destroy(): void {
    // Clean up message listener
    if (this.messageListener) {
      window.removeEventListener('message', this.messageListener);
      this.messageListener = undefined;
    }

    // Clean up pending requests
    this.pendingRequests.forEach((request) => {
      clearTimeout(request.timeout);
      request.reject(new Error('IframeController destroyed'));
    });
    this.pendingRequests.clear();

    // Remove iframe from DOM
    if (this.iframe && this.iframe.parentNode) {
      this.iframe.parentNode.removeChild(this.iframe);
    }
    
    this.iframe = null;
    this.isReady = false;
    this.readyResolve = undefined;
  }

  // Configuration getters
  getConfig(): IframeBridgeConfig {
    return { ...this.config };
  }

  updateConfig(newConfig: Partial<IframeBridgeConfig>): void {
    this.config = { ...this.config, ...newConfig };
  }
}