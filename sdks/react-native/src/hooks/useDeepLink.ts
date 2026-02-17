import { useCallback, useEffect, useRef } from 'react';
import { Linking } from 'react-native';
import { useEreborContext } from '../EreborProvider';
import { UseDeepLinkReturn, DeepLinkError } from '../types';

export function useDeepLink(): UseDeepLinkReturn {
  const { config, refreshUser } = useEreborContext();
  const listeners = useRef<((url: string) => void)[]>([]);

  // Extract parameters from URL
  const parseDeepLinkUrl = useCallback((url: string) => {
    try {
      const urlObj = new URL(url);
      const params = new URLSearchParams(urlObj.search);
      
      return {
        scheme: urlObj.protocol.replace(':', ''),
        host: urlObj.hostname,
        path: urlObj.pathname,
        params: Object.fromEntries(params.entries())
      };
    } catch (error) {
      throw new DeepLinkError(`Invalid deep link URL: ${url}`, 'INVALID_URL');
    }
  }, []);

  // Validate that the deep link matches our app's scheme
  const validateDeepLink = useCallback((url: string): boolean => {
    if (!config.deepLink) {
      return false;
    }

    const parsed = parseDeepLinkUrl(url);
    
    // Check scheme matches
    if (parsed.scheme !== config.deepLink.scheme) {
      return false;
    }

    // Check host if specified
    if (config.deepLink.host && parsed.host !== config.deepLink.host) {
      return false;
    }

    // Check path prefix if specified
    if (config.deepLink.pathPrefix && !parsed.path.startsWith(config.deepLink.pathPrefix)) {
      return false;
    }

    return true;
  }, [config.deepLink, parseDeepLinkUrl]);

  // Handle OAuth callback
  const handleOAuthCallback = useCallback(async (url: string): Promise<boolean> => {
    const parsed = parseDeepLinkUrl(url);
    
    // Check if this is an OAuth callback
    if (parsed.path.includes('/callback') || parsed.path.includes('/auth')) {
      const { code, state, error, error_description } = parsed.params;
      
      // Handle OAuth error
      if (error) {
        throw new DeepLinkError(
          error_description || `OAuth error: ${error}`,
          'OAUTH_ERROR'
        );
      }

      // Handle successful OAuth callback
      if (code) {
        try {
          // The actual OAuth handling should be done by the calling component
          // This hook just validates and extracts the parameters
          console.log('OAuth callback received:', { code, state });
          
          // Refresh user data after successful OAuth
          await refreshUser();
          
          return true;
        } catch (error) {
          throw new DeepLinkError(
            `Failed to process OAuth callback: ${error.message}`,
            'OAUTH_PROCESSING_ERROR'
          );
        }
      }
    }

    return false;
  }, [parseDeepLinkUrl, refreshUser]);

  // Main deep link handler
  const handleDeepLink = useCallback(async (url: string): Promise<boolean> => {
    try {
      // Validate the deep link
      if (!validateDeepLink(url)) {
        throw new DeepLinkError('Deep link does not match app configuration', 'INVALID_DEEP_LINK');
      }

      // Notify all registered listeners
      listeners.current.forEach(listener => {
        try {
          listener(url);
        } catch (error) {
          console.warn('Deep link listener error:', error);
        }
      });

      // Handle OAuth callbacks
      const isOAuthCallback = await handleOAuthCallback(url);
      if (isOAuthCallback) {
        return true;
      }

      // Handle other deep link types here in the future
      // For now, we only handle OAuth callbacks
      
      return true;
    } catch (error) {
      console.error('Deep link handling failed:', error);
      
      if (error instanceof DeepLinkError) {
        throw error;
      }
      
      throw new DeepLinkError(
        `Failed to handle deep link: ${error.message}`,
        'DEEP_LINK_ERROR'
      );
    }
  }, [validateDeepLink, handleOAuthCallback]);

  // Register a deep link listener
  const registerDeepLinkListener = useCallback((callback: (url: string) => void): () => void => {
    listeners.current.push(callback);
    
    // Return unregister function
    return () => {
      const index = listeners.current.indexOf(callback);
      if (index > -1) {
        listeners.current.splice(index, 1);
      }
    };
  }, []);

  // Set up initial deep link handling
  useEffect(() => {
    // Handle deep link when app is opened from closed state
    const getInitialUrl = async () => {
      try {
        const initialUrl = await Linking.getInitialURL();
        if (initialUrl) {
          // Small delay to ensure the app is fully initialized
          setTimeout(() => {
            handleDeepLink(initialUrl).catch(error => {
              console.error('Failed to handle initial deep link:', error);
            });
          }, 1000);
        }
      } catch (error) {
        console.warn('Failed to get initial URL:', error);
      }
    };

    getInitialUrl();

    // Handle deep link when app is already running
    const linkingSubscription = Linking.addEventListener('url', (event) => {
      handleDeepLink(event.url).catch(error => {
        console.error('Failed to handle deep link:', error);
      });
    });

    return () => {
      linkingSubscription?.remove();
    };
  }, [handleDeepLink]);

  // Utility functions for specific deep link operations
  const createOAuthRedirectUri = useCallback((): string => {
    if (!config.deepLink) {
      throw new DeepLinkError('Deep link configuration not provided', 'MISSING_CONFIG');
    }

    const host = config.deepLink.host || 'auth';
    const pathPrefix = config.deepLink.pathPrefix || '';
    return `${config.deepLink.scheme}://${host}${pathPrefix}/callback`;
  }, [config.deepLink]);

  const extractOAuthParams = useCallback((url: string) => {
    const parsed = parseDeepLinkUrl(url);
    return {
      code: parsed.params.code,
      state: parsed.params.state,
      error: parsed.params.error,
      errorDescription: parsed.params.error_description
    };
  }, [parseDeepLinkUrl]);

  return {
    handleDeepLink,
    registerDeepLinkListener,
    createOAuthRedirectUri,
    extractOAuthParams
  };
}