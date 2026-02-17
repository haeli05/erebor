import React, { createContext, useContext, useEffect, useState, ReactNode, useCallback } from 'react';
import { AppState, AppStateStatus } from 'react-native';
import { MobileEreborApiClient } from './api/client';
import { 
  MobileEreborConfig, 
  EreborUser, 
  AuthState,
  NetworkInfo 
} from './types';

interface EreborContextValue extends AuthState {
  client: MobileEreborApiClient;
  refreshUser: () => Promise<void>;
  config: MobileEreborConfig;
  networkInfo: NetworkInfo;
}

const EreborContext = createContext<EreborContextValue | undefined>(undefined);

interface EreborProviderProps {
  config: MobileEreborConfig;
  children: ReactNode;
  onAuthStateChange?: (state: AuthState) => void;
  onNetworkChange?: (networkInfo: NetworkInfo) => void;
}

export function EreborProvider({ 
  config, 
  children, 
  onAuthStateChange,
  onNetworkChange 
}: EreborProviderProps) {
  const [ready, setReady] = useState(false);
  const [authenticated, setAuthenticated] = useState(false);
  const [user, setUser] = useState<EreborUser | null>(null);
  const [loading, setLoading] = useState(true);
  const [client] = useState(() => new MobileEreborApiClient({
    apiUrl: config.apiUrl,
    tokenPrefix: config.tokenPrefix,
    networkTimeout: config.networkTimeout,
    secureStorage: config.secureStorage,
    sslPinning: config.sslPinning
  }));

  // Network monitoring
  const [networkInfo, setNetworkInfo] = useState<NetworkInfo>({
    isConnected: false,
    connectionType: 'none'
  });

  const refreshUser = useCallback(async () => {
    try {
      const isAuth = await client.isAuthenticated();
      
      if (isAuth) {
        const userData = await client.getMe();
        setUser(userData);
        setAuthenticated(true);
      } else {
        setUser(null);
        setAuthenticated(false);
      }
    } catch (error) {
      console.error('Failed to refresh user:', error);
      setUser(null);
      setAuthenticated(false);
      
      // Clear tokens if there's an auth error
      if (error.code === 'AUTH_REQUIRED' || error.code === 'SESSION_EXPIRED') {
        try {
          await client.clearTokens();
        } catch (clearError) {
          console.warn('Failed to clear tokens:', clearError);
        }
      }
    }
  }, [client]);

  // Initialize the provider
  useEffect(() => {
    const initialize = async () => {
      try {
        setLoading(true);
        
        // Get initial network info
        const initialNetworkInfo = client.getNetworkInfo();
        setNetworkInfo(initialNetworkInfo);
        
        // Check if we have stored authentication
        const hasTokens = await client.isAuthenticated();
        
        if (hasTokens) {
          // Try to refresh token if needed
          if (await client.shouldRefreshToken()) {
            try {
              await client.refreshTokens();
            } catch (refreshError) {
              console.warn('Token refresh failed during initialization:', refreshError);
              await client.clearTokens();
            }
          }
          
          // Load user data
          await refreshUser();
        }
      } catch (error) {
        console.error('Erebor initialization failed:', error);
        setUser(null);
        setAuthenticated(false);
      } finally {
        setLoading(false);
        setReady(true);
      }
    };

    initialize();
  }, [client, refreshUser]);

  // Monitor app state changes for token refresh
  useEffect(() => {
    const handleAppStateChange = async (nextAppState: AppStateStatus) => {
      // When app comes to foreground, check if we need to refresh tokens
      if (nextAppState === 'active' && authenticated) {
        try {
          if (await client.shouldRefreshToken()) {
            await client.refreshTokens();
          }
          
          // Refresh user data to ensure it's current
          await refreshUser();
        } catch (error) {
          console.warn('Failed to refresh on app state change:', error);
          
          // If refresh fails, check authentication status
          if (error.code === 'SESSION_EXPIRED' || error.code === 'AUTH_REQUIRED') {
            await refreshUser();
          }
        }
      }
    };

    const subscription = AppState.addEventListener('change', handleAppStateChange);
    return () => subscription?.remove();
  }, [authenticated, client, refreshUser]);

  // Monitor network changes
  useEffect(() => {
    const updateNetworkInfo = () => {
      const currentNetworkInfo = client.getNetworkInfo();
      setNetworkInfo(currentNetworkInfo);
      onNetworkChange?.(currentNetworkInfo);
    };

    // Update network info periodically
    const networkInterval = setInterval(updateNetworkInfo, 5000);
    
    return () => clearInterval(networkInterval);
  }, [client, onNetworkChange]);

  // Call auth state change callback when state changes
  useEffect(() => {
    if (ready) {
      const authState: AuthState = {
        ready,
        authenticated,
        user,
        loading
      };
      onAuthStateChange?.(authState);
    }
  }, [ready, authenticated, user, loading, onAuthStateChange]);

  // Context value
  const contextValue: EreborContextValue = {
    ready,
    authenticated,
    user,
    loading,
    client,
    refreshUser,
    config,
    networkInfo
  };

  return (
    <EreborContext.Provider value={contextValue}>
      {children}
    </EreborContext.Provider>
  );
}

export function useEreborContext(): EreborContextValue {
  const context = useContext(EreborContext);
  if (context === undefined) {
    throw new Error('useEreborContext must be used within an EreborProvider');
  }
  return context;
}