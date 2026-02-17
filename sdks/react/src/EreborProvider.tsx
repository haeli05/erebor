import React, { createContext, useContext, useEffect, useState, useCallback, useRef } from 'react';
import { EreborApiClient } from './api/client';
import { EreborConfig, AuthState, EreborUser, AuthError } from './types';

interface EreborContextValue extends AuthState {
  client: EreborApiClient;
  config: EreborConfig;
  refreshUser: () => Promise<void>;
}

const EreborContext = createContext<EreborContextValue | null>(null);

export interface EreborProviderProps {
  config: EreborConfig;
  children: React.ReactNode;
}

export function EreborProvider({ config, children }: EreborProviderProps) {
  const [authState, setAuthState] = useState<AuthState>({
    ready: false,
    authenticated: false,
    user: null,
    loading: true
  });

  // Create API client instance
  const client = useRef(new EreborApiClient(config.apiUrl, config.tokenPrefix)).current;
  const refreshIntervalRef = useRef<NodeJS.Timeout>();

  const updateAuthState = useCallback((updates: Partial<AuthState>) => {
    setAuthState(prev => ({ ...prev, ...updates }));
  }, []);

  const refreshUser = useCallback(async () => {
    if (!client.isAuthenticated()) {
      updateAuthState({
        authenticated: false,
        user: null,
        loading: false
      });
      return;
    }

    try {
      updateAuthState({ loading: true });
      const user = await client.getMe();
      updateAuthState({
        authenticated: true,
        user,
        loading: false
      });
    } catch (error) {
      console.error('Failed to refresh user:', error);
      
      if (error instanceof AuthError) {
        // Clear auth state on auth errors
        updateAuthState({
          authenticated: false,
          user: null,
          loading: false
        });
      } else {
        // Keep existing state on network errors
        updateAuthState({ loading: false });
      }
    }
  }, [client, updateAuthState]);

  // Auto-refresh tokens when needed
  const checkAndRefreshTokens = useCallback(async () => {
    if (client.shouldRefreshToken()) {
      try {
        await client.refreshTokens();
        await refreshUser();
      } catch (error) {
        console.error('Token refresh failed:', error);
        updateAuthState({
          authenticated: false,
          user: null,
          loading: false
        });
      }
    }
  }, [client, refreshUser, updateAuthState]);

  // Initialize auth state on mount
  useEffect(() => {
    const initializeAuth = async () => {
      updateAuthState({ loading: true });
      
      // Check if user is already authenticated
      if (client.isAuthenticated()) {
        // Check if token needs refresh
        await checkAndRefreshTokens();
        
        // If still authenticated, fetch user
        if (client.isAuthenticated()) {
          await refreshUser();
        }
      } else {
        updateAuthState({
          ready: true,
          authenticated: false,
          user: null,
          loading: false
        });
      }

      updateAuthState({ ready: true });
    };

    initializeAuth();
  }, [client, checkAndRefreshTokens, refreshUser, updateAuthState]);

  // Set up token refresh interval
  useEffect(() => {
    if (authState.authenticated) {
      // Check tokens every minute
      refreshIntervalRef.current = setInterval(checkAndRefreshTokens, 60 * 1000);
    } else {
      if (refreshIntervalRef.current) {
        clearInterval(refreshIntervalRef.current);
        refreshIntervalRef.current = undefined;
      }
    }

    return () => {
      if (refreshIntervalRef.current) {
        clearInterval(refreshIntervalRef.current);
      }
    };
  }, [authState.authenticated, checkAndRefreshTokens]);

  // Handle page visibility changes to refresh tokens when page becomes visible
  useEffect(() => {
    const handleVisibilityChange = () => {
      if (document.visibilityState === 'visible' && authState.authenticated) {
        checkAndRefreshTokens();
      }
    };

    document.addEventListener('visibilitychange', handleVisibilityChange);
    return () => document.removeEventListener('visibilitychange', handleVisibilityChange);
  }, [authState.authenticated, checkAndRefreshTokens]);

  const contextValue: EreborContextValue = {
    ...authState,
    client,
    config,
    refreshUser
  };

  return (
    <EreborContext.Provider value={contextValue}>
      {children}
    </EreborContext.Provider>
  );
}

export function useEreborContext(): EreborContextValue {
  const context = useContext(EreborContext);
  
  if (!context) {
    throw new Error('useEreborContext must be used within an EreborProvider');
  }
  
  return context;
}