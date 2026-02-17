import { useCallback, useState } from 'react';
import { useEreborContext } from '../EreborProvider';
import { LoginMethod, MobileLoginParams, UseEreborReturn, AuthError } from '../types';

export function useErebor(): UseEreborReturn {
  const { user, ready, authenticated, loading, client, refreshUser } = useEreborContext();
  const [loginLoading, setLoginLoading] = useState(false);

  const login = useCallback(async (method: LoginMethod, params: MobileLoginParams = {}) => {
    setLoginLoading(true);
    
    try {
      switch (method) {
        case 'email':
          if (!params.code) {
            // First step: send OTP
            if (!params.email) {
              throw new AuthError('Email is required for email login', 'MISSING_EMAIL');
            }
            await client.sendEmailOtp(params.email);
            // Don't refresh user yet, wait for OTP verification
            return;
          } else {
            // Second step: verify OTP
            if (!params.email) {
              throw new AuthError('Email is required for OTP verification', 'MISSING_EMAIL');
            }
            await client.verifyEmailOtp(params.email, params.code);
          }
          break;

        case 'google':
          if (!params.code || !params.redirectUri) {
            throw new AuthError('Authorization code and redirect URI are required for Google login', 'MISSING_GOOGLE_PARAMS');
          }
          await client.googleAuth(params.code, params.redirectUri);
          break;

        case 'apple':
          if (!params.identityToken || !params.authorizationCode) {
            throw new AuthError('Identity token and authorization code are required for Apple login', 'MISSING_APPLE_PARAMS');
          }
          await client.appleAuth(params.identityToken, params.authorizationCode, params.nonce);
          break;

        case 'siwe':
          if (!params.message || !params.signature) {
            throw new AuthError('Message and signature are required for SIWE login', 'MISSING_SIWE_PARAMS');
          }
          await client.verifySiwe(params.message, params.signature);
          break;

        default:
          throw new AuthError(`Login method "${method}" is not yet supported`, 'UNSUPPORTED_METHOD');
      }

      // After successful auth, refresh user data
      await refreshUser();
    } catch (error) {
      console.error(`Login failed for method ${method}:`, error);
      throw error;
    } finally {
      setLoginLoading(false);
    }
  }, [client, refreshUser]);

  const logout = useCallback(async () => {
    try {
      await client.logout();
      await refreshUser(); // This will clear the user state
    } catch (error) {
      console.error('Logout failed:', error);
      // Force clear state even if logout API call fails
      await refreshUser();
    }
  }, [client, refreshUser]);

  return {
    user,
    ready,
    authenticated,
    loading: loading || loginLoading,
    login,
    logout
  };
}