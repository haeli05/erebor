import { useState, useEffect, useCallback } from 'react';
import * as LocalAuthentication from 'expo-local-authentication';
import { Platform } from 'react-native';
import { BiometricType, BiometricAuthOptions, UseBiometricsReturn, BiometricError } from '../types';

export function useBiometrics(): UseBiometricsReturn {
  const [available, setAvailable] = useState<boolean>(false);
  const [biometricType, setBiometricType] = useState<BiometricType>('none');
  const [isAuthenticated, setIsAuthenticated] = useState<boolean>(false);

  // Check biometric availability and type on mount
  useEffect(() => {
    const checkBiometricAvailability = async () => {
      try {
        const hasHardware = await LocalAuthentication.hasHardwareAsync();
        const isEnrolled = await LocalAuthentication.isEnrolledAsync();
        
        setAvailable(hasHardware && isEnrolled);
        
        if (hasHardware && isEnrolled) {
          const supportedTypes = await LocalAuthentication.supportedAuthenticationTypesAsync();
          setBiometricType(mapBiometricType(supportedTypes));
        } else {
          setBiometricType('none');
        }
      } catch (error) {
        console.warn('Failed to check biometric availability:', error);
        setAvailable(false);
        setBiometricType('none');
      }
    };

    checkBiometricAvailability();
  }, []);

  const mapBiometricType = (types: LocalAuthentication.AuthenticationType[]): BiometricType => {
    if (types.includes(LocalAuthentication.AuthenticationType.FACIAL_RECOGNITION)) {
      return Platform.OS === 'ios' ? 'faceId' : 'fingerprint';
    }
    if (types.includes(LocalAuthentication.AuthenticationType.FINGERPRINT)) {
      return Platform.OS === 'ios' ? 'touchId' : 'fingerprint';
    }
    return 'none';
  };

  const authenticate = useCallback(async (options: BiometricAuthOptions = {}): Promise<boolean> => {
    if (!available) {
      throw new BiometricError('Biometric authentication not available', 'BIOMETRIC_UNAVAILABLE');
    }

    try {
      const authOptions: LocalAuthentication.LocalAuthenticationOptions = {
        promptMessage: options.promptMessage || 'Authenticate to continue',
        fallbackLabel: options.fallbackPrompt || 'Use Passcode',
        disableDeviceFallback: options.disableDeviceFallback || false,
        cancelLabel: options.cancelButtonTitle || 'Cancel',
      };

      const result = await LocalAuthentication.authenticateAsync(authOptions);
      
      if (result.success) {
        setIsAuthenticated(true);
        // Reset authentication state after a timeout for security
        setTimeout(() => setIsAuthenticated(false), 5 * 60 * 1000); // 5 minutes
        return true;
      } else {
        setIsAuthenticated(false);
        
        // Handle different error cases
        if (result.error === 'user_cancel') {
          throw new BiometricError('Authentication cancelled by user', 'USER_CANCELLED');
        }
        if (result.error === 'user_fallback') {
          throw new BiometricError('User chose fallback authentication', 'USER_FALLBACK');
        }
        if (result.error === 'system_cancel') {
          throw new BiometricError('Authentication cancelled by system', 'SYSTEM_CANCELLED');
        }
        if (result.error === 'authentication_failed') {
          throw new BiometricError('Authentication failed', 'AUTHENTICATION_FAILED');
        }
        if (result.error === 'biometric_not_available') {
          throw new BiometricError('Biometric authentication not available', 'BIOMETRIC_UNAVAILABLE');
        }
        if (result.error === 'biometric_not_enrolled') {
          throw new BiometricError('No biometrics enrolled', 'BIOMETRIC_NOT_ENROLLED');
        }
        
        throw new BiometricError('Authentication failed', 'AUTHENTICATION_FAILED');
      }
    } catch (error) {
      setIsAuthenticated(false);
      
      if (error instanceof BiometricError) {
        throw error;
      }
      
      console.error('Biometric authentication error:', error);
      throw new BiometricError('Biometric authentication failed', 'BIOMETRIC_ERROR');
    }
  }, [available]);

  // Utility methods for different biometric types
  const authenticateWithFaceId = useCallback(async (options: BiometricAuthOptions = {}): Promise<boolean> => {
    if (biometricType !== 'faceId') {
      throw new BiometricError('Face ID not available on this device', 'FACE_ID_UNAVAILABLE');
    }
    
    return authenticate({
      promptMessage: 'Authenticate with Face ID',
      ...options
    });
  }, [biometricType, authenticate]);

  const authenticateWithTouchId = useCallback(async (options: BiometricAuthOptions = {}): Promise<boolean> => {
    if (biometricType !== 'touchId') {
      throw new BiometricError('Touch ID not available on this device', 'TOUCH_ID_UNAVAILABLE');
    }
    
    return authenticate({
      promptMessage: 'Authenticate with Touch ID',
      ...options
    });
  }, [biometricType, authenticate]);

  const authenticateWithFingerprint = useCallback(async (options: BiometricAuthOptions = {}): Promise<boolean> => {
    if (biometricType !== 'fingerprint') {
      throw new BiometricError('Fingerprint authentication not available on this device', 'FINGERPRINT_UNAVAILABLE');
    }
    
    return authenticate({
      promptMessage: 'Authenticate with Fingerprint',
      ...options
    });
  }, [biometricType, authenticate]);

  // Check if user needs to re-authenticate (after timeout)
  const needsReAuthentication = useCallback((): boolean => {
    return !isAuthenticated;
  }, [isAuthenticated]);

  // Force reset authentication state
  const resetAuthenticationState = useCallback((): void => {
    setIsAuthenticated(false);
  }, []);

  return {
    available,
    biometricType,
    authenticate,
    isAuthenticated,
    // Extended API for specific biometric types
    authenticateWithFaceId,
    authenticateWithTouchId,
    authenticateWithFingerprint,
    needsReAuthentication,
    resetAuthenticationState
  };
}