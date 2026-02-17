import React, { useState, useRef, useEffect } from 'react';
import {
  View,
  Text,
  Modal,
  TextInput,
  TouchableOpacity,
  StyleSheet,
  SafeAreaView,
  KeyboardAvoidingView,
  Platform,
  Alert,
  ActivityIndicator,
  Dimensions
} from 'react-native';
import { useErebor } from '../hooks/useErebor';
import { useBiometrics } from '../hooks/useBiometrics';
import { useDeepLink } from '../hooks/useDeepLink';
import { LoginSheetProps, LoginMethod, AppearanceConfig } from '../types';
import { AppleAuth } from '../auth/AppleAuth';
import { OAuthBrowser } from '../auth/OAuthBrowser';

const { width: screenWidth, height: screenHeight } = Dimensions.get('window');

export function LoginSheet({
  isVisible,
  onClose,
  appearance = {},
  methods = ['email', 'google', 'apple'],
  biometricAuth = true,
  autoFocusEmail = true
}: LoginSheetProps) {
  const { login, loading } = useErebor();
  const { available: biometricsAvailable, biometricType, authenticate } = useBiometrics();
  const { createOAuthRedirectUri } = useDeepLink();
  
  const [currentStep, setCurrentStep] = useState<'select' | 'email' | 'otp'>('select');
  const [email, setEmail] = useState('');
  const [otpCode, setOtpCode] = useState('');
  const [isSubmitting, setIsSubmitting] = useState(false);
  const [error, setError] = useState<string | null>(null);
  
  const emailInputRef = useRef<TextInput>(null);
  const otpInputRef = useRef<TextInput>(null);

  // Auto-focus email input when sheet opens
  useEffect(() => {
    if (isVisible && currentStep === 'email' && autoFocusEmail) {
      setTimeout(() => emailInputRef.current?.focus(), 300);
    }
  }, [isVisible, currentStep, autoFocusEmail]);

  // Reset state when sheet is closed
  useEffect(() => {
    if (!isVisible) {
      setCurrentStep('select');
      setEmail('');
      setOtpCode('');
      setError(null);
    }
  }, [isVisible]);

  const styles = createStyles(appearance);

  const handleEmailLogin = async () => {
    if (!email.trim()) {
      setError('Please enter your email address');
      return;
    }

    setIsSubmitting(true);
    setError(null);

    try {
      await login('email', { email: email.trim() });
      setCurrentStep('otp');
      setTimeout(() => otpInputRef.current?.focus(), 300);
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Failed to send verification code');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleOTPVerification = async () => {
    if (!otpCode.trim()) {
      setError('Please enter the verification code');
      return;
    }

    setIsSubmitting(true);
    setError(null);

    try {
      await login('email', { email: email.trim(), code: otpCode.trim() });
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Invalid verification code');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleGoogleLogin = async () => {
    setIsSubmitting(true);
    setError(null);

    try {
      const redirectUri = createOAuthRedirectUri();
      const oauthBrowser = new OAuthBrowser(redirectUri);
      
      // You would need to configure your Google OAuth client ID
      const result = await oauthBrowser.authenticateWithGoogle('your-google-client-id');
      
      if (result.error) {
        throw new Error(result.error_description || 'Google authentication failed');
      }

      if (result.code) {
        await login('google', { 
          code: result.code, 
          redirectUri 
        });
        onClose();
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Google sign-in failed');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleAppleLogin = async () => {
    setIsSubmitting(true);
    setError(null);

    try {
      const appleAuth = new AppleAuth('your-apple-client-id', createOAuthRedirectUri());
      const result = await appleAuth.authenticate();
      
      if ('identityToken' in result) {
        // Native Apple Sign-In result
        await login('apple', {
          identityToken: result.identityToken,
          authorizationCode: result.authorizationCode
        });
      } else {
        // Web OAuth result
        await login('apple', {
          code: result.code,
          redirectUri: createOAuthRedirectUri()
        });
      }
      
      onClose();
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Apple sign-in failed');
    } finally {
      setIsSubmitting(false);
    }
  };

  const handleBiometricLogin = async () => {
    if (!biometricsAvailable) {
      setError('Biometric authentication is not available on this device');
      return;
    }

    try {
      const success = await authenticate({
        promptMessage: 'Sign in with biometrics',
        cancelButtonTitle: 'Cancel'
      });

      if (success) {
        // In a real implementation, you'd have stored credentials to use here
        Alert.alert('Biometric Auth', 'Biometric authentication successful, but no stored credentials found');
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Biometric authentication failed');
    }
  };

  const renderMethodButton = (method: LoginMethod, title: string, onPress: () => void, icon?: string) => {
    if (!methods.includes(method)) return null;

    return (
      <TouchableOpacity
        style={styles.methodButton}
        onPress={onPress}
        disabled={isSubmitting}
      >
        <Text style={styles.methodButtonText}>{title}</Text>
      </TouchableOpacity>
    );
  };

  const renderSelectMethods = () => (
    <View style={styles.content}>
      <Text style={styles.title}>Sign In</Text>
      <Text style={styles.subtitle}>Choose your preferred sign-in method</Text>

      <View style={styles.methodsContainer}>
        {renderMethodButton('email', 'Continue with Email', () => setCurrentStep('email'))}
        {renderMethodButton('google', 'Continue with Google', handleGoogleLogin)}
        {renderMethodButton('apple', 'Continue with Apple', handleAppleLogin)}
        
        {biometricAuth && biometricsAvailable && (
          <TouchableOpacity
            style={styles.biometricButton}
            onPress={handleBiometricLogin}
            disabled={isSubmitting}
          >
            <Text style={styles.biometricButtonText}>
              Sign in with {biometricType === 'faceId' ? 'Face ID' : 
                            biometricType === 'touchId' ? 'Touch ID' : 
                            'Fingerprint'}
            </Text>
          </TouchableOpacity>
        )}
      </View>

      {error && <Text style={styles.errorText}>{error}</Text>}
    </View>
  );

  const renderEmailInput = () => (
    <View style={styles.content}>
      <Text style={styles.title}>Enter your email</Text>
      <Text style={styles.subtitle}>We'll send you a verification code</Text>

      <TextInput
        ref={emailInputRef}
        style={styles.textInput}
        placeholder="Enter your email address"
        placeholderTextColor={styles.placeholderText.color}
        value={email}
        onChangeText={setEmail}
        keyboardType="email-address"
        autoCapitalize="none"
        autoCorrect={false}
        textContentType="emailAddress"
        returnKeyType="next"
        onSubmitEditing={handleEmailLogin}
      />

      <TouchableOpacity
        style={[styles.primaryButton, isSubmitting && styles.disabledButton]}
        onPress={handleEmailLogin}
        disabled={isSubmitting || !email.trim()}
      >
        {isSubmitting ? (
          <ActivityIndicator color={styles.buttonText.color} />
        ) : (
          <Text style={styles.buttonText}>Send Code</Text>
        )}
      </TouchableOpacity>

      <TouchableOpacity
        style={styles.backButton}
        onPress={() => setCurrentStep('select')}
      >
        <Text style={styles.backButtonText}>Back</Text>
      </TouchableOpacity>

      {error && <Text style={styles.errorText}>{error}</Text>}
    </View>
  );

  const renderOTPInput = () => (
    <View style={styles.content}>
      <Text style={styles.title}>Enter verification code</Text>
      <Text style={styles.subtitle}>We sent a 6-digit code to {email}</Text>

      <TextInput
        ref={otpInputRef}
        style={styles.textInput}
        placeholder="Enter 6-digit code"
        placeholderTextColor={styles.placeholderText.color}
        value={otpCode}
        onChangeText={setOtpCode}
        keyboardType="number-pad"
        maxLength={6}
        textContentType="oneTimeCode"
        returnKeyType="done"
        onSubmitEditing={handleOTPVerification}
      />

      <TouchableOpacity
        style={[styles.primaryButton, isSubmitting && styles.disabledButton]}
        onPress={handleOTPVerification}
        disabled={isSubmitting || !otpCode.trim()}
      >
        {isSubmitting ? (
          <ActivityIndicator color={styles.buttonText.color} />
        ) : (
          <Text style={styles.buttonText}>Verify Code</Text>
        )}
      </TouchableOpacity>

      <TouchableOpacity
        style={styles.linkButton}
        onPress={() => setCurrentStep('email')}
      >
        <Text style={styles.linkButtonText}>Didn't receive code? Try again</Text>
      </TouchableOpacity>

      {error && <Text style={styles.errorText}>{error}</Text>}
    </View>
  );

  const renderContent = () => {
    switch (currentStep) {
      case 'email':
        return renderEmailInput();
      case 'otp':
        return renderOTPInput();
      default:
        return renderSelectMethods();
    }
  };

  return (
    <Modal
      visible={isVisible}
      animationType="slide"
      presentationStyle="pageSheet"
      onRequestClose={onClose}
    >
      <SafeAreaView style={styles.safeArea}>
        <KeyboardAvoidingView
          style={styles.container}
          behavior={Platform.OS === 'ios' ? 'padding' : 'height'}
        >
          <View style={styles.header}>
            <TouchableOpacity
              style={styles.closeButton}
              onPress={onClose}
            >
              <Text style={styles.closeButtonText}>✕</Text>
            </TouchableOpacity>
          </View>

          {renderContent()}
        </KeyboardAvoidingView>
      </SafeAreaView>
    </Modal>
  );
}

function createStyles(appearance: AppearanceConfig) {
  const isDark = appearance.theme === 'dark';
  const primaryColor = appearance.primaryColor || '#007AFF';

  return StyleSheet.create({
    safeArea: {
      flex: 1,
      backgroundColor: isDark ? '#000000' : '#FFFFFF',
    },
    container: {
      flex: 1,
    },
    header: {
      flexDirection: 'row',
      justifyContent: 'flex-end',
      paddingHorizontal: 20,
      paddingTop: 10,
    },
    closeButton: {
      padding: 10,
    },
    closeButtonText: {
      fontSize: 18,
      color: isDark ? '#FFFFFF' : '#000000',
    },
    content: {
      flex: 1,
      paddingHorizontal: 20,
      paddingTop: 20,
    },
    title: {
      fontSize: 24,
      fontWeight: 'bold',
      textAlign: 'center',
      marginBottom: 10,
      color: isDark ? '#FFFFFF' : '#000000',
    },
    subtitle: {
      fontSize: 16,
      textAlign: 'center',
      marginBottom: 30,
      color: isDark ? '#CCCCCC' : '#666666',
    },
    methodsContainer: {
      marginBottom: 30,
    },
    methodButton: {
      backgroundColor: isDark ? '#333333' : '#F5F5F5',
      paddingVertical: 15,
      paddingHorizontal: 20,
      borderRadius: parseInt(appearance.borderRadius || '8'),
      marginBottom: 12,
      borderWidth: 1,
      borderColor: isDark ? '#444444' : '#E5E5E5',
    },
    methodButtonText: {
      fontSize: 16,
      fontWeight: '500',
      textAlign: 'center',
      color: isDark ? '#FFFFFF' : '#000000',
    },
    biometricButton: {
      backgroundColor: primaryColor,
      paddingVertical: 15,
      paddingHorizontal: 20,
      borderRadius: parseInt(appearance.borderRadius || '8'),
      marginTop: 10,
    },
    biometricButtonText: {
      fontSize: 16,
      fontWeight: '500',
      textAlign: 'center',
      color: '#FFFFFF',
    },
    textInput: {
      backgroundColor: isDark ? '#333333' : '#F5F5F5',
      paddingVertical: 15,
      paddingHorizontal: 20,
      borderRadius: parseInt(appearance.borderRadius || '8'),
      fontSize: 16,
      marginBottom: 20,
      borderWidth: 1,
      borderColor: isDark ? '#444444' : '#E5E5E5',
      color: isDark ? '#FFFFFF' : '#000000',
    },
    placeholderText: {
      color: isDark ? '#999999' : '#666666',
    },
    primaryButton: {
      backgroundColor: primaryColor,
      paddingVertical: 15,
      paddingHorizontal: 20,
      borderRadius: parseInt(appearance.borderRadius || '8'),
      marginBottom: 20,
    },
    disabledButton: {
      opacity: 0.6,
    },
    buttonText: {
      fontSize: 16,
      fontWeight: '600',
      textAlign: 'center',
      color: '#FFFFFF',
    },
    backButton: {
      paddingVertical: 10,
    },
    backButtonText: {
      fontSize: 16,
      textAlign: 'center',
      color: primaryColor,
    },
    linkButton: {
      paddingVertical: 10,
    },
    linkButtonText: {
      fontSize: 14,
      textAlign: 'center',
      color: primaryColor,
    },
    errorText: {
      fontSize: 14,
      color: '#FF3B30',
      textAlign: 'center',
      marginTop: 10,
    },
  });
}