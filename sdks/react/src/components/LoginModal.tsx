import React, { useState, useCallback } from 'react';
import { useErebor } from '../hooks/useErebor';
import { LoginModalProps, LoginMethod, AppearanceConfig } from '../types';

const defaultAppearance: AppearanceConfig = {
  theme: 'light',
  primaryColor: '#3B82F6',
  borderRadius: '8px'
};

export function LoginModal({ 
  isOpen, 
  onClose, 
  appearance = defaultAppearance,
  methods = ['email', 'google', 'siwe']
}: LoginModalProps) {
  const { login } = useErebor();
  const [activeMethod, setActiveMethod] = useState<LoginMethod | null>(null);
  const [email, setEmail] = useState('');
  const [otpCode, setOtpCode] = useState('');
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const [otpSent, setOtpSent] = useState(false);

  const theme = appearance.theme || 'light';
  const primaryColor = appearance.primaryColor || '#3B82F6';
  const borderRadius = appearance.borderRadius || '8px';

  const styles = {
    overlay: {
      position: 'fixed' as const,
      top: 0,
      left: 0,
      right: 0,
      bottom: 0,
      backgroundColor: 'rgba(0, 0, 0, 0.5)',
      display: 'flex',
      alignItems: 'center',
      justifyContent: 'center',
      zIndex: 1000
    },
    modal: {
      backgroundColor: theme === 'dark' ? '#1F2937' : '#FFFFFF',
      color: theme === 'dark' ? '#FFFFFF' : '#000000',
      borderRadius,
      padding: '24px',
      maxWidth: '400px',
      width: '90%',
      maxHeight: '90vh',
      overflow: 'auto',
      boxShadow: '0 20px 25px -5px rgba(0, 0, 0, 0.1), 0 10px 10px -5px rgba(0, 0, 0, 0.04)'
    },
    header: {
      textAlign: 'center' as const,
      marginBottom: '24px'
    },
    title: {
      fontSize: '24px',
      fontWeight: 'bold',
      margin: '0 0 8px 0'
    },
    subtitle: {
      fontSize: '14px',
      color: theme === 'dark' ? '#9CA3AF' : '#6B7280',
      margin: 0
    },
    button: {
      width: '100%',
      padding: '12px',
      margin: '8px 0',
      borderRadius,
      border: 'none',
      fontSize: '16px',
      fontWeight: '500',
      cursor: 'pointer',
      transition: 'all 0.2s ease'
    },
    primaryButton: {
      backgroundColor: primaryColor,
      color: '#FFFFFF'
    },
    secondaryButton: {
      backgroundColor: theme === 'dark' ? '#374151' : '#F3F4F6',
      color: theme === 'dark' ? '#FFFFFF' : '#374151'
    },
    input: {
      width: '100%',
      padding: '12px',
      margin: '8px 0',
      borderRadius,
      border: `1px solid ${theme === 'dark' ? '#4B5563' : '#D1D5DB'}`,
      backgroundColor: theme === 'dark' ? '#374151' : '#FFFFFF',
      color: theme === 'dark' ? '#FFFFFF' : '#000000',
      fontSize: '16px',
      outline: 'none'
    },
    error: {
      color: '#EF4444',
      fontSize: '14px',
      margin: '8px 0',
      textAlign: 'center' as const
    },
    success: {
      color: '#10B981',
      fontSize: '14px',
      margin: '8px 0',
      textAlign: 'center' as const
    },
    backButton: {
      backgroundColor: 'transparent',
      color: primaryColor,
      border: 'none',
      fontSize: '14px',
      cursor: 'pointer',
      margin: '16px 0 0 0'
    },
    closeButton: {
      position: 'absolute' as const,
      top: '16px',
      right: '16px',
      backgroundColor: 'transparent',
      border: 'none',
      fontSize: '24px',
      cursor: 'pointer',
      color: theme === 'dark' ? '#9CA3AF' : '#6B7280'
    }
  };

  const handleClose = useCallback(() => {
    setActiveMethod(null);
    setEmail('');
    setOtpCode('');
    setError(null);
    setOtpSent(false);
    onClose();
  }, [onClose]);

  const handleEmailLogin = useCallback(async () => {
    if (!email) {
      setError('Email is required');
      return;
    }

    setLoading(true);
    setError(null);

    try {
      if (!otpSent) {
        // Send OTP
        await login('email', { email });
        setOtpSent(true);
      } else {
        // Verify OTP
        if (!otpCode) {
          setError('Verification code is required');
          return;
        }
        await login('email', { email, code: otpCode });
        handleClose();
      }
    } catch (err) {
      setError(err instanceof Error ? err.message : 'Login failed');
    } finally {
      setLoading(false);
    }
  }, [email, otpCode, otpSent, login, handleClose]);

  const handleGoogleLogin = useCallback(() => {
    const redirectUri = window.location.origin;
    const googleAuthUrl = `https://accounts.google.com/oauth/authorize?client_id=YOUR_CLIENT_ID&redirect_uri=${encodeURIComponent(redirectUri)}&response_type=code&scope=openid%20email%20profile`;
    window.location.href = googleAuthUrl;
  }, []);

  const handleSiweLogin = useCallback(() => {
    setError('Wallet connection not yet implemented');
  }, []);

  if (!isOpen) return null;

  const renderMethodSelection = () => (
    <div>
      <div style={styles.header}>
        {appearance.logo && <img src={appearance.logo} alt="Logo" style={{ height: '32px', marginBottom: '16px' }} />}
        <h2 style={styles.title}>Welcome to Erebor</h2>
        <p style={styles.subtitle}>Choose your preferred sign-in method</p>
      </div>

      {methods.includes('email') && (
        <button
          style={{ ...styles.button, ...styles.primaryButton }}
          onClick={() => setActiveMethod('email')}
        >
          Continue with Email
        </button>
      )}

      {methods.includes('google') && (
        <button
          style={{ ...styles.button, ...styles.secondaryButton }}
          onClick={() => setActiveMethod('google')}
        >
          Continue with Google
        </button>
      )}

      {methods.includes('siwe') && (
        <button
          style={{ ...styles.button, ...styles.secondaryButton }}
          onClick={() => setActiveMethod('siwe')}
        >
          Connect Wallet
        </button>
      )}

      {error && <div style={styles.error}>{error}</div>}
    </div>
  );

  const renderEmailForm = () => (
    <div>
      <div style={styles.header}>
        <h2 style={styles.title}>
          {otpSent ? 'Check your email' : 'Sign in with email'}
        </h2>
        <p style={styles.subtitle}>
          {otpSent 
            ? `We sent a verification code to ${email}`
            : 'Enter your email address to continue'
          }
        </p>
      </div>

      {!otpSent ? (
        <input
          type="email"
          placeholder="Enter your email"
          value={email}
          onChange={(e) => setEmail(e.target.value)}
          style={styles.input}
          disabled={loading}
        />
      ) : (
        <input
          type="text"
          placeholder="Enter verification code"
          value={otpCode}
          onChange={(e) => setOtpCode(e.target.value)}
          style={styles.input}
          disabled={loading}
        />
      )}

      <button
        style={{ ...styles.button, ...styles.primaryButton }}
        onClick={handleEmailLogin}
        disabled={loading}
      >
        {loading ? 'Please wait...' : otpSent ? 'Verify Code' : 'Send Code'}
      </button>

      {error && <div style={styles.error}>{error}</div>}
      {otpSent && !error && <div style={styles.success}>Verification code sent!</div>}

      <button
        style={styles.backButton}
        onClick={() => {
          setActiveMethod(null);
          setOtpSent(false);
          setEmail('');
          setOtpCode('');
          setError(null);
        }}
      >
        ← Back to methods
      </button>
    </div>
  );

  const renderGoogleFlow = () => (
    <div>
      <div style={styles.header}>
        <h2 style={styles.title}>Continue with Google</h2>
        <p style={styles.subtitle}>You'll be redirected to Google to sign in</p>
      </div>

      <button
        style={{ ...styles.button, ...styles.primaryButton }}
        onClick={handleGoogleLogin}
      >
        Open Google Sign-In
      </button>

      {error && <div style={styles.error}>{error}</div>}

      <button
        style={styles.backButton}
        onClick={() => setActiveMethod(null)}
      >
        ← Back to methods
      </button>
    </div>
  );

  const renderSiweFlow = () => (
    <div>
      <div style={styles.header}>
        <h2 style={styles.title}>Connect Wallet</h2>
        <p style={styles.subtitle}>Sign a message with your wallet to authenticate</p>
      </div>

      <button
        style={{ ...styles.button, ...styles.primaryButton }}
        onClick={handleSiweLogin}
      >
        Connect Wallet
      </button>

      {error && <div style={styles.error}>{error}</div>}

      <button
        style={styles.backButton}
        onClick={() => setActiveMethod(null)}
      >
        ← Back to methods
      </button>
    </div>
  );

  return (
    <div style={styles.overlay} onClick={handleClose}>
      <div style={{ ...styles.modal, position: 'relative' }} onClick={(e) => e.stopPropagation()}>
        <button style={styles.closeButton} onClick={handleClose}>
          ×
        </button>

        {!activeMethod && renderMethodSelection()}
        {activeMethod === 'email' && renderEmailForm()}
        {activeMethod === 'google' && renderGoogleFlow()}
        {activeMethod === 'siwe' && renderSiweFlow()}
      </div>
    </div>
  );
}