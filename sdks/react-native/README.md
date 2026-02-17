# @erebor/react-native

React Native SDK for Erebor — self-custodial wallet infrastructure on mobile. A drop-in alternative to `@privy-io/react-auth` with enhanced security, biometric authentication, and mobile-optimized UI components.

## Features

✨ **Mobile-Native Security**
- Secure token storage with expo-secure-store
- Biometric authentication (Face ID, Touch ID, Fingerprint)
- Device-side key share management
- SSL pinning and network security

🔐 **Self-Custodial Wallets**
- Client-side key generation and signing
- Multi-signature wallet support
- Hardware-backed key storage
- Automatic key rotation and backup

📱 **Mobile-Optimized UI**
- Native bottom sheet components
- Haptic feedback and animations
- Dark/light theme support
- Accessibility compliance

🌐 **Cross-Platform OAuth**
- Deep link handling for redirects
- Native Apple Sign-In (iOS)
- System browser integration
- PKCE security flow

## Installation

```bash
# Install the SDK
npm install @erebor/react-native

# Install peer dependencies
npx expo install expo-secure-store expo-web-browser expo-crypto expo-local-authentication expo-apple-authentication
npm install @react-native-async-storage/async-storage @react-native-community/netinfo
```

## Expo Configuration

Add deep link scheme to your `app.json`:

```json
{
  "expo": {
    "name": "Your App",
    "scheme": "yourapp",
    "ios": {
      "bundleIdentifier": "com.yourcompany.yourapp",
      "infoPlist": {
        "NSFaceIDUsageDescription": "Use Face ID to secure your wallet"
      }
    },
    "android": {
      "package": "com.yourcompany.yourapp",
      "permissions": [
        "USE_BIOMETRIC",
        "USE_FINGERPRINT"
      ]
    }
  }
}
```

## Quick Start

### 1. Wrap your app with EreborProvider

```tsx
import { EreborProvider } from '@erebor/react-native';

export default function App() {
  return (
    <EreborProvider
      config={{
        apiUrl: 'https://api.erebor.xyz',
        appId: 'your-app-id',
        loginMethods: ['email', 'google', 'apple'],
        chains: [
          { id: 1, name: 'Ethereum', rpcUrl: 'https://eth.llamarpc.com' },
          { id: 10, name: 'Optimism', rpcUrl: 'https://mainnet.optimism.io' }
        ],
        deepLink: {
          scheme: 'yourapp',
          host: 'auth'
        },
        secureStorage: {
          useSecureStore: true,
          biometricProtection: true
        },
        biometricAuth: true
      }}
    >
      <YourApp />
    </EreborProvider>
  );
}
```

### 2. Use the auth hook

```tsx
import { useErebor } from '@erebor/react-native';
import { View, Text, TouchableOpacity } from 'react-native';

function YourApp() {
  const { user, authenticated, login, logout, loading } = useErebor();

  if (loading) {
    return <Text>Loading...</Text>;
  }

  if (!authenticated) {
    return (
      <View>
        <TouchableOpacity onPress={() => login('email', { email: 'user@example.com' })}>
          <Text>Sign In with Email</Text>
        </TouchableOpacity>
        <TouchableOpacity onPress={() => login('apple')}>
          <Text>Sign In with Apple</Text>
        </TouchableOpacity>
      </View>
    );
  }

  return (
    <View>
      <Text>Welcome, {user?.email}!</Text>
      <TouchableOpacity onPress={logout}>
        <Text>Sign Out</Text>
      </TouchableOpacity>
    </View>
  );
}
```

### 3. Or use the pre-built components

```tsx
import { useState } from 'react';
import { LoginSheet, WalletCard, TransactionSheet } from '@erebor/react-native';
import { useWallets, useSendTransaction } from '@erebor/react-native';

function WalletScreen() {
  const [showLogin, setShowLogin] = useState(false);
  const [showTx, setShowTx] = useState(false);
  const { wallets, activeWallet } = useWallets();
  const { sendTransaction } = useSendTransaction();

  const handleSendTransaction = async () => {
    await sendTransaction({
      to: '0x742d35Cc...',
      value: '1000000000000000000', // 1 ETH
      chainId: 1
    });
  };

  return (
    <View>
      {wallets.map(wallet => (
        <WalletCard 
          key={wallet.id}
          wallet={wallet}
          onPress={() => console.log('Wallet pressed')}
          showBalance={true}
        />
      ))}

      <LoginSheet 
        isVisible={showLogin} 
        onClose={() => setShowLogin(false)}
        biometricAuth={true}
      />

      <TransactionSheet
        isVisible={showTx}
        transaction={{
          to: '0x742d35Cc...',
          value: '1000000000000000000',
          chainId: 1
        }}
        onConfirm={handleSendTransaction}
        onCancel={() => setShowTx(false)}
        biometricRequired={true}
      />
    </View>
  );
}
```

## Privy Migration

**Migrating from Privy React Native? It's a single import change!**

```tsx
// Before (Privy)
import { usePrivy } from '@privy-io/react-auth';

// After (Erebor)
import { usePrivy } from '@erebor/react-native';

// Your existing code works unchanged!
const { user, login, logout, createWallet, signMessage } = usePrivy();
```

Our `usePrivy` hook provides 100% API compatibility with Privy's React Native interface.

## API Reference

### EreborProvider

```tsx
interface MobileEreborConfig {
  apiUrl: string;              // Your Erebor API endpoint
  appId: string;               // Your application ID
  loginMethods: LoginMethod[]; // ['email', 'google', 'apple', 'siwe']
  chains?: Chain[];            // Supported blockchains
  deepLink?: {                 // Deep link configuration
    scheme: string;            // 'yourapp'
    host?: string;             // 'auth' (default)
    pathPrefix?: string;       // '' (default)
  };
  secureStorage?: {            // Storage security settings
    useSecureStore: boolean;   // true (default)
    biometricProtection: boolean; // false (default)
    fallbackToAsyncStorage: boolean; // true (default)
  };
  biometricAuth?: boolean;     // Enable biometric flows
  networkTimeout?: number;     // Request timeout (30s default)
  appearance?: {               // UI customization
    theme?: 'light' | 'dark';
    primaryColor?: string;
    borderRadius?: string;
  };
}
```

### Hooks

#### useErebor()

Main authentication hook:

```tsx
const {
  user,          // Current user or null
  ready,         // SDK initialization complete
  authenticated, // User is signed in
  loading,       // Operation in progress
  login,         // (method, params?) => Promise<void>
  logout         // () => Promise<void>
} = useErebor();
```

**Login Methods:**
```tsx
// Email OTP (2-step process)
await login('email', { email: 'user@example.com' });
await login('email', { email: 'user@example.com', code: '123456' });

// Apple Sign-In (native on iOS, web on Android)
await login('apple');

// Google OAuth (system browser)
await login('google');

// Sign-in with Ethereum (wallet connect)
await login('siwe', { message, signature });
```

#### useWallets()

Wallet management:

```tsx
const {
  wallets,        // User's wallets
  activeWallet,   // Currently selected wallet
  createWallet,   // (chainId?) => Promise<Wallet>
  setActiveWallet,// (wallet) => void
  loading,
  error
} = useWallets();
```

#### useBiometrics()

Mobile biometric authentication:

```tsx
const {
  available,      // Biometrics available on device
  biometricType,  // 'faceId' | 'touchId' | 'fingerprint' | 'none'
  authenticate,   // (options?) => Promise<boolean>
  isAuthenticated // Current auth state
} = useBiometrics();

// Authenticate with custom prompt
const success = await authenticate({
  promptMessage: 'Sign transaction with Face ID',
  cancelButtonTitle: 'Cancel',
  fallbackPrompt: 'Use Passcode'
});
```

#### useDeepLink()

Handle OAuth redirects and deep links:

```tsx
const {
  handleDeepLink,           // (url) => Promise<boolean>
  registerDeepLinkListener, // (callback) => unsubscribe function
  createOAuthRedirectUri,   // () => string
  extractOAuthParams        // (url) => { code, state, error }
} = useDeepLink();
```

#### useSignMessage()

Message signing with biometric protection:

```tsx
const {
  signMessage, // (message, walletId?, requireBiometric?) => Promise<signature>
  loading,
  error
} = useSignMessage();

// Sign with biometric confirmation
const signature = await signMessage(
  'Hello, World!',
  walletId,
  true // require biometric auth
);
```

#### useSendTransaction()

Transaction sending with confirmation UI:

```tsx
const {
  sendTransaction, // (tx, walletId?, options?) => Promise<txHash>
  loading,
  error,
  txHash
} = useSendTransaction();

// Send with biometric confirmation
const hash = await sendTransaction(
  {
    to: '0x742d35Cc...',
    value: '1000000000000000000',
    chainId: 1
  },
  walletId,
  {
    biometricRequired: true,
    confirmationMessage: 'Send 1 ETH to recipient'
  }
);
```

### Components

#### LoginSheet

Native modal with authentication methods:

```tsx
<LoginSheet
  isVisible={boolean}
  onClose={() => void}
  appearance={{
    theme: 'dark',
    primaryColor: '#6366F1'
  }}
  methods={['email', 'apple', 'google']}
  biometricAuth={true}
  autoFocusEmail={true}
/>
```

Features:
- Email OTP flow with native keyboard
- Apple Sign-In (native on iOS)
- Google OAuth with system browser
- Biometric quick login
- Dark/light theme support
- Haptic feedback

#### WalletCard

Display wallet information with native interactions:

```tsx
<WalletCard
  wallet={walletObject}
  onPress={(wallet) => handleWalletPress(wallet)}
  showBalance={true}
  appearance={{ theme: 'dark' }}
  style={{ marginVertical: 8 }}
/>
```

Features:
- Address truncation and copy-to-clipboard
- Chain badge and wallet type indicator
- Balance display (when available)
- Haptic feedback on interactions
- Native styling with shadows

#### TransactionSheet

Transaction confirmation with security features:

```tsx
<TransactionSheet
  isVisible={boolean}
  transaction={{
    to: '0x...',
    value: '1000000000000000000',
    chainId: 1
  }}
  onConfirm={handleConfirm}
  onCancel={handleCancel}
  biometricRequired={true}
  appearance={{ theme: 'dark' }}
/>
```

Features:
- Detailed transaction breakdown
- Security warnings for high-value transactions
- Biometric confirmation flow
- Gas estimation and formatting
- Native bottom sheet presentation

## Authentication Methods

### Email OTP

Two-step email verification:

```tsx
// Step 1: Send verification code
await login('email', { email: 'user@example.com' });

// Step 2: Verify code
await login('email', { 
  email: 'user@example.com', 
  code: '123456' 
});
```

### Apple Sign-In

Native integration with fallback:

```tsx
// Automatic platform detection
await login('apple');

// Manual configuration
const appleAuth = new AppleAuth('your-client-id', redirectUri);
const result = await appleAuth.authenticate({
  requestedScopes: ['email', 'fullName']
});
```

iOS: Uses `expo-apple-authentication` for native Sign in with Apple
Android: Falls back to web-based Apple OAuth

### Google OAuth

System browser with PKCE security:

```tsx
await login('google');

// Manual OAuth flow
const oauth = new OAuthBrowser(redirectUri);
const result = await oauth.authenticateWithGoogle('your-client-id', {
  useSystemBrowser: true,
  additionalScopes: ['profile']
});
```

### Sign-in with Ethereum (SIWE)

Wallet-based authentication:

```tsx
// Get challenge nonce
const nonce = await client.getSiweNonce();

// Create and sign SIWE message (using external wallet)
const message = createSiweMessage({ nonce, address, chainId });
const signature = await externalWallet.signMessage(message);

// Authenticate
await login('siwe', { message, signature });
```

## Biometric Authentication

### Setup

Configure biometric prompts in your app:

```tsx
const { authenticate, biometricType } = useBiometrics();

const handleSecureAction = async () => {
  try {
    const success = await authenticate({
      promptMessage: `Use ${biometricType} to confirm`,
      fallbackPrompt: 'Use device passcode',
      cancelButtonTitle: 'Cancel'
    });
    
    if (success) {
      // Perform secure action
    }
  } catch (error) {
    if (error.code === 'USER_CANCELLED') {
      // Handle cancellation
    }
  }
};
```

### Integration with Transactions

Automatic biometric gates before sensitive operations:

```tsx
const { sendTransaction } = useSendTransaction();

// Biometric auth is automatic if configured
await sendTransaction(transaction, walletId, {
  biometricRequired: true,
  confirmationMessage: 'Confirm transaction with biometrics'
});
```

## Security Model

### Token Storage

- **Primary**: expo-secure-store with optional biometric protection
- **Fallback**: AsyncStorage with encryption
- **Features**: Automatic token rotation, secure cleanup, key isolation

### Key Management

- **Device Share**: Stored in secure enclave with biometric gating
- **Server Share**: Retrieved securely from Erebor API
- **Reconstruction**: Performed in memory, immediately zeroized
- **Backup**: Encrypted QR codes or cloud keychain integration

### Network Security

- **SSL Pinning**: Certificate validation for API calls
- **Request Signing**: Cryptographic request authentication
- **Timeout Handling**: Prevents hanging network operations
- **Retry Logic**: Exponential backoff with jitter

## Deep Link Configuration

### Setup

Configure your app's URL scheme:

```json
// app.json
{
  "expo": {
    "scheme": "yourapp",
    "ios": {
      "associatedDomains": ["applinks:yourapp.com"]
    },
    "android": {
      "intentFilters": [
        {
          "action": "VIEW",
          "data": {
            "scheme": "yourapp"
          },
          "category": ["BROWSABLE", "DEFAULT"]
        }
      ]
    }
  }
}
```

### OAuth Redirects

Handle authentication callbacks:

```tsx
const { handleDeepLink } = useDeepLink();

// Automatic setup in EreborProvider
// Manual handling if needed
useEffect(() => {
  const handleUrl = (url: string) => {
    handleDeepLink(url).catch(console.error);
  };

  // Handle app launch from deep link
  Linking.getInitialURL().then(url => {
    if (url) handleUrl(url);
  });

  // Handle deep links while app is running
  const subscription = Linking.addEventListener('url', ({ url }) => {
    handleUrl(url);
  });

  return () => subscription?.remove();
}, []);
```

## Platform-Specific Notes

### iOS

- Face ID/Touch ID integration via expo-local-authentication
- Native Apple Sign-In via expo-apple-authentication
- Secure Enclave storage via expo-secure-store
- App Transport Security (ATS) compliance

### Android

- Fingerprint authentication support
- System browser for OAuth flows
- Hardware-backed keystore when available
- Network security config for SSL pinning

## Advanced Usage

### Custom API Client

```tsx
import { MobileEreborApiClient } from '@erebor/react-native';

const client = new MobileEreborApiClient({
  apiUrl: 'https://api.erebor.xyz',
  secureStorage: {
    useSecureStore: true,
    biometricProtection: true
  },
  sslPinning: {
    enabled: true,
    certificates: ['sha256/AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA=']
  }
});

// Direct API calls
const user = await client.getMe();
const signature = await client.signMessage(walletId, message);
```

### Device Key Management

```tsx
import { DeviceKeyManager } from '@erebor/react-native';

const keyManager = new DeviceKeyManager({
  requireBiometrics: true,
  autoBackup: true
});

// Generate secure key share
const keyShare = await keyManager.generateKeyShare(walletId, {
  biometricProtection: true,
  derivationPath: "m/44'/60'/0'/0/0"
});

// Access key with biometric auth
const decryptedKey = await keyManager.getDecryptedKeyMaterial(
  walletId, 
  true // require biometric
);
```

### Mobile Signing

```tsx
import { MobileSigner } from '@erebor/react-native';

const signer = new MobileSigner(keyManager);

// Sign transaction with device key reconstruction
const signature = await signer.signTransaction(
  walletId,
  transaction,
  serverKeyShare,
  {
    requireBiometric: true,
    autoZeroize: true
  }
);
```

## Error Handling

```tsx
import { 
  AuthError, 
  WalletError, 
  BiometricError, 
  NetworkError 
} from '@erebor/react-native';

try {
  await login('apple');
} catch (error) {
  if (error instanceof BiometricError) {
    if (error.code === 'USER_CANCELLED') {
      // User cancelled biometric prompt
    } else if (error.code === 'BIOMETRIC_UNAVAILABLE') {
      // Fallback to other auth method
    }
  } else if (error instanceof NetworkError) {
    // Handle connectivity issues
  }
}
```

## TypeScript Support

Full TypeScript support with comprehensive type definitions:

```tsx
import type { 
  EreborUser, 
  EreborWallet, 
  TransactionRequest,
  BiometricType,
  MobileEreborConfig 
} from '@erebor/react-native';

const config: MobileEreborConfig = {
  apiUrl: 'https://api.erebor.xyz',
  appId: 'your-app-id',
  loginMethods: ['email', 'apple', 'google'],
  biometricAuth: true,
  deepLink: {
    scheme: 'yourapp',
    host: 'auth'
  }
};
```

## Examples

### Complete Authentication Flow

```tsx
import React, { useState } from 'react';
import { View, Text, TouchableOpacity, Alert } from 'react-native';
import { 
  EreborProvider, 
  useErebor, 
  useBiometrics, 
  LoginSheet 
} from '@erebor/react-native';

function AuthenticatedApp() {
  const { user, authenticated, logout } = useErebor();
  const { biometricType } = useBiometrics();

  return (
    <View style={{ flex: 1, justifyContent: 'center', padding: 20 }}>
      <Text style={{ fontSize: 18, marginBottom: 20 }}>
        Welcome, {user?.email}!
      </Text>
      <Text style={{ marginBottom: 20 }}>
        Protected by {biometricType === 'faceId' ? 'Face ID' : 
                      biometricType === 'touchId' ? 'Touch ID' : 
                      'Fingerprint'}
      </Text>
      <TouchableOpacity 
        onPress={logout}
        style={{ backgroundColor: '#007AFF', padding: 15, borderRadius: 8 }}
      >
        <Text style={{ color: 'white', textAlign: 'center' }}>Sign Out</Text>
      </TouchableOpacity>
    </View>
  );
}

function LoginScreen() {
  const [showLogin, setShowLogin] = useState(false);

  return (
    <View style={{ flex: 1, justifyContent: 'center', padding: 20 }}>
      <TouchableOpacity 
        onPress={() => setShowLogin(true)}
        style={{ backgroundColor: '#007AFF', padding: 15, borderRadius: 8 }}
      >
        <Text style={{ color: 'white', textAlign: 'center' }}>Sign In</Text>
      </TouchableOpacity>

      <LoginSheet 
        isVisible={showLogin} 
        onClose={() => setShowLogin(false)}
        methods={['email', 'apple', 'google']}
        biometricAuth={true}
        appearance={{ theme: 'dark' }}
      />
    </View>
  );
}

function AppContent() {
  const { authenticated, loading } = useErebor();

  if (loading) {
    return (
      <View style={{ flex: 1, justifyContent: 'center', alignItems: 'center' }}>
        <Text>Loading...</Text>
      </View>
    );
  }

  return authenticated ? <AuthenticatedApp /> : <LoginScreen />;
}

export default function App() {
  return (
    <EreborProvider
      config={{
        apiUrl: 'https://api.erebor.xyz',
        appId: 'your-app-id',
        loginMethods: ['email', 'apple', 'google'],
        deepLink: { scheme: 'yourapp' },
        secureStorage: { 
          useSecureStore: true, 
          biometricProtection: true 
        },
        biometricAuth: true,
        appearance: { theme: 'dark' }
      }}
    >
      <AppContent />
    </EreborProvider>
  );
}
```

### Wallet Management Screen

```tsx
import React, { useState } from 'react';
import { View, ScrollView, TouchableOpacity, Text, Alert } from 'react-native';
import { 
  useWallets, 
  useSendTransaction, 
  WalletCard, 
  TransactionSheet 
} from '@erebor/react-native';

export function WalletScreen() {
  const { wallets, activeWallet, createWallet, loading } = useWallets();
  const { sendTransaction, loading: txLoading } = useSendTransaction();
  const [showTransactionSheet, setShowTransactionSheet] = useState(false);

  const handleCreateWallet = async () => {
    try {
      const newWallet = await createWallet(1); // Ethereum mainnet
      Alert.alert('Success', `Created wallet: ${newWallet.address}`);
    } catch (error) {
      Alert.alert('Error', error.message);
    }
  };

  const sampleTransaction = {
    to: '0x742d35Cc6C6C27f5CD1d15Ba06C522A6b928F123',
    value: '1000000000000000000', // 1 ETH
    chainId: 1
  };

  const handleSendTransaction = async () => {
    try {
      if (!activeWallet) {
        Alert.alert('Error', 'No active wallet');
        return;
      }
      
      const hash = await sendTransaction(sampleTransaction, activeWallet.id);
      Alert.alert('Success', `Transaction sent: ${hash}`);
      setShowTransactionSheet(false);
    } catch (error) {
      Alert.alert('Error', error.message);
    }
  };

  return (
    <View style={{ flex: 1 }}>
      <ScrollView style={{ flex: 1, padding: 16 }}>
        <TouchableOpacity
          onPress={handleCreateWallet}
          disabled={loading}
          style={{
            backgroundColor: '#007AFF',
            padding: 15,
            borderRadius: 8,
            marginBottom: 20
          }}
        >
          <Text style={{ color: 'white', textAlign: 'center', fontSize: 16 }}>
            {loading ? 'Creating...' : 'Create New Wallet'}
          </Text>
        </TouchableOpacity>

        {wallets.map(wallet => (
          <WalletCard
            key={wallet.id}
            wallet={wallet}
            showBalance={true}
            onPress={() => {
              Alert.alert(
                'Wallet Options',
                'What would you like to do?',
                [
                  { text: 'Cancel', style: 'cancel' },
                  { text: 'Send Transaction', onPress: () => setShowTransactionSheet(true) }
                ]
              );
            }}
          />
        ))}

        {wallets.length === 0 && (
          <Text style={{ textAlign: 'center', color: '#666', marginTop: 50 }}>
            No wallets yet. Create your first wallet to get started.
          </Text>
        )}
      </ScrollView>

      <TransactionSheet
        isVisible={showTransactionSheet}
        transaction={sampleTransaction}
        onConfirm={handleSendTransaction}
        onCancel={() => setShowTransactionSheet(false)}
        biometricRequired={true}
      />
    </View>
  );
}
```

## Browser Support

- **iOS**: iOS 13.0+ (Expo SDK 49+)
- **Android**: Android 6.0+ (API Level 23+)

## Dependencies

- expo-secure-store: Secure token storage
- expo-web-browser: OAuth flows
- expo-crypto: Cryptographic operations
- expo-local-authentication: Biometric authentication
- expo-apple-authentication: Native Apple Sign-In
- @react-native-async-storage/async-storage: Fallback storage
- @react-native-community/netinfo: Network monitoring

## Support

- Documentation: https://docs.erebor.xyz/react-native
- Issues: https://github.com/erebor/sdk/issues
- Discord: https://discord.gg/erebor
- Email: support@erebor.xyz

## License

MIT License - see LICENSE file for details.