# React Native SDK

> **Status:** 📋 Planned — Targeting Phase 4, after the React SDK.

The React Native SDK will bring Erebor authentication and embedded wallets to mobile apps on iOS and Android.

## Planned API

### Installation

```bash
npm install @erebor/react-native
```

### Provider Setup

```tsx
import { EreborProvider } from '@erebor/react-native';

export default function App() {
  return (
    <EreborProvider apiUrl="https://erebor.yourdomain.com">
      <Navigation />
    </EreborProvider>
  );
}
```

### Authentication

```tsx
import { useLogin } from '@erebor/react-native';

function LoginScreen() {
  const { login } = useLogin();

  return (
    <View>
      <TouchableOpacity onPress={() => login({ provider: 'google' })}>
        <Text>Sign in with Google</Text>
      </TouchableOpacity>
      <TouchableOpacity onPress={() => login({ provider: 'apple' })}>
        <Text>Sign in with Apple</Text>
      </TouchableOpacity>
    </View>
  );
}
```

### Wallet Operations

```tsx
import { useWallet } from '@erebor/react-native';

function WalletScreen() {
  const { address, signTransaction } = useWallet();

  return (
    <View>
      <Text>Address: {address}</Text>
      <TouchableOpacity onPress={() => signTransaction(tx)}>
        <Text>Sign Transaction</Text>
      </TouchableOpacity>
    </View>
  );
}
```

## Mobile-Specific Features

### Secure Storage

Device shares are stored in platform-specific secure storage:

| Platform | Storage | Protection |
|----------|---------|-----------|
| iOS | Keychain Services | Secure Enclave, biometric lock |
| Android | Android Keystore | Hardware-backed, biometric lock |

### Biometric Authentication

Require biometric (Face ID / fingerprint) to access the device share:

```tsx
const { signTransaction } = useWallet({
  requireBiometric: true, // Prompt for biometric before signing
});
```

### Deep Linking

Support for OAuth callback via deep links:

```
erebor://auth/callback?code=xxx&state=yyy
```

### Push Notifications

Notify users about:
- Incoming transactions to their wallet
- Session key expiration
- Recovery requests from guardians

## Architecture

```
@erebor/react-native
       │
       ├── React Native hooks + components
       │
       ├── @erebor/client (shared core)
       │
       ├── Native modules
       │   ├── iOS: Keychain + Secure Enclave
       │   └── Android: Keystore + StrongBox
       │
       └── Erebor API Gateway (HTTPS)
```

The native modules handle:
- Secure storage of device shares (Share 2)
- Biometric gating for share access
- Platform-specific OAuth flows (ASWebAuthenticationSession on iOS, Custom Tabs on Android)
