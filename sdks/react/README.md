# @erebor/react

React SDK for Erebor — self-custodial wallet infrastructure. A drop-in alternative to `@privy-io/react-auth` with enhanced security and flexibility.

## Installation

```bash
npm install @erebor/react
# or
yarn add @erebor/react
# or
pnpm add @erebor/react
```

## Quick Start

### 1. Wrap your app with EreborProvider

```tsx
import { EreborProvider } from '@erebor/react';

function App() {
  return (
    <EreborProvider
      config={{
        apiUrl: 'https://api.erebor.xyz',
        appId: 'your-app-id',
        loginMethods: ['email', 'google', 'siwe'],
        chains: [
          { id: 1, name: 'Ethereum', rpcUrl: 'https://eth.llamarpc.com' },
          { id: 10, name: 'Optimism', rpcUrl: 'https://mainnet.optimism.io' }
        ]
      }}
    >
      <YourApp />
    </EreborProvider>
  );
}
```

### 2. Use the auth hook

```tsx
import { useErebor } from '@erebor/react';

function YourApp() {
  const { user, authenticated, login, logout } = useErebor();

  if (!authenticated) {
    return (
      <button onClick={() => login('email', { email: 'user@example.com' })}>
        Sign In
      </button>
    );
  }

  return (
    <div>
      <p>Welcome, {user?.email}!</p>
      <button onClick={logout}>Sign Out</button>
    </div>
  );
}
```

### 3. Or use the pre-built components

```tsx
import { LoginModal, WalletButton } from '@erebor/react';

function YourApp() {
  const [showLogin, setShowLogin] = useState(false);

  return (
    <div>
      <WalletButton />
      
      <LoginModal 
        isOpen={showLogin} 
        onClose={() => setShowLogin(false)}
      />
    </div>
  );
}
```

## Privy Migration

**Migrating from Privy? It's a single line change!**

```tsx
// Before (Privy)
import { usePrivy } from '@privy-io/react-auth';

// After (Erebor)
import { usePrivy } from '@erebor/react';

// Your existing code works unchanged!
const { user, login, logout, createWallet, signMessage } = usePrivy();
```

Our `usePrivy` hook provides 100% API compatibility with Privy's interface.

## API Reference

### EreborProvider

```tsx
interface EreborConfig {
  apiUrl: string;              // Your Erebor API endpoint
  appId: string;               // Your application ID
  loginMethods: LoginMethod[]; // Enabled auth methods
  chains?: Chain[];            // Supported blockchains
  appearance?: {               // UI customization
    theme?: 'light' | 'dark';
    primaryColor?: string;
    borderRadius?: string;
  };
  tokenPrefix?: string;        // localStorage key prefix
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

#### useSignMessage()

Message signing:

```tsx
const {
  signMessage, // (message, walletId?) => Promise<signature>
  loading,
  error
} = useSignMessage();
```

#### useSendTransaction()

Transaction sending:

```tsx
const {
  sendTransaction, // (tx, walletId?) => Promise<txHash>
  loading,
  error,
  txHash
} = useSendTransaction();
```

#### useAuth()

Account linking:

```tsx
const {
  linkAccount,     // (provider, token) => Promise<LinkedAccount>
  unlinkAccount,   // (provider) => Promise<void>
  linkedAccounts,  // User's linked social accounts
  loading,
  error
} = useAuth();
```

### Components

#### LoginModal

Pre-built authentication UI:

```tsx
<LoginModal
  isOpen={boolean}
  onClose={() => void}
  appearance={{
    theme: 'light' | 'dark',
    logo: 'https://...',
    primaryColor: '#3B82F6'
  }}
  methods={['email', 'google', 'siwe']}
/>
```

Features:
- Email OTP flow
- Google OAuth redirect
- Wallet connect (SIWE)
- Fully customizable styling
- No external CSS dependencies

#### WalletButton

Connect/disconnect button:

```tsx
<WalletButton
  appearance={{ theme: 'dark' }}
  text={{
    connect: 'Connect Wallet',
    disconnect: 'Disconnect'
  }}
  onClick={() => void} // Custom click handler
/>
```

Shows user info when connected, opens login when not.

#### TransactionStatus

Transaction status display:

```tsx
<TransactionStatus
  txHash="0x..."
  status="pending" | "confirmed" | "failed"
  chainId={1}
  onClose={() => void}
/>
```

## Authentication Methods

### Email OTP

Two-step process:

```tsx
// Step 1: Send OTP
await login('email', { email: 'user@example.com' });

// Step 2: Verify OTP
await login('email', { 
  email: 'user@example.com', 
  code: '123456' 
});
```

### Google OAuth

Redirects to Google:

```tsx
await login('google', { 
  code: 'auth_code_from_redirect',
  redirectUri: window.location.origin 
});
```

### Sign-in with Ethereum (SIWE)

Wallet-based authentication:

```tsx
const nonce = await client.getSiweNonce();
// ... construct SIWE message and get signature from wallet
await login('siwe', { message, signature });
```

## TypeScript Support

Full TypeScript support with comprehensive type definitions:

```tsx
import type { 
  EreborUser, 
  EreborWallet, 
  TransactionRequest,
  LoginMethod 
} from '@erebor/react';

const user: EreborUser = {
  id: 'user_123',
  email: 'user@example.com',
  wallets: [...],
  linkedAccounts: [...],
  createdAt: '2024-01-01T00:00:00Z'
};
```

## Advanced Usage

### Custom API Client

```tsx
import { EreborApiClient } from '@erebor/react';

const client = new EreborApiClient('https://api.erebor.xyz');

// Direct API calls
const user = await client.getMe();
const wallets = await client.listWallets();
const signature = await client.signMessage(walletId, message);
```

### Iframe Bridge (Client-side Signing)

For enhanced security, sign transactions client-side:

```tsx
import { IframeController } from '@erebor/react';

const iframe = new IframeController({
  vaultUrl: 'https://vault.erebor.xyz',
  timeout: 30000
});

await iframe.initialize();
const signature = await iframe.signInIframe(share, message, walletId);
```

### Error Handling

```tsx
import { AuthError, WalletError } from '@erebor/react';

try {
  await login('email', { email: 'invalid@email' });
} catch (error) {
  if (error instanceof AuthError) {
    console.error('Auth failed:', error.code);
  }
}
```

## Configuration

### Chains

Configure supported blockchains:

```tsx
const config = {
  chains: [
    {
      id: 1,
      name: 'Ethereum',
      rpcUrl: 'https://eth.llamarpc.com',
      nativeCurrency: {
        name: 'Ether',
        symbol: 'ETH',
        decimals: 18
      },
      blockExplorer: 'https://etherscan.io'
    },
    {
      id: 10,
      name: 'Optimism',
      rpcUrl: 'https://mainnet.optimism.io'
    }
  ]
};
```

### Appearance

Customize the UI theme:

```tsx
const config = {
  appearance: {
    theme: 'dark',
    primaryColor: '#8B5CF6',
    borderRadius: '12px'
  }
};
```

### Token Storage

Configure token storage:

```tsx
const config = {
  tokenPrefix: 'myapp' // Stores tokens as 'myapp_access_token'
};
```

## Security Features

- **Client-side key derivation** via secure iframe bridge
- **Automatic token refresh** with configurable intervals
- **Secure token storage** in localStorage with prefix isolation
- **Origin validation** for iframe communication
- **Request timeout handling** to prevent hanging operations
- **Error retry logic** with exponential backoff

## Browser Support

- Chrome 88+
- Firefox 85+
- Safari 14+
- Edge 88+

Requires `localStorage` and `postMessage` APIs.

## Examples

### Basic Authentication App

```tsx
import { EreborProvider, useErebor, LoginModal } from '@erebor/react';
import { useState } from 'react';

function App() {
  return (
    <EreborProvider config={{
      apiUrl: 'https://api.erebor.xyz',
      appId: 'your-app-id',
      loginMethods: ['email', 'google']
    }}>
      <AuthApp />
    </EreborProvider>
  );
}

function AuthApp() {
  const { user, authenticated, logout } = useErebor();
  const [showLogin, setShowLogin] = useState(false);

  if (authenticated) {
    return (
      <div>
        <h1>Welcome, {user?.email}!</h1>
        <button onClick={logout}>Sign Out</button>
      </div>
    );
  }

  return (
    <div>
      <button onClick={() => setShowLogin(true)}>
        Sign In
      </button>
      <LoginModal 
        isOpen={showLogin} 
        onClose={() => setShowLogin(false)} 
      />
    </div>
  );
}
```

### Wallet Transaction App

```tsx
import { useWallets, useSendTransaction, TransactionStatus } from '@erebor/react';
import { useState } from 'react';

function WalletApp() {
  const { activeWallet } = useWallets();
  const { sendTransaction, loading, txHash } = useSendTransaction();
  const [showStatus, setShowStatus] = useState(false);

  const handleSend = async () => {
    try {
      await sendTransaction({
        to: '0x742d35Cc...',
        value: '1000000000000000000', // 1 ETH in wei
        chainId: 1
      });
      setShowStatus(true);
    } catch (error) {
      console.error('Transaction failed:', error);
    }
  };

  if (!activeWallet) {
    return <div>No wallet connected</div>;
  }

  return (
    <div>
      <p>Wallet: {activeWallet.address}</p>
      <button onClick={handleSend} disabled={loading}>
        {loading ? 'Sending...' : 'Send 1 ETH'}
      </button>
      
      {txHash && (
        <TransactionStatus
          txHash={txHash}
          status="pending"
          chainId={activeWallet.chainId}
          onClose={() => setShowStatus(false)}
        />
      )}
    </div>
  );
}
```

## Support

- Documentation: https://docs.erebor.xyz
- Issues: https://github.com/erebor/sdk/issues  
- Discord: https://discord.gg/erebor

## License

MIT License - see LICENSE file for details.