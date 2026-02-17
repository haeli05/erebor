# React SDK

> **Status:** 📋 Planned — The React SDK will be the first client SDK, targeting Phase 4.

The React SDK will provide hooks and components for integrating Erebor authentication and wallet functionality into React applications.

## Planned API

### Installation

```bash
npm install @erebor/react
# or
yarn add @erebor/react
```

### Provider Setup

```tsx
import { EreborProvider } from '@erebor/react';

function App() {
  return (
    <EreborProvider
      apiUrl="https://erebor.yourdomain.com"
      appId="your-app-id"
    >
      <YourApp />
    </EreborProvider>
  );
}
```

### Authentication Hooks

```tsx
import { useAuth, useLogin, useLogout } from '@erebor/react';

function LoginButton() {
  const { isAuthenticated, user } = useAuth();
  const { login } = useLogin();
  const { logout } = useLogout();

  if (isAuthenticated) {
    return (
      <div>
        <p>Welcome, {user.email}</p>
        <button onClick={logout}>Log out</button>
      </div>
    );
  }

  return (
    <div>
      <button onClick={() => login({ provider: 'google' })}>
        Sign in with Google
      </button>
      <button onClick={() => login({ provider: 'email', email: 'user@example.com' })}>
        Sign in with Email
      </button>
    </div>
  );
}
```

### Wallet Hooks

```tsx
import { useWallet, useBalance, useSendTransaction } from '@erebor/react';

function WalletInfo() {
  const { address, chain } = useWallet();
  const { balance, isLoading } = useBalance();
  const { sendTransaction } = useSendTransaction();

  const handleSend = async () => {
    const tx = await sendTransaction({
      to: '0x...',
      value: '0.01',
      chain: 'base',
    });
    console.log('Transaction hash:', tx.hash);
  };

  return (
    <div>
      <p>Address: {address}</p>
      <p>Balance: {isLoading ? 'Loading...' : `${balance} ETH`}</p>
      <button onClick={handleSend}>Send 0.01 ETH</button>
    </div>
  );
}
```

### Pre-Built Components

```tsx
import { ConnectButton, WalletModal } from '@erebor/react';

// Drop-in connect button with wallet modal
function Header() {
  return (
    <nav>
      <ConnectButton
        providers={['google', 'email', 'siwe']}
        theme="dark"
      />
    </nav>
  );
}
```

## Design Goals

- **Drop-in replacement for Privy's React SDK** — Same DX, self-hosted backend
- **TypeScript-first** — Full type safety
- **Framework-agnostic core** — React hooks wrap a vanilla JS client
- **Bundle size conscious** — Tree-shakeable, no unnecessary dependencies
- **SSR compatible** — Works with Next.js, Remix, etc.

## Architecture

```
@erebor/react (hooks + components)
       │
       ▼
@erebor/client (vanilla JS/TS client)
       │
       ▼
  Erebor API Gateway (HTTPS)
```

The core client library (`@erebor/client`) handles:
- API communication
- Token management (access + refresh)
- Device share storage (IndexedDB / Secure Storage)
- Share encryption/decryption (client-side)

The React SDK provides:
- React hooks wrapping the client
- Pre-built UI components
- React context for state management
