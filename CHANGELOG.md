# Changelog

All notable changes to Erebor are documented here.

## [0.1.0] - 2026-02-17

### Added

#### Core Infrastructure
- **erebor-common**: Shared types, error handling, `SecretBytes` with zeroize support, and common utilities across all crates
- **erebor-gateway**: axum API gateway with 18+ REST endpoints, comprehensive error handling, and middleware integration

#### Authentication (erebor-auth)
- Google OAuth (code → token → userinfo flow)
- Apple OAuth (ES256 JWT verification, ID token validation)
- Twitter OAuth 2.0 with PKCE flow
- Discord OAuth 2.0 integration
- GitHub OAuth with email scope access
- Farcaster Sign-In (SIWF) protocol support
- Telegram Login Widget verification
- Email OTP (rate-limited, 6-digit codes, 10-minute TTL)
- Phone OTP (E.164 validation, comprehensive rate limiting)
- SIWE (Sign-In with Ethereum, EIP-4361 compliant)
- Passkey authentication stub (WebAuthn ready)
- JWT session management with refresh token rotation and theft detection
- Identity linking system (multi-provider per user)
- Auth middleware with comprehensive rate limiting

#### Key Vault (erebor-vault)
- Shamir 2-of-3 secret sharing over GF(2^8) finite field
- AES-256-GCM envelope encryption with secure key derivation
- BIP-32/44 HD key derivation (Ethereum + Solana derivation paths)
- secp256k1 ECDSA + Ed25519 signature support
- Share rotation with atomic replacement mechanism
- Recovery share export (password-encrypted backup)
- Immutable audit trail for all vault operations

#### Account Abstraction (erebor-aa)
- ERC-4337 UserOperation handling + bundler implementation
- Verifying paymaster (operator-signed transactions)
- Sponsored paymaster (whitelisted users/contracts)
- ERC-20 paymaster (pay gas fees with any token)
- Smart account factory with CREATE2 deterministic addresses
- Session keys with spending limits and time bounds

#### Chain Service (erebor-chain)
- Multi-chain RPC pooling with health tracking and automatic failover
- Chain registry (Ethereum, Base, Polygon, Arbitrum, Optimism, Sepolia, Solana)
- EIP-1559 + legacy gas estimation with configurable safety margins
- Transaction signing pipeline (RLP encoding, EIP-155 replay protection)
- Nonce management (per-address atomic counters)
- Transaction broadcasting with receipt polling and confirmation tracking

#### Policy Engine (erebor-policy)
- 11 comprehensive rule types:
  - Spending limits (per transaction, daily, weekly, monthly)
  - Recipient allowlists and blocklists
  - Chain restrictions and network-specific rules
  - Time windows and scheduling constraints
  - Geographic restrictions
  - Rate limiting (transaction frequency)
  - Multi-signature requirements
  - Contract allowlists (whitelisted smart contracts)
  - Token restrictions (allowed/blocked assets)
  - Gas price limits
  - Velocity checks (cumulative spending patterns)
- Condition sets with AND/OR boolean logic and 12 comparison operators
- Real-time aggregation tracking (tx count, volume, unique recipients, gas usage, failure rates)
- Key quorums with threshold-based multi-party approval workflows
- Approval request lifecycle management (pending → approved/denied/expired)

#### React SDK (@erebor/react)
- `EreborProvider` context provider with automatic token management
- `useErebor()` hook (login, logout, user state, ready status, authenticated state)
- `useWallets()` hook (create wallet, list wallets, active wallet management)
- `useSignMessage()` and `useSendTransaction()` hooks with typed responses
- `useAuth()` hook (link/unlink identity providers)
- `usePrivy()` compatibility shim for seamless Privy migration
- `LoginModal` component with email OTP, Google OAuth, SIWE flows
- `WalletButton` and `TransactionStatus` UI components
- Embedded wallet iframe bridge (secure postMessage protocol)
- Typed API client with automatic token refresh and error handling
- Zero runtime dependencies (minimal bundle impact)

#### React Native SDK (@erebor/react-native)
- Complete hook API surface matching React SDK
- expo-secure-store encrypted token storage
- Biometric authentication (FaceID/TouchID/Fingerprint) integration
- Deep link OAuth handling with PKCE flow
- Native Apple Sign-In (iOS) with web fallback support
- React Native components: LoginSheet, WalletCard, TransactionSheet
- Device key share management with biometric protection
- On-device transaction signing with hardware security

#### Swift SDK (EreborSwift)
- Swift Package Manager distribution (iOS 15+, macOS 13+)
- AuthManager with email/phone OTP, Google OAuth, Apple Sign-In, SIWE
- WalletManager with biometric-gated transaction signing
- Keychain token storage with biometric protection
- ASWebAuthenticationSession OAuth flows with PKCE
- SwiftUI components: LoginView, WalletCardView, TransactionConfirmView
- Device key share storage in iOS Keychain
- Native secp256k1 signing via iOS Security framework

#### Kotlin SDK (erebor-kotlin)
- Android library (minSdk 24, compileSdk 34)
- AuthManager with Kotlin StateFlow reactive state management
- WalletManager with Android BiometricPrompt integration
- EncryptedSharedPreferences secure token storage
- Chrome Custom Tabs OAuth flows with PKCE
- Jetpack Compose UI components: LoginSheet, WalletCard, TransactionConfirmSheet
- OkHttp HTTP client with interceptors and SSL certificate pinning
- Bouncy Castle cryptography for secp256k1 signing

#### Documentation
- Complete architecture documentation (auth, vault, chain, AA, policy systems)
- REST API reference with comprehensive request/response examples
- Self-hosting deployment guide (Docker, environment variables, PostgreSQL + Redis setup)
- Quick-start tutorial covering auth → wallet creation → transaction signing flow
- SDK integration guides with migration documentation from other wallet providers
- Security best practices and threat model documentation

### Infrastructure
- Docker containerization with multi-stage builds
- PostgreSQL database schema with migrations
- Redis caching and session storage
- Comprehensive test suite across all modules
- CI/CD pipeline configuration
- Environment-based configuration management
- Logging and observability setup

### Security
- End-to-end encryption for all sensitive data
- Zero-knowledge architecture (server cannot access private keys)
- Hardware security module (HSM) integration ready
- Audit logging for all security-critical operations
- Rate limiting and DDoS protection
- SQL injection and XSS protection
- Secure random number generation
- Memory protection with zeroization