# EreborSwift

A native iOS/macOS SDK for the Erebor wallet infrastructure, providing secure authentication, wallet management, and transaction signing capabilities with biometric protection.

## Features

- 🔐 **Secure Authentication** - Multi-provider auth (Email, Phone, Apple, Google, OAuth, SIWE)
- 👛 **Wallet Management** - Create, import, and manage blockchain wallets
- 🔒 **Biometric Security** - FaceID/TouchID protection for sensitive operations
- ⛓️ **Multi-Chain Support** - Ethereum, Polygon, Arbitrum, Optimism, Base, and more
- 📱 **SwiftUI Components** - Ready-to-use UI components for common workflows
- 🛡️ **Keychain Storage** - Secure token and key storage using iOS Keychain Services
- 🌐 **SSL Pinning** - Optional certificate pinning for enhanced security

## Installation

### Swift Package Manager

Add EreborSwift to your project using Xcode:

1. In Xcode, go to **File → Add Package Dependencies**
2. Enter the repository URL: `https://github.com/erebor-xyz/erebor-swift`
3. Select the version and add to your target

Or add to your `Package.swift` file:

```swift
dependencies: [
    .package(url: "https://github.com/erebor-xyz/erebor-swift", from: "1.0.0")
]
```

## Quick Start

### 1. Configuration

Configure the SDK in your app's initialization:

```swift
import EreborSwift

// In your AppDelegate or App struct
func configureErebor() {
    let config = EreborConfig(
        apiUrl: "https://api.erebor.xyz",
        appId: "your-app-id",
        loginMethods: [.email, .apple, .google],
        chains: Chain.mainnetChains,
        requireBiometricForSigning: true
    )
    
    Erebor.shared.configure(
        apiUrl: "https://api.erebor.xyz",
        appId: "your-app-id",
        config: config
    )
}
```

### 2. Authentication

#### Email Authentication

```swift
// Send OTP
let otpSession = try await Erebor.shared.auth?.loginWithEmail("user@example.com")

// Verify OTP
let authResult = try await Erebor.shared.auth?.verifyEmailOTP(otpSession, code: "123456")
print("User authenticated: \(authResult.user)")
```

#### Apple Sign In

```swift
let authResult = try await Erebor.shared.auth?.loginWithApple(
    presenting: viewController
)
print("Authenticated with Apple: \(authResult.user.email)")
```

#### Phone Authentication

```swift
// Send SMS OTP
let otpSession = try await Erebor.shared.auth?.loginWithPhone("+1234567890")

// Verify SMS OTP
let authResult = try await Erebor.shared.auth?.verifyPhoneOTP(otpSession, code: "654321")
```

### 3. Wallet Operations

#### Create a Wallet

```swift
// Create wallet on Ethereum mainnet
let wallet = try await Erebor.shared.wallet?.createWallet(chainId: 1)
print("New wallet address: \(wallet.address)")

// Create wallet on Polygon
let polygonWallet = try await Erebor.shared.wallet?.createWallet(chainId: 137)
```

#### Sign a Message

```swift
let message = "Hello, Erebor!"
let signature = try await Erebor.shared.wallet?.signMessage(
    walletId: wallet.id, 
    message: message
)
print("Signature: \(signature)")
```

#### Send a Transaction

```swift
let transaction = TransactionRequest(
    to: "0x742d35Cc6634C0532925a3b8D5C9b8ca04Bd2e",
    value: "1000000000000000000", // 1 ETH in wei
    chainId: 1
)

let txHash = try await Erebor.shared.wallet?.sendTransaction(
    walletId: wallet.id,
    transaction: transaction
)
print("Transaction hash: \(txHash)")
```

## SwiftUI Integration

### Login View

```swift
import SwiftUI
import EreborSwift

struct ContentView: View {
    @State private var showLogin = true
    @State private var authenticatedUser: EreborUser?
    
    var body: some View {
        if let user = authenticatedUser {
            DashboardView(user: user)
        } else {
            LoginView(
                config: LoginViewConfig(
                    title: "Welcome to MyApp",
                    availableMethods: [.email, .apple, .google]
                ),
                onSuccess: { user in
                    authenticatedUser = user
                    showLogin = false
                },
                onCancel: {
                    // Handle cancellation
                }
            )
        }
    }
}
```

### Wallet Card View

```swift
struct WalletListView: View {
    let wallets: [EreborWallet]
    
    var body: some View {
        ScrollView {
            LazyVStack(spacing: 16) {
                ForEach(wallets) { wallet in
                    WalletCardView(
                        wallet: wallet,
                        config: WalletCardConfig(
                            showBalance: true,
                            showTokens: true,
                            showActions: true
                        ),
                        onTap: {
                            // Handle wallet selection
                        },
                        onCopy: {
                            // Handle address copy
                        }
                    )
                }
            }
            .padding()
        }
    }
}
```

### Transaction Confirmation

```swift
struct SendView: View {
    @State private var showConfirmation = false
    let transaction: TransactionRequest
    let wallet: EreborWallet
    
    var body: some View {
        VStack {
            // Transaction form
            // ...
            
            Button("Send") {
                showConfirmation = true
            }
        }
        .sheet(isPresented: $showConfirmation) {
            TransactionConfirmView(
                transaction: transaction,
                wallet: wallet,
                onConfirm: {
                    return try await Erebor.shared.wallet?.sendTransaction(
                        wallet.id,
                        transaction: transaction
                    ) ?? ""
                },
                onCancel: {
                    showConfirmation = false
                }
            )
        }
    }
}
```

## Advanced Configuration

### Custom Chains

```swift
let customChain = Chain(
    id: 42161,
    name: "Arbitrum One",
    rpcUrl: "https://arb1.arbitrum.io/rpc",
    chainType: .evm,
    nativeCurrency: NativeCurrency(name: "Ether", symbol: "ETH", decimals: 18),
    blockExplorer: "https://arbiscan.io",
    gasPrice: GasPriceConfig(supportsEIP1559: true)
)

let config = EreborConfig(
    apiUrl: "https://api.erebor.xyz",
    appId: "your-app-id",
    chains: [customChain]
)
```

### SSL Pinning

```swift
let sslConfig = SSLPinningConfig(
    certificateHashes: [
        "sha256-hash-of-your-certificate",
        "sha256-hash-of-backup-certificate"
    ],
    enforceOnFailure: true
)

let config = EreborConfig(
    apiUrl: "https://api.erebor.xyz",
    appId: "your-app-id",
    sslPinning: sslConfig
)
```

### Biometric Configuration

```swift
// Check biometric availability
let biometricGate = BiometricGate()
if biometricGate.isAvailable {
    print("Biometric type: \(biometricGate.biometricType)")
} else {
    print("Setup error: \(biometricGate.getBiometricSetupError() ?? "Unknown")")
}

// Configure biometric requirements
let config = EreborConfig(
    apiUrl: "https://api.erebor.xyz",
    appId: "your-app-id",
    requireBiometricForSigning: true
)
```

## Authentication Providers Setup

### Apple Sign In

1. Enable "Sign in with Apple" in your Apple Developer account
2. Add the capability to your Xcode project
3. Configure your domain and redirect URLs

### Google OAuth

1. Set up OAuth 2.0 credentials in Google Cloud Console
2. Configure your redirect URI scheme in Info.plist:

```xml
<key>CFBundleURLTypes</key>
<array>
    <dict>
        <key>CFBundleURLName</key>
        <string>google-oauth</string>
        <key>CFBundleURLSchemes</key>
        <array>
            <string>your.app.bundle.id</string>
        </array>
    </dict>
</array>
```

### Other OAuth Providers

Configure redirect URI schemes for Discord, GitHub, Twitter, etc.:

```xml
<key>CFBundleURLSchemes</key>
<array>
    <string>com.erebor.app</string>
</array>
```

## Error Handling

The SDK provides comprehensive error handling:

```swift
do {
    let wallet = try await Erebor.shared.wallet?.createWallet()
} catch let error as EreborError {
    switch error {
    case .sdkNotConfigured:
        print("SDK not configured")
    case .authenticationRequired:
        print("User needs to sign in")
    case .biometricNotAvailable:
        print("Biometric authentication not available")
    case .networkError(let message):
        print("Network error: \(message)")
    default:
        print("Other error: \(error.localizedDescription)")
    }
} catch let error as WalletError {
    switch error {
    case .walletNotFound(let id):
        print("Wallet not found: \(id)")
    case .insufficientBalance:
        print("Insufficient balance")
    case .chainMismatch(let expected, let actual):
        print("Chain mismatch: expected \(expected), got \(actual)")
    default:
        print("Wallet error: \(error.localizedDescription)")
    }
}
```

## Security Best Practices

1. **Always enable biometric protection** for signing operations
2. **Use SSL pinning** for production apps
3. **Validate transaction details** before signing
4. **Clear sensitive data** from memory after use
5. **Use unique service identifiers** for keychain storage
6. **Test keychain access** in various device states

```swift
// Example: Secure transaction signing
func secureTransactionSigning() async throws {
    // Validate transaction parameters
    guard isValidAddress(transaction.to) else {
        throw TransactionError.invalidAddress
    }
    
    // Require biometric authentication
    let biometricGate = BiometricGate()
    let authenticated = try await biometricGate.authenticate(
        reason: "Sign transaction to \(transaction.to)"
    )
    
    guard authenticated else {
        throw EreborError.userCancelled
    }
    
    // Sign with secure key management
    let signature = try await wallet.signTransaction(transaction)
    
    // Clear sensitive data
    // (handled automatically by SecureData class)
}
```

## Testing

The SDK includes comprehensive test coverage:

```bash
# Run tests
swift test

# Run tests with coverage
swift test --enable-code-coverage
```

## Migration Guide

### From React SDK

The Swift SDK mirrors the React SDK API structure:

| React SDK | Swift SDK |
|-----------|-----------|
| `useErebor()` | `Erebor.shared` |
| `loginWithEmail()` | `Erebor.shared.auth?.loginWithEmail()` |
| `createWallet()` | `Erebor.shared.wallet?.createWallet()` |
| `signMessage()` | `Erebor.shared.wallet?.signMessage()` |

## API Reference

### Core Classes

- **`Erebor`** - Main SDK entry point and configuration
- **`AuthManager`** - Authentication and user management
- **`WalletManager`** - Wallet operations and transaction signing
- **`KeychainStore`** - Secure storage for tokens and keys
- **`BiometricGate`** - Biometric authentication handling

### Models

- **`EreborUser`** - User account information
- **`EreborWallet`** - Wallet representation
- **`TransactionRequest`** - Transaction parameters
- **`Chain`** - Blockchain configuration
- **`AuthProvider`** - Authentication method enumeration

### UI Components

- **`LoginView`** - SwiftUI login interface
- **`WalletCardView`** - Wallet display component
- **`TransactionConfirmView`** - Transaction confirmation interface

## Examples

Check the `Examples/` directory for complete sample apps:

- **BasicWallet** - Simple wallet app with authentication and transactions
- **MultiChain** - Multi-chain wallet with chain switching
- **BiometricDemo** - Biometric authentication showcase

## Support

- **Documentation**: [https://docs.erebor.xyz/swift](https://docs.erebor.xyz/swift)
- **Issues**: [GitHub Issues](https://github.com/erebor-xyz/erebor-swift/issues)
- **Discord**: [Erebor Community](https://discord.gg/erebor)
- **Email**: [support@erebor.xyz](mailto:support@erebor.xyz)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## Contributing

We welcome contributions! Please see [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes (`git commit -m 'Add some amazing feature'`)
4. Push to the branch (`git push origin feature/amazing-feature`)
5. Open a Pull Request

## Changelog

See [CHANGELOG.md](CHANGELOG.md) for version history and updates.