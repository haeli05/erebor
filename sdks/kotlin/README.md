# Erebor Kotlin SDK

[![Maven Central](https://img.shields.io/maven-central/v/io.erebor/erebor-kotlin)](https://search.maven.org/search?q=g:io.erebor%20AND%20a:erebor-kotlin)
[![API](https://img.shields.io/badge/API-24%2B-brightgreen.svg?style=flat)](https://android-arsenal.com/api?level=24)
[![License](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)

The official Erebor SDK for Android/Kotlin. Build secure, user-friendly Web3 applications with native Android integration, biometric security, and Jetpack Compose support.

## Features

✅ **Native Android Integration** - Built specifically for Android with modern Android practices  
✅ **Biometric Security** - Secure wallet operations with fingerprint, face, and device authentication  
✅ **Jetpack Compose Ready** - First-class Compose support with reactive state management  
✅ **Multiple Auth Methods** - Email OTP, Phone OTP, Google OAuth, Apple, SIWE (Sign-In With Ethereum)  
✅ **Multi-Chain Support** - EVM compatible chains (Ethereum, Polygon, BSC, etc.) and Solana  
✅ **Encrypted Storage** - Secure token and key storage using AndroidX Security  
✅ **Material 3 UI** - Beautiful, customizable UI components following Material Design  
✅ **Kotlin Coroutines** - Async operations with modern Kotlin concurrency  

## Installation

Add the dependency to your `build.gradle.kts` (Module: app):

```kotlin
dependencies {
    implementation("io.erebor:erebor-kotlin:1.0.0")
}
```

## Quick Start

### 1. Configure the SDK

Initialize Erebor in your `Application` class or main activity:

```kotlin
import io.erebor.sdk.Erebor
import io.erebor.sdk.models.EreborConfig
import io.erebor.sdk.models.LoginMethod

class MyApplication : Application() {
    override fun onCreate() {
        super.onCreate()
        
        val config = EreborConfig(
            apiUrl = "https://api.erebor.io",
            appId = "your-app-id", // Get this from Erebor Dashboard
            loginMethods = listOf(
                LoginMethod.EMAIL,
                LoginMethod.GOOGLE,
                LoginMethod.SIWE
            )
        )
        
        Erebor.configure(this, config)
    }
}
```

### 2. Handle Authentication

#### Using the Login Sheet (Recommended)

```kotlin
import io.erebor.sdk.ui.EreborLoginSheet

@Composable
fun LoginScreen() {
    var showLogin by remember { mutableStateOf(true) }
    var user by remember { mutableStateOf<EreborUser?>(null) }
    
    if (showLogin) {
        EreborLoginSheet(
            onDismiss = { /* Handle dismissal */ },
            onAuthenticated = { authenticatedUser ->
                user = authenticatedUser
                showLogin = false
            }
        )
    } else {
        // Show authenticated content
        MainContent(user = user!!)
    }
}
```

#### Manual Authentication

```kotlin
// Email authentication
val session = Erebor.auth.loginWithEmail("user@example.com")
val result = Erebor.auth.verifyEmailOtp(session, "123456")

// Google authentication
val result = Erebor.auth.loginWithGoogle(activity)

// Sign-In With Ethereum
val nonce = Erebor.auth.getSiweNonce()
val message = "Sign-in message with nonce: $nonce"
val signature = "0x..." // Get from wallet
val result = Erebor.auth.loginWithSiwe(message, signature)
```

### 3. Manage Wallets

```kotlin
// Create a new wallet (requires biometric authentication)
val wallet = Erebor.wallets.createWallet()

// List user's wallets
val wallets = Erebor.wallets.listWallets()

// Sign a message
val signature = Erebor.wallets.signMessage(
    walletId = wallet.id,
    message = "Hello, Web3!"
)

// Send a transaction
val txRequest = TransactionRequest(
    to = "0x742d35Cc6634C0532925a3b8D435b3e4b2b8C2f3",
    value = "1000000000000000000", // 1 ETH in wei
    chainId = 1
)

val txHash = Erebor.wallets.sendTransaction(
    walletId = wallet.id,
    tx = txRequest
)
```

### 4. Jetpack Compose Integration

```kotlin
@Composable
fun WalletScreen() {
    val ereborState = rememberEreborState()
    val walletsState = rememberWalletsState()
    
    LazyColumn {
        items(walletsState.wallets) { wallet ->
            WalletCard(
                wallet = wallet,
                onClick = { selectedWallet ->
                    // Handle wallet selection
                }
            )
        }
    }
    
    // Auto-initialize when authenticated
    EreborInitEffect()
}
```

## Authentication Methods

### Email OTP

```kotlin
// Step 1: Request OTP
val session = Erebor.auth.loginWithEmail("user@example.com")

// Step 2: Verify OTP
val result = Erebor.auth.verifyEmailOtp(session, "123456")
```

### Phone OTP

```kotlin
// Step 1: Request OTP
val session = Erebor.auth.loginWithPhone("+1234567890")

// Step 2: Verify OTP
val result = Erebor.auth.verifyPhoneOtp(session, "123456")
```

### Google OAuth

Set up Google OAuth in your app:

1. Add to `AndroidManifest.xml`:
```xml
<activity
    android:name=".auth.CallbackActivity"
    android:exported="true">
    <intent-filter>
        <action android:name="android.intent.action.VIEW" />
        <category android:name="android.intent.category.DEFAULT" />
        <category android:name="android.intent.category.BROWSABLE" />
        <data android:scheme="io.erebor.auth" 
              android:host="callback" />
    </intent-filter>
</activity>
```

2. Handle the callback:
```kotlin
class CallbackActivity : Activity() {
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        
        intent.data?.let { uri ->
            GoogleAuthProvider().handleCallback(uri)
        }
        
        finish()
    }
}
```

3. Use in your app:
```kotlin
val result = Erebor.auth.loginWithGoogle(activity)
```

## Biometric Security

The SDK automatically uses biometric authentication for sensitive operations when available:

- Creating wallets
- Signing messages
- Signing transactions
- Sending transactions

Configure biometric behavior:

```kotlin
// Check if biometric authentication is available
val biometricGate = BiometricGate(context)
if (biometricGate.isAvailable) {
    val authenticated = biometricGate.authenticate(
        reason = "Authenticate to access wallet",
        title = "Biometric Authentication",
        subtitle = "Use your biometric to continue"
    )
}
```

## UI Components

### Login Sheet

```kotlin
EreborLoginSheet(
    onDismiss = { },
    onAuthenticated = { user -> },
    config = LoginSheetConfig(
        title = "Welcome to MyApp",
        methods = listOf(LoginMethod.EMAIL, LoginMethod.GOOGLE),
        theme = Theme.DARK
    )
)
```

### Wallet Cards

```kotlin
// Full wallet card
WalletCard(
    wallet = wallet,
    config = WalletCardConfig(
        showChainInfo = true,
        showFullAddress = false
    ),
    onClick = { wallet -> }
)

// Compact wallet card for lists
CompactWalletCard(
    wallet = wallet,
    onClick = { wallet -> }
)
```

### Auth Gate

Automatically show login when user is not authenticated:

```kotlin
EreborAuthGate(
    content = {
        // Your authenticated content
        MainScreen()
    },
    onAuthenticationSuccess = { user ->
        // Handle successful authentication
    }
)
```

## State Management

### Reactive State with Flows

```kotlin
@Composable
fun MyScreen() {
    // Observe authentication state
    val authState by Erebor.auth.authState.collectAsState()
    
    // Observe user
    val user by Erebor.user.collectAsState()
    
    // Observe wallets
    val wallets by Erebor.wallets.walletsState.collectAsState()
    
    when {
        !authState.authenticated -> ShowLogin()
        wallets.isEmpty() -> ShowCreateWallet()
        else -> ShowWallets(wallets)
    }
}
```

### Compose Helpers

```kotlin
// All-in-one state
val ereborState = rememberEreborState()

// Wallet operations
val walletOps = rememberWalletOperations()
val newWallet = walletOps.createWallet(chainId = 137) // Polygon

// Auth operations  
val authOps = rememberAuthOperations()
authOps.logout()
```

## Chain Configuration

Configure supported chains:

```kotlin
val config = EreborConfig(
    apiUrl = "https://api.erebor.io",
    appId = "your-app-id",
    loginMethods = listOf(LoginMethod.EMAIL),
    chains = listOf(
        Chain(
            id = 1,
            name = "Ethereum",
            rpcUrl = "https://mainnet.infura.io/v3/your-key",
            nativeCurrency = NativeCurrency("Ether", "ETH", 18),
            blockExplorer = "https://etherscan.io"
        ),
        Chain(
            id = 137,
            name = "Polygon",
            rpcUrl = "https://polygon-rpc.com",
            nativeCurrency = NativeCurrency("MATIC", "MATIC", 18),
            blockExplorer = "https://polygonscan.com"
        )
    )
)
```

## Error Handling

The SDK uses typed exceptions for clear error handling:

```kotlin
try {
    val wallet = Erebor.wallets.createWallet()
} catch (e: BiometricException) {
    // Handle biometric authentication failure
    when (e.code) {
        "BIOMETRIC_NOT_AVAILABLE" -> showError("Biometric authentication not available")
        "BIOMETRIC_REQUIRED" -> showError("Biometric authentication is required")
    }
} catch (e: WalletException) {
    // Handle wallet-related errors
    showError("Wallet operation failed: ${e.message}")
} catch (e: NetworkException) {
    // Handle network errors
    showError("Network error: ${e.message}")
}
```

## Testing

The SDK is designed to be testable with MockK:

```kotlin
@Test
fun `wallet creation requires biometric auth`() = runTest {
    val mockBiometric = mockk<BiometricGate>()
    every { mockBiometric.isAvailable } returns true
    coEvery { mockBiometric.authenticate(any(), any(), any(), any()) } returns false
    
    val walletManager = WalletManager(mockApiClient, mockBiometric)
    
    assertThrows<BiometricException> {
        walletManager.createWallet()
    }
}
```

## ProGuard Rules

Add to your `proguard-rules.pro`:

```proguard
# Erebor SDK
-keep class io.erebor.sdk.** { *; }

# Kotlinx Serialization
-keepattributes *Annotation*, InnerClasses
-dontnote kotlinx.serialization.AnnotationsKt
-keepclassmembers class kotlinx.serialization.json.** {
    *** Companion;
}
-keepclasseswithmembers class kotlinx.serialization.json.** {
    kotlinx.serialization.KSerializer serializer(...);
}
-keep,includedescriptorclasses class io.erebor.sdk.**$$serializer { *; }
-keepclassmembers class io.erebor.sdk.** {
    *** Companion;
}
-keepclasseswithmembers class io.erebor.sdk.** {
    kotlinx.serialization.KSerializer serializer(...);
}

# OkHttp3
-keepnames class okhttp3.internal.publicsuffix.PublicSuffixDatabase
-dontwarn org.codehaus.mojo.animal_sniffer.*
-dontwarn okhttp3.internal.platform.ConscryptPlatform
```

## Security Considerations

- **Encrypted Storage**: All tokens and sensitive data are encrypted using AndroidX Security
- **Biometric Gating**: Critical operations require biometric authentication when available  
- **SSL Pinning**: Network communication uses certificate pinning for additional security
- **No Private Keys**: Private keys never leave secure enclaves or the Erebor infrastructure
- **MPC Architecture**: Multi-party computation ensures no single point of failure

## Sample App

Check out the [sample app](https://github.com/erebor-protocol/erebor-android-sample) for a complete integration example.

## API Reference

Full API documentation is available at [docs.erebor.io/sdk/kotlin](https://docs.erebor.io/sdk/kotlin).

## Support

- 📚 [Documentation](https://docs.erebor.io)
- 💬 [Discord Community](https://discord.gg/erebor)
- 🐛 [GitHub Issues](https://github.com/erebor-protocol/erebor-kotlin-sdk/issues)
- 📧 [Email Support](mailto:support@erebor.io)

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

---

Built with ❤️ by the Erebor team