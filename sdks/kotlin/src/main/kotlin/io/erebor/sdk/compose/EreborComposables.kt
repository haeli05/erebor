package io.erebor.sdk.compose

import androidx.compose.runtime.*
import androidx.lifecycle.compose.collectAsStateWithLifecycle
import io.erebor.sdk.Erebor
import io.erebor.sdk.models.*

/**
 * State holder for Erebor SDK in Compose.
 */
@Stable
data class EreborState(
    val isConfigured: Boolean,
    val isAuthenticated: Boolean,
    val user: EreborUser?,
    val authState: AuthState,
    val loading: Boolean
)

/**
 * State holder for wallets in Compose.
 */
@Stable
data class WalletsState(
    val wallets: List<EreborWallet>,
    val primaryWallet: EreborWallet?,
    val loading: Boolean
)

/**
 * Remember the current Erebor SDK state as a Compose state.
 * This provides reactive updates to authentication and user state.
 */
@Composable
fun rememberEreborState(): EreborState {
    val authState by Erebor.auth.authState.collectAsStateWithLifecycle()
    val user by Erebor.user.collectAsStateWithLifecycle()
    
    return remember(authState, user) {
        EreborState(
            isConfigured = Erebor.isConfigured,
            isAuthenticated = Erebor.isAuthenticated,
            user = user,
            authState = authState,
            loading = authState.loading
        )
    }
}

/**
 * Remember the current wallets state as a Compose state.
 * This provides reactive updates to the user's wallets.
 */
@Composable
fun rememberWalletsState(): WalletsState {
    val walletsFlow by Erebor.wallets.walletsState.collectAsStateWithLifecycle()
    val loadingFlow by Erebor.wallets.loading.collectAsStateWithLifecycle()
    
    return remember(walletsFlow, loadingFlow) {
        WalletsState(
            wallets = walletsFlow,
            primaryWallet = walletsFlow.firstOrNull(),
            loading = loadingFlow
        )
    }
}

/**
 * Remember the current authentication state as a Compose state.
 * This is a more focused version of rememberEreborState for auth-only needs.
 */
@Composable
fun rememberAuthState(): AuthState {
    return Erebor.auth.authState.collectAsStateWithLifecycle().value
}

/**
 * Effect that initializes the Erebor SDK when the composable enters the composition.
 * This should be used in your root composable to ensure the SDK is initialized.
 * 
 * @param onAuthStateChanged Callback when authentication state changes
 */
@Composable
fun EreborInitEffect(
    onAuthStateChanged: ((AuthState) -> Unit)? = null
) {
    val authState by Erebor.auth.authState.collectAsStateWithLifecycle()
    
    // Initialize wallets when user becomes authenticated
    LaunchedEffect(authState.authenticated) {
        if (authState.authenticated && authState.user != null) {
            try {
                Erebor.wallets.initialize()
            } catch (e: Exception) {
                // Handle initialization error silently
                // UI can handle empty wallet state
            }
        }
    }
    
    // Notify about auth state changes
    LaunchedEffect(authState) {
        onAuthStateChanged?.invoke(authState)
    }
    
    // Load current user on startup if tokens exist
    LaunchedEffect(Unit) {
        if (Erebor.isConfigured && Erebor.isAuthenticated) {
            try {
                Erebor.auth.loadCurrentUser()
            } catch (e: Exception) {
                // Handle silently - user will need to login again
            }
        }
    }
}

/**
 * Composable function that automatically shows a login sheet when user is not authenticated.
 * 
 * @param content The content to show when authenticated
 * @param loginConfig Configuration for the login sheet
 * @param onAuthenticationSuccess Callback when authentication succeeds
 */
@Composable
fun EreborAuthGate(
    content: @Composable () -> Unit,
    loginConfig: io.erebor.sdk.ui.LoginSheetConfig = io.erebor.sdk.ui.LoginSheetConfig(),
    onAuthenticationSuccess: ((EreborUser) -> Unit)? = null
) {
    val ereborState = rememberEreborState()
    var showLoginSheet by remember { mutableStateOf(false) }
    
    // Show login sheet if not authenticated
    LaunchedEffect(ereborState.isAuthenticated) {
        showLoginSheet = !ereborState.isAuthenticated
    }
    
    if (ereborState.isAuthenticated && ereborState.user != null) {
        content()
    } else if (showLoginSheet) {
        io.erebor.sdk.ui.EreborLoginSheet(
            onDismiss = { /* Don't allow dismissal in auth gate mode */ },
            onAuthenticated = { user ->
                showLoginSheet = false
                onAuthenticationSuccess?.invoke(user)
            },
            config = loginConfig
        )
    }
    
    // Initialize Erebor
    EreborInitEffect()
}

/**
 * Hook-like composable for wallet operations.
 * Returns wallet state and common operations.
 */
@Composable
fun rememberWalletOperations(): WalletOperations {
    val walletsState = rememberWalletsState()
    
    return remember {
        WalletOperations(
            state = walletsState,
            createWallet = { chainId ->
                Erebor.wallets.createWallet(chainId)
            },
            signMessage = { walletId, message ->
                Erebor.wallets.signMessage(walletId, message)
            },
            signTransaction = { walletId, tx ->
                Erebor.wallets.signTransaction(walletId, tx)
            },
            sendTransaction = { walletId, tx ->
                Erebor.wallets.sendTransaction(walletId, tx)
            },
            refreshWallets = {
                Erebor.wallets.refreshWallets()
            }
        )
    }
}

/**
 * Operations available for wallet management.
 */
@Stable
data class WalletOperations(
    val state: WalletsState,
    val createWallet: suspend (chainId: Long?) -> EreborWallet,
    val signMessage: suspend (walletId: String, message: String) -> String,
    val signTransaction: suspend (walletId: String, tx: TransactionRequest) -> SignedTransaction,
    val sendTransaction: suspend (walletId: String, tx: TransactionRequest) -> String,
    val refreshWallets: suspend () -> Unit
)

/**
 * Hook-like composable for authentication operations.
 * Returns auth state and common operations.
 */
@Composable
fun rememberAuthOperations(): AuthOperations {
    val authState = rememberAuthState()
    
    return remember {
        AuthOperations(
            state = authState,
            loginWithEmail = { email ->
                Erebor.auth.loginWithEmail(email)
            },
            verifyEmailOtp = { session, code ->
                Erebor.auth.verifyEmailOtp(session, code)
            },
            loginWithPhone = { phone ->
                Erebor.auth.loginWithPhone(phone)
            },
            verifyPhoneOtp = { session, code ->
                Erebor.auth.verifyPhoneOtp(session, code)
            },
            loginWithSiwe = { message, signature ->
                Erebor.auth.loginWithSiwe(message, signature)
            },
            getSiweNonce = {
                Erebor.auth.getSiweNonce()
            },
            logout = {
                Erebor.auth.logout()
            },
            linkAccount = { provider, token ->
                Erebor.auth.linkAccount(provider, token)
            },
            unlinkAccount = { provider ->
                Erebor.auth.unlinkAccount(provider)
            }
        )
    }
}

/**
 * Operations available for authentication.
 */
@Stable
data class AuthOperations(
    val state: AuthState,
    val loginWithEmail: suspend (email: String) -> OtpSession,
    val verifyEmailOtp: suspend (session: OtpSession, code: String) -> AuthResult,
    val loginWithPhone: suspend (phone: String) -> OtpSession,
    val verifyPhoneOtp: suspend (session: OtpSession, code: String) -> AuthResult,
    val loginWithSiwe: suspend (message: String, signature: String) -> AuthResult,
    val getSiweNonce: suspend () -> String,
    val logout: suspend () -> Unit,
    val linkAccount: suspend (provider: AuthProvider, token: String) -> LinkedAccount,
    val unlinkAccount: suspend (provider: AuthProvider) -> Unit
)