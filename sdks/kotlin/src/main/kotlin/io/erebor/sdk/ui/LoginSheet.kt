package io.erebor.sdk.ui

import androidx.compose.foundation.layout.*
import androidx.compose.foundation.shape.RoundedCornerShape
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Alignment
import androidx.compose.ui.Modifier
import androidx.compose.ui.platform.LocalContext
import androidx.compose.ui.text.font.FontWeight
import androidx.compose.ui.text.input.KeyboardType
import androidx.compose.ui.unit.dp
import androidx.compose.ui.window.Dialog
import androidx.compose.ui.window.DialogProperties
import androidx.compose.foundation.text.KeyboardOptions
import io.erebor.sdk.Erebor
import io.erebor.sdk.models.*
import kotlinx.coroutines.launch

/**
 * Configuration for the login sheet appearance and behavior.
 */
data class LoginSheetConfig(
    val title: String = "Sign In to Erebor",
    val subtitle: String? = "Choose your preferred sign-in method",
    val methods: List<LoginMethod> = listOf(LoginMethod.EMAIL, LoginMethod.GOOGLE),
    val theme: Theme = Theme.LIGHT,
    val primaryColor: String = "#007AFF"
)

/**
 * Bottom sheet login component for Erebor authentication.
 * 
 * @param onDismiss Callback when the sheet is dismissed
 * @param onAuthenticated Callback when authentication is successful
 * @param config Configuration for appearance and behavior
 */
@OptIn(ExperimentalMaterial3Api::class)
@Composable
fun EreborLoginSheet(
    onDismiss: () -> Unit,
    onAuthenticated: (EreborUser) -> Unit,
    config: LoginSheetConfig = LoginSheetConfig()
) {
    val context = LocalContext.current
    val coroutineScope = rememberCoroutineScope()
    
    var currentStep by remember { mutableStateOf(LoginStep.METHOD_SELECTION) }
    var selectedMethod by remember { mutableStateOf<LoginMethod?>(null) }
    var email by remember { mutableStateOf("") }
    var phone by remember { mutableStateOf("") }
    var otpCode by remember { mutableStateOf("") }
    var otpSession by remember { mutableStateOf<OtpSession?>(null) }
    var loading by remember { mutableStateOf(false) }
    var error by remember { mutableStateOf<String?>(null) }
    
    Dialog(
        onDismissRequest = onDismiss,
        properties = DialogProperties(usePlatformDefaultWidth = false)
    ) {
        Surface(
            modifier = Modifier
                .fillMaxWidth()
                .padding(16.dp),
            shape = RoundedCornerShape(16.dp),
            color = MaterialTheme.colorScheme.surface
        ) {
            Column(
                modifier = Modifier
                    .fillMaxWidth()
                    .padding(24.dp),
                verticalArrangement = Arrangement.spacedBy(16.dp)
            ) {
                // Header
                Text(
                    text = config.title,
                    style = MaterialTheme.typography.headlineSmall,
                    fontWeight = FontWeight.Bold
                )
                
                if (config.subtitle != null) {
                    Text(
                        text = config.subtitle,
                        style = MaterialTheme.typography.bodyMedium,
                        color = MaterialTheme.colorScheme.onSurfaceVariant
                    )
                }
                
                // Error message
                if (error != null) {
                    Card(
                        colors = CardDefaults.cardColors(
                            containerColor = MaterialTheme.colorScheme.errorContainer
                        )
                    ) {
                        Text(
                            text = error!!,
                            color = MaterialTheme.colorScheme.onErrorContainer,
                            modifier = Modifier.padding(12.dp),
                            style = MaterialTheme.typography.bodySmall
                        )
                    }
                }
                
                when (currentStep) {
                    LoginStep.METHOD_SELECTION -> {
                        MethodSelectionStep(
                            methods = config.methods,
                            onMethodSelected = { method ->
                                selectedMethod = method
                                when (method) {
                                    LoginMethod.EMAIL -> currentStep = LoginStep.EMAIL_INPUT
                                    LoginMethod.PHONE -> currentStep = LoginStep.PHONE_INPUT
                                    LoginMethod.GOOGLE -> {
                                        coroutineScope.launch {
                                            try {
                                                loading = true
                                                error = null
                                                val result = Erebor.auth.loginWithGoogle(context as androidx.fragment.app.FragmentActivity)
                                                val user = Erebor.user.value
                                                if (user != null) {
                                                    onAuthenticated(user)
                                                }
                                            } catch (e: Exception) {
                                                error = e.message ?: "Google sign-in failed"
                                            } finally {
                                                loading = false
                                            }
                                        }
                                    }
                                    else -> {
                                        error = "This sign-in method is not yet implemented"
                                    }
                                }
                            },
                            loading = loading
                        )
                    }
                    
                    LoginStep.EMAIL_INPUT -> {
                        EmailInputStep(
                            email = email,
                            onEmailChange = { email = it },
                            onContinue = {
                                coroutineScope.launch {
                                    try {
                                        loading = true
                                        error = null
                                        otpSession = Erebor.auth.loginWithEmail(email)
                                        currentStep = LoginStep.OTP_VERIFICATION
                                    } catch (e: Exception) {
                                        error = e.message ?: "Failed to send verification code"
                                    } finally {
                                        loading = false
                                    }
                                }
                            },
                            onBack = { currentStep = LoginStep.METHOD_SELECTION },
                            loading = loading
                        )
                    }
                    
                    LoginStep.PHONE_INPUT -> {
                        PhoneInputStep(
                            phone = phone,
                            onPhoneChange = { phone = it },
                            onContinue = {
                                coroutineScope.launch {
                                    try {
                                        loading = true
                                        error = null
                                        otpSession = Erebor.auth.loginWithPhone(phone)
                                        currentStep = LoginStep.OTP_VERIFICATION
                                    } catch (e: Exception) {
                                        error = e.message ?: "Failed to send verification code"
                                    } finally {
                                        loading = false
                                    }
                                }
                            },
                            onBack = { currentStep = LoginStep.METHOD_SELECTION },
                            loading = loading
                        )
                    }
                    
                    LoginStep.OTP_VERIFICATION -> {
                        OtpVerificationStep(
                            code = otpCode,
                            onCodeChange = { otpCode = it },
                            contactInfo = otpSession?.contact ?: "",
                            onVerify = {
                                coroutineScope.launch {
                                    try {
                                        loading = true
                                        error = null
                                        val session = otpSession ?: return@launch
                                        
                                        when (selectedMethod) {
                                            LoginMethod.EMAIL -> {
                                                Erebor.auth.verifyEmailOtp(session, otpCode)
                                            }
                                            LoginMethod.PHONE -> {
                                                Erebor.auth.verifyPhoneOtp(session, otpCode)
                                            }
                                            else -> throw IllegalStateException("Invalid OTP method")
                                        }
                                        
                                        val user = Erebor.user.value
                                        if (user != null) {
                                            onAuthenticated(user)
                                        }
                                    } catch (e: Exception) {
                                        error = e.message ?: "Verification failed"
                                    } finally {
                                        loading = false
                                    }
                                }
                            },
                            onBack = {
                                when (selectedMethod) {
                                    LoginMethod.EMAIL -> currentStep = LoginStep.EMAIL_INPUT
                                    LoginMethod.PHONE -> currentStep = LoginStep.PHONE_INPUT
                                    else -> currentStep = LoginStep.METHOD_SELECTION
                                }
                            },
                            loading = loading
                        )
                    }
                }
            }
        }
    }
}

private enum class LoginStep {
    METHOD_SELECTION,
    EMAIL_INPUT,
    PHONE_INPUT,
    OTP_VERIFICATION
}

@Composable
private fun MethodSelectionStep(
    methods: List<LoginMethod>,
    onMethodSelected: (LoginMethod) -> Unit,
    loading: Boolean
) {
    Column(
        verticalArrangement = Arrangement.spacedBy(12.dp)
    ) {
        methods.forEach { method ->
            Button(
                onClick = { onMethodSelected(method) },
                modifier = Modifier.fillMaxWidth(),
                enabled = !loading
            ) {
                if (loading) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(20.dp),
                        strokeWidth = 2.dp
                    )
                } else {
                    Text(getMethodDisplayName(method))
                }
            }
        }
    }
}

@Composable
private fun EmailInputStep(
    email: String,
    onEmailChange: (String) -> Unit,
    onContinue: () -> Unit,
    onBack: () -> Unit,
    loading: Boolean
) {
    Column(
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        OutlinedTextField(
            value = email,
            onValueChange = onEmailChange,
            label = { Text("Email Address") },
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Email),
            modifier = Modifier.fillMaxWidth(),
            enabled = !loading
        )
        
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            OutlinedButton(
                onClick = onBack,
                modifier = Modifier.weight(1f),
                enabled = !loading
            ) {
                Text("Back")
            }
            
            Button(
                onClick = onContinue,
                modifier = Modifier.weight(1f),
                enabled = !loading && email.isNotBlank()
            ) {
                if (loading) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(20.dp),
                        strokeWidth = 2.dp
                    )
                } else {
                    Text("Continue")
                }
            }
        }
    }
}

@Composable
private fun PhoneInputStep(
    phone: String,
    onPhoneChange: (String) -> Unit,
    onContinue: () -> Unit,
    onBack: () -> Unit,
    loading: Boolean
) {
    Column(
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        OutlinedTextField(
            value = phone,
            onValueChange = onPhoneChange,
            label = { Text("Phone Number") },
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Phone),
            modifier = Modifier.fillMaxWidth(),
            enabled = !loading
        )
        
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            OutlinedButton(
                onClick = onBack,
                modifier = Modifier.weight(1f),
                enabled = !loading
            ) {
                Text("Back")
            }
            
            Button(
                onClick = onContinue,
                modifier = Modifier.weight(1f),
                enabled = !loading && phone.isNotBlank()
            ) {
                if (loading) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(20.dp),
                        strokeWidth = 2.dp
                    )
                } else {
                    Text("Send Code")
                }
            }
        }
    }
}

@Composable
private fun OtpVerificationStep(
    code: String,
    onCodeChange: (String) -> Unit,
    contactInfo: String,
    onVerify: () -> Unit,
    onBack: () -> Unit,
    loading: Boolean
) {
    Column(
        verticalArrangement = Arrangement.spacedBy(16.dp)
    ) {
        Text(
            text = "Enter the verification code sent to $contactInfo",
            style = MaterialTheme.typography.bodyMedium,
            color = MaterialTheme.colorScheme.onSurfaceVariant
        )
        
        OutlinedTextField(
            value = code,
            onValueChange = onCodeChange,
            label = { Text("Verification Code") },
            keyboardOptions = KeyboardOptions(keyboardType = KeyboardType.Number),
            modifier = Modifier.fillMaxWidth(),
            enabled = !loading
        )
        
        Row(
            modifier = Modifier.fillMaxWidth(),
            horizontalArrangement = Arrangement.spacedBy(12.dp)
        ) {
            OutlinedButton(
                onClick = onBack,
                modifier = Modifier.weight(1f),
                enabled = !loading
            ) {
                Text("Back")
            }
            
            Button(
                onClick = onVerify,
                modifier = Modifier.weight(1f),
                enabled = !loading && code.isNotBlank()
            ) {
                if (loading) {
                    CircularProgressIndicator(
                        modifier = Modifier.size(20.dp),
                        strokeWidth = 2.dp
                    )
                } else {
                    Text("Verify")
                }
            }
        }
    }
}

private fun getMethodDisplayName(method: LoginMethod): String {
    return when (method) {
        LoginMethod.EMAIL -> "Continue with Email"
        LoginMethod.PHONE -> "Continue with Phone"
        LoginMethod.GOOGLE -> "Continue with Google"
        LoginMethod.APPLE -> "Continue with Apple"
        LoginMethod.TWITTER -> "Continue with Twitter"
        LoginMethod.DISCORD -> "Continue with Discord"
        LoginMethod.GITHUB -> "Continue with GitHub"
        LoginMethod.SIWE -> "Sign-In with Ethereum"
    }
}