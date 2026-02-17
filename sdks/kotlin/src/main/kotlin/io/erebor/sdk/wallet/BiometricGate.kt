package io.erebor.sdk.wallet

import android.content.Context
import androidx.biometric.BiometricManager
import androidx.biometric.BiometricPrompt
import androidx.fragment.app.FragmentActivity
import androidx.lifecycle.lifecycleScope
import io.erebor.sdk.models.BiometricException
import kotlinx.coroutines.suspendCancellableCoroutine
import java.util.concurrent.Executor
import kotlin.coroutines.resume

/**
 * Types of biometric authentication available.
 */
enum class BiometricType {
    FINGERPRINT,
    FACE,
    IRIS,
    MULTIPLE,
    NONE
}

/**
 * Handles biometric authentication using AndroidX Biometric library.
 */
class BiometricGate(private val context: Context) {
    
    private val biometricManager = BiometricManager.from(context)
    
    /**
     * Check if biometric authentication is available on this device.
     */
    val isAvailable: Boolean
        get() = biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_WEAK) == BiometricManager.BIOMETRIC_SUCCESS
    
    /**
     * Get the type of biometric authentication available.
     */
    val biometricType: BiometricType
        get() {
            return when (biometricManager.canAuthenticate(BiometricManager.Authenticators.BIOMETRIC_WEAK)) {
                BiometricManager.BIOMETRIC_SUCCESS -> {
                    // We can't easily determine the specific type, so return MULTIPLE as a safe default
                    BiometricType.MULTIPLE
                }
                else -> BiometricType.NONE
            }
        }
    
    /**
     * Authenticate the user using biometric authentication.
     * 
     * @param reason The reason for authentication (displayed to user)
     * @param title The title for the authentication prompt
     * @param subtitle Optional subtitle for the authentication prompt
     * @param negativeButtonText Text for the negative/cancel button
     * @return true if authentication was successful, false otherwise
     */
    suspend fun authenticate(
        reason: String,
        title: String = "Authenticate",
        subtitle: String? = null,
        negativeButtonText: String = "Cancel"
    ): Boolean {
        if (!isAvailable) {
            throw BiometricException("Biometric authentication not available", "BIOMETRIC_NOT_AVAILABLE")
        }
        
        // For suspend functions, we need to be in a FragmentActivity context
        val activity = context as? FragmentActivity
            ?: throw BiometricException("BiometricGate requires FragmentActivity context", "INVALID_CONTEXT")
        
        return suspendCancellableCoroutine { continuation ->
            val executor: Executor = androidx.core.content.ContextCompat.getMainExecutor(context)
            
            val biometricPrompt = BiometricPrompt(activity, executor, object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    if (continuation.isActive) {
                        continuation.resume(false)
                    }
                }
                
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    if (continuation.isActive) {
                        continuation.resume(true)
                    }
                }
                
                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    // Don't complete the continuation here - let the user try again
                }
            })
            
            val promptInfo = BiometricPrompt.PromptInfo.Builder()
                .setTitle(title)
                .apply {
                    if (subtitle != null) {
                        setSubtitle(subtitle)
                    }
                }
                .setDescription(reason)
                .setNegativeButtonText(negativeButtonText)
                .setAllowedAuthenticators(BiometricManager.Authenticators.BIOMETRIC_WEAK)
                .build()
            
            try {
                biometricPrompt.authenticate(promptInfo)
            } catch (e: Exception) {
                if (continuation.isActive) {
                    continuation.resume(false)
                }
            }
            
            continuation.invokeOnCancellation {
                try {
                    biometricPrompt.cancelAuthentication()
                } catch (e: Exception) {
                    // Ignore cancellation errors
                }
            }
        }
    }
    
    /**
     * Check if device credential authentication (PIN, pattern, password) is available.
     */
    val isDeviceCredentialAvailable: Boolean
        get() = biometricManager.canAuthenticate(BiometricManager.Authenticators.DEVICE_CREDENTIAL) == BiometricManager.BIOMETRIC_SUCCESS
    
    /**
     * Authenticate using either biometric or device credential.
     */
    suspend fun authenticateWithFallback(
        reason: String,
        title: String = "Authenticate",
        subtitle: String? = null
    ): Boolean {
        val activity = context as? FragmentActivity
            ?: throw BiometricException("BiometricGate requires FragmentActivity context", "INVALID_CONTEXT")
        
        return suspendCancellableCoroutine { continuation ->
            val executor: Executor = androidx.core.content.ContextCompat.getMainExecutor(context)
            
            val biometricPrompt = BiometricPrompt(activity, executor, object : BiometricPrompt.AuthenticationCallback() {
                override fun onAuthenticationError(errorCode: Int, errString: CharSequence) {
                    super.onAuthenticationError(errorCode, errString)
                    if (continuation.isActive) {
                        continuation.resume(false)
                    }
                }
                
                override fun onAuthenticationSucceeded(result: BiometricPrompt.AuthenticationResult) {
                    super.onAuthenticationSucceeded(result)
                    if (continuation.isActive) {
                        continuation.resume(true)
                    }
                }
                
                override fun onAuthenticationFailed() {
                    super.onAuthenticationFailed()
                    // Don't complete the continuation here - let the user try again
                }
            })
            
            val promptInfo = BiometricPrompt.PromptInfo.Builder()
                .setTitle(title)
                .apply {
                    if (subtitle != null) {
                        setSubtitle(subtitle)
                    }
                }
                .setDescription(reason)
                .setAllowedAuthenticators(
                    BiometricManager.Authenticators.BIOMETRIC_WEAK or 
                    BiometricManager.Authenticators.DEVICE_CREDENTIAL
                )
                .build()
            
            try {
                biometricPrompt.authenticate(promptInfo)
            } catch (e: Exception) {
                if (continuation.isActive) {
                    continuation.resume(false)
                }
            }
            
            continuation.invokeOnCancellation {
                try {
                    biometricPrompt.cancelAuthentication()
                } catch (e: Exception) {
                    // Ignore cancellation errors
                }
            }
        }
    }
}