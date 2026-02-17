package io.erebor.sdk.auth

import android.app.Activity
import android.content.Intent
import android.net.Uri
import androidx.browser.customtabs.CustomTabsIntent
import io.erebor.sdk.models.AuthException
import kotlinx.coroutines.CompletableDeferred
import kotlinx.coroutines.suspendCancellableCoroutine
import java.security.MessageDigest
import java.util.*
import kotlin.coroutines.resume
import kotlin.coroutines.resumeWithException

/**
 * Google OAuth authentication result.
 */
data class GoogleAuthCode(
    val code: String,
    val redirectUri: String
)

/**
 * Handles Google OAuth authentication using Chrome Custom Tabs with PKCE.
 */
class GoogleAuthProvider {
    
    companion object {
        private const val GOOGLE_AUTH_URL = "https://accounts.google.com/o/oauth2/v2/auth"
        private const val REDIRECT_URI = "io.erebor.auth://callback"
        
        // You would typically get this from your app configuration
        private const val CLIENT_ID = "your-google-client-id.apps.googleusercontent.com"
    }
    
    private var pendingAuth: CompletableDeferred<GoogleAuthCode>? = null
    
    /**
     * Start Google OAuth authentication flow.
     * 
     * @param activity The activity to launch the authentication from
     * @return GoogleAuthCode containing the authorization code and redirect URI
     */
    suspend fun authenticate(activity: Activity): GoogleAuthCode {
        return suspendCancellableCoroutine { continuation ->
            try {
                val codeVerifier = generateCodeVerifier()
                val codeChallenge = generateCodeChallenge(codeVerifier)
                val state = generateState()
                
                val authUrl = buildAuthUrl(codeChallenge, state)
                
                // Store the pending authentication
                pendingAuth = CompletableDeferred<GoogleAuthCode>().apply {
                    invokeOnCompletion { throwable ->
                        if (throwable != null) {
                            continuation.resumeWithException(throwable)
                        } else {
                            continuation.resume(getCompleted())
                        }
                    }
                }
                
                continuation.invokeOnCancellation {
                    pendingAuth?.cancel()
                    pendingAuth = null
                }
                
                // Launch Chrome Custom Tab
                launchCustomTab(activity, authUrl)
                
            } catch (e: Exception) {
                continuation.resumeWithException(
                    AuthException("Failed to start Google authentication", "GOOGLE_AUTH_FAILED", e)
                )
            }
        }
    }
    
    /**
     * Handle the OAuth callback. This should be called from your deep link handler.
     * 
     * @param uri The callback URI received from Google
     */
    fun handleCallback(uri: Uri) {
        val code = uri.getQueryParameter("code")
        val error = uri.getQueryParameter("error")
        val state = uri.getQueryParameter("state")
        
        val pendingAuth = this.pendingAuth
        
        if (pendingAuth == null) {
            // No pending authentication
            return
        }
        
        if (error != null) {
            pendingAuth.completeExceptionally(
                AuthException("Google authentication failed: $error", "GOOGLE_AUTH_ERROR")
            )
            return
        }
        
        if (code == null) {
            pendingAuth.completeExceptionally(
                AuthException("No authorization code received", "MISSING_AUTH_CODE")
            )
            return
        }
        
        // TODO: Verify state parameter for security
        
        val result = GoogleAuthCode(
            code = code,
            redirectUri = REDIRECT_URI
        )
        
        pendingAuth.complete(result)
        this.pendingAuth = null
    }
    
    private fun buildAuthUrl(codeChallenge: String, state: String): String {
        val uri = Uri.parse(GOOGLE_AUTH_URL).buildUpon()
            .appendQueryParameter("client_id", CLIENT_ID)
            .appendQueryParameter("redirect_uri", REDIRECT_URI)
            .appendQueryParameter("response_type", "code")
            .appendQueryParameter("scope", "openid email profile")
            .appendQueryParameter("code_challenge", codeChallenge)
            .appendQueryParameter("code_challenge_method", "S256")
            .appendQueryParameter("state", state)
            .build()
        
        return uri.toString()
    }
    
    private fun launchCustomTab(activity: Activity, url: String) {
        val intent = CustomTabsIntent.Builder()
            .setShowTitle(true)
            .setStartAnimations(activity, android.R.anim.slide_in_left, android.R.anim.slide_out_right)
            .setExitAnimations(activity, android.R.anim.slide_in_left, android.R.anim.slide_out_right)
            .build()
        
        try {
            intent.launchUrl(activity, Uri.parse(url))
        } catch (e: Exception) {
            // Fallback to regular browser
            val browserIntent = Intent(Intent.ACTION_VIEW, Uri.parse(url))
            activity.startActivity(browserIntent)
        }
    }
    
    private fun generateCodeVerifier(): String {
        val bytes = ByteArray(32)
        Random().nextBytes(bytes)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    }
    
    private fun generateCodeChallenge(codeVerifier: String): String {
        val digest = MessageDigest.getInstance("SHA-256")
        val hash = digest.digest(codeVerifier.toByteArray(Charsets.UTF_8))
        return Base64.getUrlEncoder().withoutPadding().encodeToString(hash)
    }
    
    private fun generateState(): String {
        val bytes = ByteArray(16)
        Random().nextBytes(bytes)
        return Base64.getUrlEncoder().withoutPadding().encodeToString(bytes)
    }
}