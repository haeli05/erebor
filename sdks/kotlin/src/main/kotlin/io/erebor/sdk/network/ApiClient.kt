package io.erebor.sdk.network

import io.erebor.sdk.models.*
import io.erebor.sdk.storage.SecureTokenStore
import kotlinx.coroutines.Dispatchers
import kotlinx.coroutines.withContext
import kotlinx.serialization.decodeFromString
import kotlinx.serialization.encodeToString
import kotlinx.serialization.json.Json
import okhttp3.*
import okhttp3.MediaType.Companion.toMediaType
import okhttp3.RequestBody.Companion.toRequestBody
import java.io.IOException
import java.util.concurrent.TimeUnit

/**
 * HTTP client for communicating with the Erebor API.
 * Handles authentication, token refresh, and request/response serialization.
 */
class ApiClient(
    private val apiUrl: String,
    private val tokenStore: SecureTokenStore,
    private val tokenPrefix: String = "erebor"
) {
    
    private val json = Json {
        ignoreUnknownKeys = true
        encodeDefaults = false
    }
    
    private val mediaType = "application/json".toMediaType()
    
    private val httpClient = OkHttpClient.Builder()
        .connectTimeout(30, TimeUnit.SECONDS)
        .readTimeout(30, TimeUnit.SECONDS)
        .writeTimeout(30, TimeUnit.SECONDS)
        .addInterceptor(AuthInterceptor())
        .authenticator(TokenAuthenticator())
        .build()
    
    private val baseUrl = apiUrl.trimEnd('/')
    
    // Auth endpoints
    suspend fun googleAuth(code: String, redirectUri: String): AuthTokens {
        val request = mapOf(
            "code" to code,
            "redirectUri" to redirectUri
        )
        val response = post<AuthTokens>("/auth/google", request)
        tokenStore.saveTokens(response)
        return response
    }
    
    suspend fun sendEmailOtp(email: String) {
        val request = mapOf("email" to email)
        post<Unit>("/auth/email/send", request)
    }
    
    suspend fun verifyEmailOtp(email: String, code: String): AuthTokens {
        val request = mapOf(
            "email" to email,
            "code" to code
        )
        val response = post<AuthTokens>("/auth/email/verify", request)
        tokenStore.saveTokens(response)
        return response
    }
    
    suspend fun sendPhoneOtp(phone: String) {
        val request = mapOf("phone" to phone)
        post<Unit>("/auth/phone/send", request)
    }
    
    suspend fun verifyPhoneOtp(phone: String, code: String): AuthTokens {
        val request = mapOf(
            "phone" to phone,
            "code" to code
        )
        val response = post<AuthTokens>("/auth/phone/verify", request)
        tokenStore.saveTokens(response)
        return response
    }
    
    suspend fun getSiweNonce(): String {
        val response = get<SiweNonceResponse>("/auth/siwe/nonce")
        return response.nonce
    }
    
    suspend fun verifySiwe(message: String, signature: String): AuthTokens {
        val request = mapOf(
            "message" to message,
            "signature" to signature
        )
        val response = post<AuthTokens>("/auth/siwe/verify", request)
        tokenStore.saveTokens(response)
        return response
    }
    
    suspend fun refreshTokens(): AuthTokens {
        val currentTokens = tokenStore.loadTokens()
            ?: throw AuthException("No refresh token available", "NO_REFRESH_TOKEN")
        
        val request = mapOf("refreshToken" to currentTokens.refreshToken)
        val response = post<AuthTokens>("/auth/refresh", request)
        tokenStore.saveTokens(response)
        return response
    }
    
    suspend fun logout() {
        try {
            post<Unit>("/auth/logout", emptyMap<String, String>())
        } catch (e: Exception) {
            // Continue with logout even if API call fails
        } finally {
            tokenStore.clearTokens()
        }
    }
    
    // User endpoints
    suspend fun getMe(): EreborUser {
        return get("/user/me")
    }
    
    // Wallet endpoints
    suspend fun createWallet(chainId: Long?): EreborWallet {
        val request = if (chainId != null) {
            mapOf("chainId" to chainId)
        } else {
            emptyMap()
        }
        return post("/wallets", request)
    }
    
    suspend fun listWallets(): List<EreborWallet> {
        return get("/wallets")
    }
    
    suspend fun signMessage(walletId: String, message: String): String {
        val request = mapOf("message" to message)
        val response = post<SignatureResponse>("/wallets/$walletId/sign", request)
        return response.signature
    }
    
    suspend fun signTransaction(walletId: String, tx: TransactionRequest): String {
        val response = post<SignedTransactionResponse>("/wallets/$walletId/sign-transaction", tx)
        return response.signedTransaction
    }
    
    suspend fun sendTransaction(walletId: String, tx: TransactionRequest): String {
        val response = post<TransactionHashResponse>("/wallets/$walletId/send-transaction", tx)
        return response.txHash
    }
    
    // Account linking
    suspend fun linkAccount(provider: String, token: String): LinkedAccount {
        val request = mapOf(
            "provider" to provider,
            "token" to token
        )
        return post("/user/link-account", request)
    }
    
    suspend fun unlinkAccount(provider: String) {
        delete<Unit>("/user/unlink-account/$provider")
    }
    
    // Generic HTTP methods
    private suspend inline fun <reified T> get(endpoint: String): T {
        return request("GET", endpoint, null)
    }
    
    private suspend inline fun <reified T> post(endpoint: String, body: Any?): T {
        return request("POST", endpoint, body)
    }
    
    private suspend inline fun <reified T> delete(endpoint: String): T {
        return request("DELETE", endpoint, null)
    }
    
    private suspend inline fun <reified T> request(
        method: String,
        endpoint: String,
        body: Any?
    ): T = withContext(Dispatchers.IO) {
        val url = "$baseUrl$endpoint"
        
        val requestBuilder = Request.Builder().url(url)
        
        when (method) {
            "GET" -> requestBuilder.get()
            "POST" -> {
                val requestBody = if (body != null) {
                    json.encodeToString(body).toRequestBody(mediaType)
                } else {
                    "".toRequestBody(mediaType)
                }
                requestBuilder.post(requestBody)
            }
            "DELETE" -> requestBuilder.delete()
            else -> throw IllegalArgumentException("Unsupported HTTP method: $method")
        }
        
        val request = requestBuilder.build()
        
        httpClient.newCall(request).execute().use { response ->
            val responseBody = response.body?.string() ?: ""
            
            if (!response.isSuccessful) {
                handleHttpError(response.code, responseBody)
            }
            
            if (T::class == Unit::class) {
                @Suppress("UNCHECKED_CAST")
                return@withContext Unit as T
            }
            
            try {
                val apiResponse = json.decodeFromString<ApiResponse<T>>(responseBody)
                if (!apiResponse.success) {
                    throw NetworkException(
                        apiResponse.error ?: "API request failed",
                        apiResponse.code ?: "API_ERROR"
                    )
                }
                apiResponse.data!!
            } catch (e: kotlinx.serialization.SerializationException) {
                // Try to decode directly as T
                json.decodeFromString<T>(responseBody)
            }
        }
    }
    
    private fun handleHttpError(code: Int, body: String): Nothing {
        when (code) {
            401 -> throw AuthException("Authentication required", "AUTH_REQUIRED")
            403 -> throw AuthException("Access forbidden", "ACCESS_FORBIDDEN")
            404 -> throw NetworkException("Resource not found", "NOT_FOUND")
            in 500..599 -> throw NetworkException("Server error", "SERVER_ERROR")
            else -> {
                try {
                    val errorResponse = json.decodeFromString<ApiResponse<Unit>>(body)
                    throw NetworkException(
                        errorResponse.error ?: "HTTP $code",
                        errorResponse.code ?: "HTTP_ERROR"
                    )
                } catch (e: Exception) {
                    throw NetworkException("HTTP $code", "HTTP_ERROR")
                }
            }
        }
    }
    
    /**
     * Interceptor that adds authentication headers to requests.
     */
    private inner class AuthInterceptor : Interceptor {
        override fun intercept(chain: Interceptor.Chain): Response {
            val original = chain.request()
            
            val tokens = tokenStore.loadTokens()
            if (tokens != null) {
                val request = original.newBuilder()
                    .header("Authorization", "Bearer ${tokens.accessToken}")
                    .build()
                return chain.proceed(request)
            }
            
            return chain.proceed(original)
        }
    }
    
    /**
     * Authenticator that handles token refresh on 401 responses.
     */
    private inner class TokenAuthenticator : Authenticator {
        override fun authenticate(route: Route?, response: Response): Request? {
            if (response.code == 401) {
                val currentTokens = tokenStore.loadTokens()
                if (currentTokens != null) {
                    try {
                        // Synchronously refresh the token
                        val refreshRequest = Request.Builder()
                            .url("$baseUrl/auth/refresh")
                            .post(
                                json.encodeToString(mapOf("refreshToken" to currentTokens.refreshToken))
                                    .toRequestBody(mediaType)
                            )
                            .build()
                        
                        httpClient.newCall(refreshRequest).execute().use { refreshResponse ->
                            if (refreshResponse.isSuccessful) {
                                val body = refreshResponse.body?.string() ?: ""
                                val newTokens = json.decodeFromString<AuthTokens>(body)
                                tokenStore.saveTokens(newTokens)
                                
                                // Retry the original request with new token
                                return response.request.newBuilder()
                                    .header("Authorization", "Bearer ${newTokens.accessToken}")
                                    .build()
                            }
                        }
                    } catch (e: Exception) {
                        // If refresh fails, clear tokens
                        tokenStore.clearTokens()
                    }
                }
            }
            return null
        }
    }
}