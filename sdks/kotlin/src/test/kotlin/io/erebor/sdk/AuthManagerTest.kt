package io.erebor.sdk

import io.erebor.sdk.auth.AuthManager
import io.erebor.sdk.models.*
import io.erebor.sdk.network.ApiClient
import io.erebor.sdk.storage.SecureTokenStore
import io.mockk.*
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import org.junit.Before
import org.junit.Test
import org.junit.Assert.*

class AuthManagerTest {
    
    private lateinit var authManager: AuthManager
    private lateinit var mockApiClient: ApiClient
    private lateinit var mockTokenStore: SecureTokenStore
    
    @Before
    fun setup() {
        mockApiClient = mockk()
        mockTokenStore = mockk()
        
        // Default token store behavior
        every { mockTokenStore.loadTokens() } returns null
        every { mockTokenStore.saveTokens(any()) } just Runs
        every { mockTokenStore.clearTokens() } just Runs
        
        authManager = AuthManager(mockApiClient, mockTokenStore)
    }
    
    @Test
    fun `initial auth state is not authenticated`() = runTest {
        val authState = authManager.authState.first()
        
        assertFalse(authState.authenticated)
        assertNull(authState.user)
        assertTrue(authState.ready)
        assertFalse(authState.loading)
    }
    
    @Test
    fun `loginWithEmail sends OTP and returns session`() = runTest {
        val email = "test@example.com"
        
        coEvery { mockApiClient.sendEmailOtp(email) } just Runs
        
        val session = authManager.loginWithEmail(email)
        
        assertEquals("email_$email", session.sessionId)
        assertEquals(email, session.contact)
        assertTrue(session.expiresAt > System.currentTimeMillis())
        
        coVerify { mockApiClient.sendEmailOtp(email) }
    }
    
    @Test
    fun `verifyEmailOtp completes authentication successfully`() = runTest {
        val session = OtpSession("session123", "test@example.com", System.currentTimeMillis() + 600000)
        val code = "123456"
        
        val mockTokens = AuthTokens("access_token", "refresh_token", 3600)
        val mockUser = EreborUser(
            id = "user123",
            email = "test@example.com",
            wallets = emptyList(),
            linkedAccounts = emptyList(),
            createdAt = "2023-01-01T00:00:00Z"
        )
        
        coEvery { mockApiClient.verifyEmailOtp(session.contact, code) } returns mockTokens
        coEvery { mockApiClient.getMe() } returns mockUser
        
        val result = authManager.verifyEmailOtp(session, code)
        
        assertEquals(mockTokens.accessToken, result.accessToken)
        assertEquals(mockTokens.refreshToken, result.refreshToken)
        assertEquals(mockUser.id, result.userId)
        
        // Check auth state is updated
        val authState = authManager.authState.first()
        assertTrue(authState.authenticated)
        assertEquals(mockUser, authState.user)
        
        verify { mockTokenStore.saveTokens(mockTokens) }
        coVerify { mockApiClient.verifyEmailOtp(session.contact, code) }
        coVerify { mockApiClient.getMe() }
    }
    
    @Test
    fun `loginWithPhone sends OTP and returns session`() = runTest {
        val phone = "+1234567890"
        
        coEvery { mockApiClient.sendPhoneOtp(phone) } just Runs
        
        val session = authManager.loginWithPhone(phone)
        
        assertEquals("phone_$phone", session.sessionId)
        assertEquals(phone, session.contact)
        assertTrue(session.expiresAt > System.currentTimeMillis())
        
        coVerify { mockApiClient.sendPhoneOtp(phone) }
    }
    
    @Test
    fun `logout clears auth state and tokens`() = runTest {
        // Set up authenticated state first
        every { mockTokenStore.loadTokens() } returns AuthTokens("access", "refresh", 3600)
        val mockUser = EreborUser("user123", "test@example.com", emptyList(), emptyList(), "2023-01-01T00:00:00Z")
        
        // Mock successful logout
        coEvery { mockApiClient.logout() } just Runs
        
        authManager.logout()
        
        val authState = authManager.authState.first()
        assertFalse(authState.authenticated)
        assertNull(authState.user)
        assertTrue(authState.ready)
        
        coVerify { mockApiClient.logout() }
        verify { mockTokenStore.clearTokens() }
    }
    
    @Test
    fun `refresh updates tokens and user`() = runTest {
        val newTokens = AuthTokens("new_access", "new_refresh", 3600)
        val mockUser = EreborUser("user123", "test@example.com", emptyList(), emptyList(), "2023-01-01T00:00:00Z")
        
        coEvery { mockApiClient.refreshTokens() } returns newTokens
        coEvery { mockApiClient.getMe() } returns mockUser
        
        val result = authManager.refresh()
        
        assertEquals(newTokens.accessToken, result.accessToken)
        assertEquals(mockUser.id, result.userId)
        
        val authState = authManager.authState.first()
        assertTrue(authState.authenticated)
        assertEquals(mockUser, authState.user)
        
        verify { mockTokenStore.saveTokens(newTokens) }
    }
    
    @Test
    fun `refresh failure clears auth state`() = runTest {
        coEvery { mockApiClient.refreshTokens() } throws NetworkException("Network error", "NETWORK_ERROR")
        
        try {
            authManager.refresh()
            fail("Expected exception to be thrown")
        } catch (e: NetworkException) {
            // Expected
        }
        
        val authState = authManager.authState.first()
        assertFalse(authState.authenticated)
        assertNull(authState.user)
    }
    
    @Test
    fun `loadCurrentUser restores authenticated state`() = runTest {
        val mockTokens = AuthTokens("access", "refresh", 3600)
        val mockUser = EreborUser("user123", "test@example.com", emptyList(), emptyList(), "2023-01-01T00:00:00Z")
        
        every { mockTokenStore.loadTokens() } returns mockTokens
        coEvery { mockApiClient.getMe() } returns mockUser
        
        val result = authManager.loadCurrentUser()
        
        assertNotNull(result)
        assertEquals(mockUser.id, result?.id)
        
        val authState = authManager.authState.first()
        assertTrue(authState.authenticated)
        assertEquals(mockUser, authState.user)
    }
    
    @Test
    fun `loadCurrentUser returns null when no tokens`() = runTest {
        every { mockTokenStore.loadTokens() } returns null
        
        val result = authManager.loadCurrentUser()
        
        assertNull(result)
        
        val authState = authManager.authState.first()
        assertFalse(authState.authenticated)
    }
    
    @Test
    fun `linkAccount adds linked account to user`() = runTest {
        // Set up authenticated state
        val mockUser = EreborUser("user123", "test@example.com", emptyList(), emptyList(), "2023-01-01T00:00:00Z")
        val linkedAccount = LinkedAccount(AuthProvider.GOOGLE, "google123", "test@gmail.com", null)
        val updatedUser = mockUser.copy(linkedAccounts = listOf(linkedAccount))
        
        // Mock authenticated state
        every { mockTokenStore.loadTokens() } returns AuthTokens("access", "refresh", 3600)
        
        coEvery { mockApiClient.linkAccount("google", "token123") } returns linkedAccount
        coEvery { mockApiClient.getMe() } returns updatedUser
        
        val result = authManager.linkAccount(AuthProvider.GOOGLE, "token123")
        
        assertEquals(linkedAccount, result)
        
        // Verify user state is updated
        val authState = authManager.authState.first()
        assertEquals(1, authState.user?.linkedAccounts?.size)
    }
    
    @Test(expected = AuthException::class)
    fun `linkAccount throws when not authenticated`() = runTest {
        every { mockTokenStore.loadTokens() } returns null
        
        authManager.linkAccount(AuthProvider.GOOGLE, "token123")
    }
}