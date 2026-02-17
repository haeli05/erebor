package io.erebor.sdk

import io.erebor.sdk.models.*
import io.erebor.sdk.network.ApiClient
import io.erebor.sdk.wallet.BiometricGate
import io.erebor.sdk.wallet.WalletManager
import io.mockk.*
import kotlinx.coroutines.flow.first
import kotlinx.coroutines.test.runTest
import org.junit.Before
import org.junit.Test
import org.junit.Assert.*

class WalletManagerTest {
    
    private lateinit var walletManager: WalletManager
    private lateinit var mockApiClient: ApiClient
    private lateinit var mockBiometricGate: BiometricGate
    
    @Before
    fun setup() {
        mockApiClient = mockk()
        mockBiometricGate = mockk()
        
        // Default biometric behavior
        every { mockBiometricGate.isAvailable } returns true
        coEvery { mockBiometricGate.authenticate(any(), any(), any(), any()) } returns true
        
        walletManager = WalletManager(mockApiClient, mockBiometricGate)
    }
    
    @Test
    fun `createWallet requires biometric authentication`() = runTest {
        val mockWallet = EreborWallet(
            id = "wallet123",
            address = "0x1234567890abcdef1234567890abcdef12345678",
            chainId = 1,
            chainType = ChainType.EVM,
            createdAt = "2023-01-01T00:00:00Z"
        )
        
        coEvery { mockApiClient.createWallet(null) } returns mockWallet
        coEvery { mockApiClient.listWallets() } returns listOf(mockWallet)
        
        val result = walletManager.createWallet()
        
        assertEquals(mockWallet, result)
        
        // Verify biometric authentication was required
        coVerify { 
            mockBiometricGate.authenticate(
                reason = "Authenticate to create a new wallet",
                title = "Create Wallet",
                subtitle = "Biometric authentication required"
            )
        }
        
        coVerify { mockApiClient.createWallet(null) }
        coVerify { mockApiClient.listWallets() }
    }
    
    @Test
    fun `createWallet fails when biometric authentication fails`() = runTest {
        coEvery { mockBiometricGate.authenticate(any(), any(), any(), any()) } returns false
        
        try {
            walletManager.createWallet()
            fail("Expected BiometricException to be thrown")
        } catch (e: BiometricException) {
            assertEquals("BIOMETRIC_REQUIRED", e.code)
        }
        
        // Verify API was not called
        coVerify(exactly = 0) { mockApiClient.createWallet(any()) }
    }
    
    @Test
    fun `createWallet with specific chainId`() = runTest {
        val chainId = 137L // Polygon
        val mockWallet = EreborWallet(
            id = "wallet123",
            address = "0x1234567890abcdef1234567890abcdef12345678",
            chainId = chainId,
            chainType = ChainType.EVM,
            createdAt = "2023-01-01T00:00:00Z"
        )
        
        coEvery { mockApiClient.createWallet(chainId) } returns mockWallet
        coEvery { mockApiClient.listWallets() } returns listOf(mockWallet)
        
        val result = walletManager.createWallet(chainId)
        
        assertEquals(mockWallet, result)
        assertEquals(chainId, result.chainId)
        
        coVerify { mockApiClient.createWallet(chainId) }
    }
    
    @Test
    fun `listWallets returns user wallets`() = runTest {
        val wallets = listOf(
            EreborWallet("wallet1", "0xaddr1", 1, ChainType.EVM, createdAt = "2023-01-01T00:00:00Z"),
            EreborWallet("wallet2", "0xaddr2", 137, ChainType.EVM, createdAt = "2023-01-01T00:00:00Z")
        )
        
        coEvery { mockApiClient.listWallets() } returns wallets
        
        val result = walletManager.listWallets()
        
        assertEquals(wallets, result)
        
        // Check state is updated
        val walletsState = walletManager.walletsState.first()
        assertEquals(wallets, walletsState)
        
        coVerify { mockApiClient.listWallets() }
    }
    
    @Test
    fun `signMessage requires biometric authentication`() = runTest {
        val walletId = "wallet123"
        val message = "Hello, world!"
        val signature = "0xsignature123"
        
        coEvery { mockApiClient.signMessage(walletId, message) } returns signature
        
        val result = walletManager.signMessage(walletId, message)
        
        assertEquals(signature, result)
        
        coVerify { 
            mockBiometricGate.authenticate(
                reason = "Authenticate to sign message",
                title = "Sign Message",
                subtitle = "Confirm signing of message"
            )
        }
        
        coVerify { mockApiClient.signMessage(walletId, message) }
    }
    
    @Test
    fun `signTransaction requires biometric authentication`() = runTest {
        val walletId = "wallet123"
        val tx = TransactionRequest(
            to = "0xrecipient",
            value = "1000000000000000000", // 1 ETH
            chainId = 1
        )
        val signedTxData = "0xsignedtransaction"
        
        coEvery { mockApiClient.signTransaction(walletId, tx) } returns signedTxData
        
        val result = walletManager.signTransaction(walletId, tx)
        
        assertEquals(signedTxData, result.raw)
        assertTrue(result.hash.startsWith("0x"))
        
        coVerify { 
            mockBiometricGate.authenticate(
                reason = "Authenticate to sign transaction",
                title = "Sign Transaction",
                subtitle = "Confirm transaction to ${tx.to}"
            )
        }
        
        coVerify { mockApiClient.signTransaction(walletId, tx) }
    }
    
    @Test
    fun `sendTransaction requires biometric authentication`() = runTest {
        val walletId = "wallet123"
        val tx = TransactionRequest(
            to = "0xrecipient",
            value = "1000000000000000000", // 1 ETH
            chainId = 1
        )
        val txHash = "0xtransactionhash123"
        
        coEvery { mockApiClient.sendTransaction(walletId, tx) } returns txHash
        
        val result = walletManager.sendTransaction(walletId, tx)
        
        assertEquals(txHash, result)
        
        coVerify { 
            mockBiometricGate.authenticate(
                reason = "Authenticate to send transaction",
                title = "Send Transaction",
                subtitle = "Confirm sending 1.0 ETH to ${tx.to}"
            )
        }
        
        coVerify { mockApiClient.sendTransaction(walletId, tx) }
    }
    
    @Test
    fun `sendTransaction fails when biometric authentication fails`() = runTest {
        val walletId = "wallet123"
        val tx = TransactionRequest(
            to = "0xrecipient",
            value = "1000000000000000000",
            chainId = 1
        )
        
        coEvery { mockBiometricGate.authenticate(any(), any(), any(), any()) } returns false
        
        try {
            walletManager.sendTransaction(walletId, tx)
            fail("Expected BiometricException to be thrown")
        } catch (e: BiometricException) {
            assertEquals("BIOMETRIC_REQUIRED", e.code)
        }
        
        coVerify(exactly = 0) { mockApiClient.sendTransaction(any(), any()) }
    }
    
    @Test
    fun `getWallet returns correct wallet by id`() = runTest {
        val wallets = listOf(
            EreborWallet("wallet1", "0xaddr1", 1, ChainType.EVM, createdAt = "2023-01-01T00:00:00Z"),
            EreborWallet("wallet2", "0xaddr2", 137, ChainType.EVM, createdAt = "2023-01-01T00:00:00Z")
        )
        
        coEvery { mockApiClient.listWallets() } returns wallets
        
        // Load wallets first
        walletManager.listWallets()
        
        val result = walletManager.getWallet("wallet2")
        
        assertNotNull(result)
        assertEquals("wallet2", result?.id)
        assertEquals("0xaddr2", result?.address)
    }
    
    @Test
    fun `getWallet returns null for non-existent wallet`() = runTest {
        coEvery { mockApiClient.listWallets() } returns emptyList()
        
        walletManager.listWallets()
        
        val result = walletManager.getWallet("nonexistent")
        
        assertNull(result)
    }
    
    @Test
    fun `getWalletsForChain returns filtered wallets`() = runTest {
        val wallets = listOf(
            EreborWallet("wallet1", "0xaddr1", 1, ChainType.EVM, createdAt = "2023-01-01T00:00:00Z"),
            EreborWallet("wallet2", "0xaddr2", 137, ChainType.EVM, createdAt = "2023-01-01T00:00:00Z"),
            EreborWallet("wallet3", "0xaddr3", 1, ChainType.EVM, createdAt = "2023-01-01T00:00:00Z")
        )
        
        coEvery { mockApiClient.listWallets() } returns wallets
        
        walletManager.listWallets()
        
        val ethereumWallets = walletManager.getWalletsForChain(1)
        val polygonWallets = walletManager.getWalletsForChain(137)
        
        assertEquals(2, ethereumWallets.size)
        assertEquals(1, polygonWallets.size)
        assertTrue(ethereumWallets.all { it.chainId == 1L })
        assertTrue(polygonWallets.all { it.chainId == 137L })
    }
    
    @Test
    fun `getPrimaryWallet returns first wallet`() = runTest {
        val wallets = listOf(
            EreborWallet("wallet1", "0xaddr1", 1, ChainType.EVM, createdAt = "2023-01-01T00:00:00Z"),
            EreborWallet("wallet2", "0xaddr2", 137, ChainType.EVM, createdAt = "2023-01-01T00:00:00Z")
        )
        
        coEvery { mockApiClient.listWallets() } returns wallets
        
        walletManager.listWallets()
        
        val result = walletManager.getPrimaryWallet()
        
        assertNotNull(result)
        assertEquals("wallet1", result?.id)
    }
    
    @Test
    fun `getPrimaryWallet returns null when no wallets`() = runTest {
        coEvery { mockApiClient.listWallets() } returns emptyList()
        
        walletManager.listWallets()
        
        val result = walletManager.getPrimaryWallet()
        
        assertNull(result)
    }
    
    @Test
    fun `initialize loads wallets without throwing on error`() = runTest {
        // First call succeeds
        coEvery { mockApiClient.listWallets() } returns emptyList()
        
        walletManager.initialize()
        
        // Verify no exception is thrown and wallets state is updated
        val walletsState = walletManager.walletsState.first()
        assertEquals(emptyList<EreborWallet>(), walletsState)
        
        coVerify { mockApiClient.listWallets() }
    }
    
    @Test
    fun `operations work without biometric when not available`() = runTest {
        every { mockBiometricGate.isAvailable } returns false
        
        val signature = "0xsignature"
        coEvery { mockApiClient.signMessage("wallet1", "message") } returns signature
        
        val result = walletManager.signMessage("wallet1", "message")
        
        assertEquals(signature, result)
        
        // Verify biometric authentication was not attempted
        coVerify(exactly = 0) { mockBiometricGate.authenticate(any(), any(), any(), any()) }
        coVerify { mockApiClient.signMessage("wallet1", "message") }
    }
}