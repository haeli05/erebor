package io.erebor.sdk.crypto

import org.bouncycastle.crypto.digests.KeccakDigest
import org.bouncycastle.crypto.signers.ECDSASigner
import org.bouncycastle.crypto.signers.HMacDSAKCalculator
import org.bouncycastle.crypto.params.ECPrivateKeyParameters
import org.bouncycastle.crypto.params.ECDomainParameters
import org.bouncycastle.math.ec.ECConstants
import org.bouncycastle.math.ec.custom.sec.SecP256K1Curve
import org.bouncycastle.math.ec.custom.sec.SecP256K1Point
import java.math.BigInteger
import java.security.SecureRandom

/**
 * Cryptographic signer for secp256k1 signatures used in blockchain transactions.
 * 
 * This class handles the low-level cryptographic operations for signing messages
 * and transactions using the secp256k1 elliptic curve.
 */
class Signer {
    
    private val curve = SecP256K1Curve()
    private val domainParams = ECDomainParameters(
        curve,
        curve.g,
        curve.n,
        curve.h
    )
    
    /**
     * Sign a message hash using the provided private key.
     * 
     * @param messageHash The hash of the message to sign (32 bytes)
     * @param privateKey The private key to sign with
     * @return ECDSA signature (r, s, v)
     */
    fun signMessageHash(messageHash: ByteArray, privateKey: ByteArray): ECDSASignature {
        require(messageHash.size == 32) { "Message hash must be 32 bytes" }
        require(privateKey.size == 32) { "Private key must be 32 bytes" }
        
        val privKey = BigInteger(1, privateKey)
        val keyParams = ECPrivateKeyParameters(privKey, domainParams)
        
        val signer = ECDSASigner(HMacDSAKCalculator(KeccakDigest(256)))
        signer.init(true, keyParams)
        
        val signature = signer.generateSignature(messageHash)
        val r = signature[0]
        val s = signature[1]
        
        // Calculate recovery ID (v)
        val recoveryId = calculateRecoveryId(messageHash, r, s, privateKey)
        
        return ECDSASignature(r, s, recoveryId)
    }
    
    /**
     * Sign an Ethereum message with the standard prefix.
     * 
     * @param message The message to sign
     * @param privateKey The private key to sign with
     * @return ECDSA signature
     */
    fun signEthereumMessage(message: String, privateKey: ByteArray): ECDSASignature {
        val messageBytes = message.toByteArray(Charsets.UTF_8)
        val prefix = "\u0019Ethereum Signed Message:\n${messageBytes.size}".toByteArray()
        val fullMessage = prefix + messageBytes
        
        val messageHash = keccak256(fullMessage)
        return signMessageHash(messageHash, privateKey)
    }
    
    /**
     * Sign an EIP-712 typed data hash.
     * 
     * @param domainSeparator The EIP-712 domain separator
     * @param structHash The hash of the typed data struct
     * @param privateKey The private key to sign with
     * @return ECDSA signature
     */
    fun signTypedData(domainSeparator: ByteArray, structHash: ByteArray, privateKey: ByteArray): ECDSASignature {
        val prefix = "\u0019\u0001".toByteArray()
        val fullMessage = prefix + domainSeparator + structHash
        
        val messageHash = keccak256(fullMessage)
        return signMessageHash(messageHash, privateKey)
    }
    
    /**
     * Recover the public key from a signature and message hash.
     * 
     * @param messageHash The hash that was signed
     * @param signature The signature
     * @return The recovered public key (64 bytes, uncompressed without prefix)
     */
    fun recoverPublicKey(messageHash: ByteArray, signature: ECDSASignature): ByteArray {
        val point = recoverPoint(messageHash, signature)
        
        // Return uncompressed public key without the 0x04 prefix
        val encoded = point.getEncoded(false)
        return encoded.sliceArray(1..64) // Remove the 0x04 prefix
    }
    
    /**
     * Derive an Ethereum address from a public key.
     * 
     * @param publicKey The public key (64 bytes, uncompressed)
     * @return Ethereum address (20 bytes)
     */
    fun publicKeyToAddress(publicKey: ByteArray): ByteArray {
        require(publicKey.size == 64) { "Public key must be 64 bytes" }
        
        val hash = keccak256(publicKey)
        return hash.sliceArray(12..31) // Take last 20 bytes
    }
    
    /**
     * Generate a random private key.
     * 
     * @return 32-byte private key
     */
    fun generatePrivateKey(): ByteArray {
        val random = SecureRandom()
        val privateKey = ByteArray(32)
        
        do {
            random.nextBytes(privateKey)
            val privKeyBigInt = BigInteger(1, privateKey)
        } while (privKeyBigInt >= domainParams.n || privKeyBigInt == BigInteger.ZERO)
        
        return privateKey
    }
    
    private fun calculateRecoveryId(messageHash: ByteArray, r: BigInteger, s: BigInteger, privateKey: ByteArray): Int {
        // Try different recovery IDs to find the correct one
        for (recoveryId in 0..3) {
            try {
                val point = recoverPoint(messageHash, ECDSASignature(r, s, recoveryId))
                val publicKey = point.getEncoded(false).sliceArray(1..64)
                
                // Check if this recovery ID produces the correct public key
                val expectedPublicKey = getPublicKeyFromPrivate(privateKey)
                if (publicKey.contentEquals(expectedPublicKey)) {
                    return recoveryId
                }
            } catch (e: Exception) {
                continue
            }
        }
        throw IllegalStateException("Could not determine recovery ID")
    }
    
    private fun recoverPoint(messageHash: ByteArray, signature: ECDSASignature): SecP256K1Point {
        val r = signature.r
        val s = signature.s
        val recoveryId = signature.recoveryId
        
        val isYEven = (recoveryId and 1) == 0
        val isSecondKey = (recoveryId and 2) != 0
        
        val x = if (isSecondKey) r + domainParams.n else r
        
        val point = curve.decodePoint(byteArrayOf(if (isYEven) 0x02 else 0x03) + x.toByteArray())
        val rInv = r.modInverse(domainParams.n)
        val e = BigInteger(1, messageHash)
        
        return point.multiply(s).subtract(domainParams.g.multiply(e)).multiply(rInv) as SecP256K1Point
    }
    
    private fun getPublicKeyFromPrivate(privateKey: ByteArray): ByteArray {
        val privKeyBigInt = BigInteger(1, privateKey)
        val point = domainParams.g.multiply(privKeyBigInt)
        val encoded = point.getEncoded(false)
        return encoded.sliceArray(1..64) // Remove 0x04 prefix
    }
    
    private fun keccak256(input: ByteArray): ByteArray {
        val digest = KeccakDigest(256)
        val output = ByteArray(digest.digestSize)
        digest.update(input, 0, input.size)
        digest.doFinal(output, 0)
        return output
    }
}

/**
 * Represents an ECDSA signature with recovery ID.
 */
data class ECDSASignature(
    val r: BigInteger,
    val s: BigInteger,
    val recoveryId: Int
) {
    /**
     * Convert signature to hex string format.
     */
    fun toHexString(): String {
        val rBytes = r.toByteArray().let { if (it.size > 32) it.sliceArray(1..32) else it.padStart(32) }
        val sBytes = s.toByteArray().let { if (it.size > 32) it.sliceArray(1..32) else it.padStart(32) }
        val vByte = (recoveryId + 27).toByte()
        
        return "0x" + (rBytes + sBytes + vByte).joinToString("") { "%02x".format(it) }
    }
    
    private fun ByteArray.padStart(length: Int): ByteArray {
        return if (this.size >= length) {
            this
        } else {
            ByteArray(length - this.size) + this
        }
    }
}