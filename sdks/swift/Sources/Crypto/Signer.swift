import Foundation
import CryptoKit

/// Cryptographic signer for blockchain operations using secp256k1 curve
public class Signer {
    
    // MARK: - Message Signing
    
    /// Sign a message using Ethereum's personal message format
    /// - Parameters:
    ///   - message: Message to sign
    ///   - privateKey: 32-byte private key
    /// - Returns: 65-byte signature (r + s + v)
    public static func signPersonalMessage(_ message: String, privateKey: Data) throws -> Data {
        let messageData = message.data(using: .utf8)!
        let prefix = "\u{19}Ethereum Signed Message:\n\(messageData.count)".data(using: .utf8)!
        let fullMessage = prefix + messageData
        
        let hash = keccak256(fullMessage)
        return try signHash(hash, privateKey: privateKey)
    }
    
    /// Sign a raw message hash
    /// - Parameters:
    ///   - message: Message bytes to hash and sign
    ///   - privateKey: 32-byte private key
    /// - Returns: 65-byte signature (r + s + v)
    public static func signMessage(_ message: Data, privateKey: Data) throws -> Data {
        let hash = keccak256(message)
        return try signHash(hash, privateKey: privateKey)
    }
    
    /// Sign a pre-computed hash
    /// - Parameters:
    ///   - hash: 32-byte hash to sign
    ///   - privateKey: 32-byte private key
    /// - Returns: 65-byte signature (r + s + v)
    public static func signHash(_ hash: Data, privateKey: Data) throws -> Data {
        guard hash.count == 32 else {
            throw SigningError.invalidHashLength
        }
        
        guard privateKey.count == 32 else {
            throw SigningError.invalidPrivateKeyLength
        }
        
        // For this example, we'll use P256 as a substitute for secp256k1
        // In production, you would use a proper secp256k1 library
        let key = try P256.Signing.PrivateKey(rawRepresentation: privateKey)
        let signature = try key.signature(for: hash)
        
        // Convert to Ethereum signature format (r + s + v)
        return try convertToEthereumSignature(signature, hash: hash, privateKey: privateKey)
    }
    
    // MARK: - Transaction Signing
    
    /// Sign an Ethereum transaction
    /// - Parameters:
    ///   - transaction: Transaction parameters
    ///   - privateKey: 32-byte private key
    ///   - chainId: Chain ID for EIP-155 replay protection
    /// - Returns: Signed transaction data
    public static func signTransaction(
        _ transaction: EthereumTransaction,
        privateKey: Data,
        chainId: UInt64
    ) throws -> Data {
        // Encode transaction for signing (RLP encoding)
        let encodedTx = try encodeTransactionForSigning(transaction, chainId: chainId)
        
        // Hash the encoded transaction
        let hash = keccak256(encodedTx)
        
        // Sign the hash
        let signature = try signHash(hash, privateKey: privateKey)
        
        // Adjust v value for EIP-155
        let r = signature.prefix(32)
        let s = signature.dropFirst(32).prefix(32)
        let v = signature.last! + UInt8(chainId * 2 + 35)
        
        // Encode signed transaction (RLP encoding with v, r, s)
        return try encodeSignedTransaction(transaction, v: v, r: Data(r), s: Data(s))
    }
    
    // MARK: - Key Operations
    
    /// Derive public key from private key
    /// - Parameter privateKey: 32-byte private key
    /// - Returns: 33-byte compressed public key
    public static func derivePublicKey(_ privateKey: Data) throws -> Data {
        guard privateKey.count == 32 else {
            throw SigningError.invalidPrivateKeyLength
        }
        
        let key = try P256.Signing.PrivateKey(rawRepresentation: privateKey)
        return key.publicKey.compressedRepresentation
    }
    
    /// Derive Ethereum address from private key
    /// - Parameter privateKey: 32-byte private key
    /// - Returns: 20-byte Ethereum address
    public static func deriveAddress(_ privateKey: Data) throws -> Data {
        let publicKey = try derivePublicKey(privateKey)
        return try addressFromPublicKey(publicKey)
    }
    
    /// Derive Ethereum address from public key
    /// - Parameter publicKey: 33-byte compressed or 65-byte uncompressed public key
    /// - Returns: 20-byte Ethereum address
    public static func addressFromPublicKey(_ publicKey: Data) throws -> Data {
        let uncompressedKey: Data
        
        if publicKey.count == 33 {
            // Decompress public key
            uncompressedKey = try decompressPublicKey(publicKey)
        } else if publicKey.count == 65 {
            uncompressedKey = publicKey
        } else {
            throw SigningError.invalidPublicKeyLength
        }
        
        // Remove the 0x04 prefix for uncompressed key
        let keyBytes = uncompressedKey.dropFirst()
        
        // Hash the key bytes and take last 20 bytes
        let hash = keccak256(keyBytes)
        return hash.suffix(20)
    }
    
    // MARK: - Verification
    
    /// Verify a signature against a message
    /// - Parameters:
    ///   - signature: 65-byte signature (r + s + v)
    ///   - message: Original message
    ///   - address: Expected signer address
    /// - Returns: True if signature is valid
    public static func verifySignature(
        _ signature: Data,
        message: String,
        address: Data
    ) throws -> Bool {
        let messageData = message.data(using: .utf8)!
        let prefix = "\u{19}Ethereum Signed Message:\n\(messageData.count)".data(using: .utf8)!
        let fullMessage = prefix + messageData
        let hash = keccak256(fullMessage)
        
        return try verifySignature(signature, hash: hash, address: address)
    }
    
    /// Verify a signature against a hash
    /// - Parameters:
    ///   - signature: 65-byte signature (r + s + v)
    ///   - hash: 32-byte hash
    ///   - address: Expected signer address
    /// - Returns: True if signature is valid
    public static func verifySignature(
        _ signature: Data,
        hash: Data,
        address: Data
    ) throws -> Bool {
        guard signature.count == 65 else {
            throw SigningError.invalidSignatureLength
        }
        
        // Recover public key from signature
        let publicKey = try recoverPublicKey(signature: signature, hash: hash)
        
        // Derive address from recovered public key
        let recoveredAddress = try addressFromPublicKey(publicKey)
        
        return recoveredAddress == address
    }
    
    // MARK: - Recovery
    
    /// Recover public key from signature and hash
    /// - Parameters:
    ///   - signature: 65-byte signature (r + s + v)
    ///   - hash: 32-byte hash that was signed
    /// - Returns: Recovered public key
    public static func recoverPublicKey(signature: Data, hash: Data) throws -> Data {
        guard signature.count == 65 else {
            throw SigningError.invalidSignatureLength
        }
        
        guard hash.count == 32 else {
            throw SigningError.invalidHashLength
        }
        
        // This is a simplified implementation
        // In production, use a proper secp256k1 library for recovery
        
        let r = signature.prefix(32)
        let s = signature.dropFirst(32).prefix(32)
        let v = signature.last!
        
        // For this example, we'll return a placeholder
        // Real implementation would perform EC point recovery
        throw SigningError.recoveryNotImplemented
    }
    
    // MARK: - Private Helpers
    
    private static func convertToEthereumSignature(
        _ signature: P256.Signing.ECDSASignature,
        hash: Data,
        privateKey: Data
    ) throws -> Data {
        // Convert DER signature to raw r,s values
        let derData = signature.derRepresentation
        
        // This is simplified - in production, properly parse DER format
        // and convert to 32-byte r and s values
        var r = Data(count: 32)
        var s = Data(count: 32)
        
        // Placeholder recovery ID
        let v: UInt8 = 27 // This would be calculated based on recovery
        
        return r + s + Data([v])
    }
    
    private static func encodeTransactionForSigning(
        _ transaction: EthereumTransaction,
        chainId: UInt64
    ) throws -> Data {
        // RLP encode transaction parameters for signing
        // This is a simplified implementation
        var fields: [Data] = []
        
        fields.append(encodeNumber(transaction.nonce))
        fields.append(encodeNumber(transaction.gasPrice))
        fields.append(encodeNumber(transaction.gasLimit))
        fields.append(Data(hex: transaction.to))
        fields.append(encodeNumber(transaction.value))
        fields.append(Data(hex: transaction.data))
        fields.append(encodeNumber(chainId))
        fields.append(Data()) // empty r
        fields.append(Data()) // empty s
        
        return try rlpEncode(fields)
    }
    
    private static func encodeSignedTransaction(
        _ transaction: EthereumTransaction,
        v: UInt8,
        r: Data,
        s: Data
    ) throws -> Data {
        var fields: [Data] = []
        
        fields.append(encodeNumber(transaction.nonce))
        fields.append(encodeNumber(transaction.gasPrice))
        fields.append(encodeNumber(transaction.gasLimit))
        fields.append(Data(hex: transaction.to))
        fields.append(encodeNumber(transaction.value))
        fields.append(Data(hex: transaction.data))
        fields.append(Data([v]))
        fields.append(r)
        fields.append(s)
        
        return try rlpEncode(fields)
    }
    
    private static func encodeNumber(_ value: UInt64) -> Data {
        if value == 0 {
            return Data()
        }
        
        var bytes = withUnsafeBytes(of: value.bigEndian) { Data($0) }
        
        // Remove leading zeros
        while bytes.first == 0 && bytes.count > 1 {
            bytes.removeFirst()
        }
        
        return bytes
    }
    
    private static func rlpEncode(_ items: [Data]) throws -> Data {
        // Simplified RLP encoding
        // In production, use a proper RLP library
        var encoded = Data()
        
        for item in items {
            if item.isEmpty {
                encoded.append(0x80)
            } else if item.count == 1 && item[0] < 0x80 {
                encoded.append(item)
            } else {
                if item.count < 56 {
                    encoded.append(UInt8(0x80 + item.count))
                    encoded.append(item)
                } else {
                    let lengthBytes = encodeNumber(UInt64(item.count))
                    encoded.append(UInt8(0xb7 + lengthBytes.count))
                    encoded.append(lengthBytes)
                    encoded.append(item)
                }
            }
        }
        
        // Encode list
        if encoded.count < 56 {
            return Data([UInt8(0xc0 + encoded.count)]) + encoded
        } else {
            let lengthBytes = encodeNumber(UInt64(encoded.count))
            return Data([UInt8(0xf7 + lengthBytes.count)]) + lengthBytes + encoded
        }
    }
    
    private static func decompressPublicKey(_ compressedKey: Data) throws -> Data {
        // Simplified implementation - in production use proper secp256k1 library
        throw SigningError.decompressionNotImplemented
    }
    
    // MARK: - Keccak256 Hash
    
    private static func keccak256(_ data: Data) -> Data {
        // For this example, using SHA256 as placeholder
        // In production, use proper Keccak256 implementation
        return SHA256.hash(data: data).withUnsafeBytes { Data($0) }
    }
}

// MARK: - Supporting Types

public struct EthereumTransaction {
    let nonce: UInt64
    let gasPrice: UInt64
    let gasLimit: UInt64
    let to: String
    let value: UInt64
    let data: String
}

// MARK: - Data Extension

extension Data {
    init(hex: String) {
        let cleanHex = hex.hasPrefix("0x") ? String(hex.dropFirst(2)) : hex
        self = Data(cleanHex.chunks(ofCount: 2).compactMap { UInt8($0, radix: 16) })
    }
}

extension String {
    func chunks(ofCount count: Int) -> [String] {
        var chunks: [String] = []
        var currentIndex = startIndex
        
        while currentIndex < endIndex {
            let nextIndex = index(currentIndex, offsetBy: count, limitedBy: endIndex) ?? endIndex
            chunks.append(String(self[currentIndex..<nextIndex]))
            currentIndex = nextIndex
        }
        
        return chunks
    }
}

// MARK: - Error Types

public enum SigningError: LocalizedError {
    case invalidPrivateKeyLength
    case invalidPublicKeyLength
    case invalidHashLength
    case invalidSignatureLength
    case signingFailed
    case verificationFailed
    case recoveryNotImplemented
    case decompressionNotImplemented
    case rlpEncodingFailed
    
    public var errorDescription: String? {
        switch self {
        case .invalidPrivateKeyLength:
            return "Private key must be exactly 32 bytes."
        case .invalidPublicKeyLength:
            return "Public key must be 33 bytes (compressed) or 65 bytes (uncompressed)."
        case .invalidHashLength:
            return "Hash must be exactly 32 bytes."
        case .invalidSignatureLength:
            return "Signature must be exactly 65 bytes."
        case .signingFailed:
            return "Signing operation failed."
        case .verificationFailed:
            return "Signature verification failed."
        case .recoveryNotImplemented:
            return "Public key recovery is not implemented in this version."
        case .decompressionNotImplemented:
            return "Public key decompression is not implemented in this version."
        case .rlpEncodingFailed:
            return "RLP encoding failed."
        }
    }
}