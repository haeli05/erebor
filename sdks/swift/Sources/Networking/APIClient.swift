import Foundation

/// HTTP client for communicating with the Erebor API
public class APIClient {
    private let config: EreborConfig
    private let session: URLSession
    private var currentTokens: AuthTokens?
    
    /// Base URL for API requests
    public var baseURL: URL {
        return URL(string: config.apiUrl)!
    }
    
    init(config: EreborConfig) {
        self.config = config
        
        // Configure URL session with custom delegate for SSL pinning
        let configuration = URLSessionConfiguration.default
        configuration.timeoutIntervalForRequest = 30.0
        configuration.timeoutIntervalForResource = 60.0
        
        if let sslPinning = config.sslPinning {
            let delegate = SSLPinningDelegate(config: sslPinning)
            self.session = URLSession(configuration: configuration, delegate: delegate, delegateQueue: nil)
        } else {
            self.session = URLSession(configuration: configuration)
        }
    }
    
    // MARK: - Token Management
    
    /// Set authentication tokens
    /// - Parameter tokens: Authentication tokens to use for requests
    func setTokens(_ tokens: AuthTokens) {
        currentTokens = tokens
    }
    
    /// Clear authentication tokens
    func clearTokens() {
        currentTokens = nil
    }
    
    /// Check if client is authenticated
    var isAuthenticated: Bool {
        return currentTokens != nil
    }
    
    // MARK: - Generic Request Method
    
    private func request<T: Codable>(
        method: HTTPMethod,
        path: String,
        body: Encodable? = nil,
        responseType: T.Type,
        requiresAuth: Bool = true
    ) async throws -> T {
        let url = baseURL.appendingPathComponent(path)
        var request = URLRequest(url: url)
        request.httpMethod = method.rawValue
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue("EreborSwift/1.0", forHTTPHeaderField: "User-Agent")
        
        // Add authentication header if required and available
        if requiresAuth {
            guard let tokens = currentTokens else {
                throw APIError.authenticationRequired
            }
            
            // Check if token needs refresh
            if tokens.shouldRefresh {
                try await refreshTokensInternal()
            }
            
            if let tokens = currentTokens {
                request.setValue("Bearer \(tokens.accessToken)", forHTTPHeaderField: "Authorization")
            }
        }
        
        // Add request body if provided
        if let body = body {
            do {
                request.httpBody = try JSONEncoder().encode(body)
            } catch {
                throw APIError.encodingError(error)
            }
        }
        
        // Perform request
        let (data, response) = try await session.data(for: request)
        
        guard let httpResponse = response as? HTTPURLResponse else {
            throw APIError.invalidResponse
        }
        
        // Handle HTTP status codes
        switch httpResponse.statusCode {
        case 200...299:
            break // Success
        case 401:
            // Unauthorized - try to refresh token if possible
            if requiresAuth && currentTokens != nil {
                try await refreshTokensInternal()
                // Retry the request once with new token
                return try await request(
                    method: method,
                    path: path,
                    body: body,
                    responseType: responseType,
                    requiresAuth: requiresAuth
                )
            } else {
                throw APIError.unauthorized
            }
        case 403:
            throw APIError.forbidden
        case 404:
            throw APIError.notFound
        case 422:
            throw APIError.validationError(try parseErrorResponse(data))
        case 429:
            throw APIError.rateLimited
        case 500...599:
            throw APIError.serverError(httpResponse.statusCode)
        default:
            throw APIError.httpError(httpResponse.statusCode, try parseErrorResponse(data))
        }
        
        // Parse response
        do {
            let decoder = JSONDecoder()
            decoder.dateDecodingStrategy = .iso8601
            return try decoder.decode(responseType, from: data)
        } catch {
            throw APIError.decodingError(error)
        }
    }
    
    private func parseErrorResponse(_ data: Data) -> String {
        if let errorResponse = try? JSONDecoder().decode(ErrorResponse.self, from: data) {
            return errorResponse.error ?? "Unknown error"
        } else if let errorString = String(data: data, encoding: .utf8) {
            return errorString
        }
        return "Failed to parse error response"
    }
    
    // MARK: - Authentication Endpoints
    
    func sendEmailOTP(email: String) async throws -> OTPSession {
        struct Request: Codable {
            let email: String
        }
        
        return try await request(
            method: .POST,
            path: "/auth/email/send",
            body: Request(email: email),
            responseType: OTPSession.self,
            requiresAuth: false
        )
    }
    
    func verifyEmailOTP(email: String, code: String) async throws -> AuthResult {
        struct Request: Codable {
            let email: String
            let code: String
        }
        
        return try await request(
            method: .POST,
            path: "/auth/email/verify",
            body: Request(email: email, code: code),
            responseType: AuthResult.self,
            requiresAuth: false
        )
    }
    
    func sendPhoneOTP(phoneNumber: String) async throws -> OTPSession {
        struct Request: Codable {
            let phoneNumber: String
        }
        
        return try await request(
            method: .POST,
            path: "/auth/phone/send",
            body: Request(phoneNumber: phoneNumber),
            responseType: OTPSession.self,
            requiresAuth: false
        )
    }
    
    func verifyPhoneOTP(phoneNumber: String, code: String) async throws -> AuthResult {
        struct Request: Codable {
            let phoneNumber: String
            let code: String
        }
        
        return try await request(
            method: .POST,
            path: "/auth/phone/verify",
            body: Request(phoneNumber: phoneNumber, code: code),
            responseType: AuthResult.self,
            requiresAuth: false
        )
    }
    
    func loginWithGoogle(authorizationCode: String, redirectUri: String) async throws -> AuthResult {
        struct Request: Codable {
            let code: String
            let redirectUri: String
        }
        
        return try await request(
            method: .POST,
            path: "/auth/google",
            body: Request(code: authorizationCode, redirectUri: redirectUri),
            responseType: AuthResult.self,
            requiresAuth: false
        )
    }
    
    func loginWithApple(identityToken: String, authorizationCode: String?, user: AppleUser) async throws -> AuthResult {
        struct Request: Codable {
            let identityToken: String
            let authorizationCode: String?
            let user: AppleUser
        }
        
        return try await request(
            method: .POST,
            path: "/auth/apple",
            body: Request(identityToken: identityToken, authorizationCode: authorizationCode, user: user),
            responseType: AuthResult.self,
            requiresAuth: false
        )
    }
    
    func getSiweNonce() async throws -> String {
        struct Response: Codable {
            let nonce: String
        }
        
        let response: Response = try await request(
            method: .GET,
            path: "/auth/siwe/nonce",
            responseType: Response.self,
            requiresAuth: false
        )
        
        return response.nonce
    }
    
    func verifySIWE(message: String, signature: String) async throws -> AuthResult {
        struct Request: Codable {
            let message: String
            let signature: String
        }
        
        return try await request(
            method: .POST,
            path: "/auth/siwe/verify",
            body: Request(message: message, signature: signature),
            responseType: AuthResult.self,
            requiresAuth: false
        )
    }
    
    func loginWithOAuth(provider: AuthProvider, authorizationCode: String, redirectUri: String) async throws -> AuthResult {
        struct Request: Codable {
            let provider: String
            let code: String
            let redirectUri: String
        }
        
        return try await request(
            method: .POST,
            path: "/auth/oauth",
            body: Request(provider: provider.rawValue, code: authorizationCode, redirectUri: redirectUri),
            responseType: AuthResult.self,
            requiresAuth: false
        )
    }
    
    func refreshTokens() async throws -> AuthResult {
        guard let currentTokens = currentTokens else {
            throw APIError.authenticationRequired
        }
        
        struct Request: Codable {
            let refreshToken: String
        }
        
        let result: AuthResult = try await request(
            method: .POST,
            path: "/auth/refresh",
            body: Request(refreshToken: currentTokens.refreshToken),
            responseType: AuthResult.self,
            requiresAuth: false
        )
        
        // Update stored tokens
        let newTokens = AuthTokens(
            accessToken: result.accessToken,
            refreshToken: result.refreshToken,
            expiresIn: result.expiresIn
        )
        self.currentTokens = newTokens
        
        return result
    }
    
    private func refreshTokensInternal() async throws {
        _ = try await refreshTokens()
    }
    
    func logout() async throws {
        try await request(
            method: .POST,
            path: "/auth/logout",
            responseType: EmptyResponse.self,
            requiresAuth: true
        )
        
        clearTokens()
    }
    
    // MARK: - User Endpoints
    
    func getMe() async throws -> EreborUser {
        return try await request(
            method: .GET,
            path: "/user/me",
            responseType: EreborUser.self,
            requiresAuth: true
        )
    }
    
    func linkAccount(provider: String, token: String) async throws -> LinkedAccount {
        struct Request: Codable {
            let provider: String
            let token: String
        }
        
        return try await request(
            method: .POST,
            path: "/user/link-account",
            body: Request(provider: provider, token: token),
            responseType: LinkedAccount.self,
            requiresAuth: true
        )
    }
    
    func unlinkAccount(provider: String) async throws {
        try await request(
            method: .DELETE,
            path: "/user/unlink-account/\(provider)",
            responseType: EmptyResponse.self,
            requiresAuth: true
        )
    }
    
    // MARK: - Wallet Endpoints
    
    func createWallet(chainId: UInt64?) async throws -> EreborWallet {
        struct Request: Codable {
            let chainId: UInt64?
        }
        
        return try await request(
            method: .POST,
            path: "/wallets",
            body: Request(chainId: chainId),
            responseType: EreborWallet.self,
            requiresAuth: true
        )
    }
    
    func listWallets() async throws -> [EreborWallet] {
        return try await request(
            method: .GET,
            path: "/wallets",
            responseType: [EreborWallet].self,
            requiresAuth: true
        )
    }
    
    func signMessage(walletId: String, message: String) async throws -> String {
        struct Request: Codable {
            let message: String
        }
        
        struct Response: Codable {
            let signature: String
        }
        
        let response: Response = try await request(
            method: .POST,
            path: "/wallets/\(walletId)/sign",
            body: Request(message: message),
            responseType: Response.self,
            requiresAuth: true
        )
        
        return response.signature
    }
    
    func signTransaction(walletId: String, transaction: TransactionRequest) async throws -> String {
        struct Response: Codable {
            let signedTransaction: String
        }
        
        let response: Response = try await request(
            method: .POST,
            path: "/wallets/\(walletId)/sign-transaction",
            body: transaction,
            responseType: Response.self,
            requiresAuth: true
        )
        
        return response.signedTransaction
    }
    
    func sendTransaction(walletId: String, transaction: TransactionRequest) async throws -> String {
        struct Response: Codable {
            let txHash: String
        }
        
        let response: Response = try await request(
            method: .POST,
            path: "/wallets/\(walletId)/send-transaction",
            body: transaction,
            responseType: Response.self,
            requiresAuth: true
        )
        
        return response.txHash
    }
    
    func getWalletBalance(walletId: String) async throws -> WalletBalance {
        return try await request(
            method: .GET,
            path: "/wallets/\(walletId)/balance",
            responseType: WalletBalance.self,
            requiresAuth: true
        )
    }
}

// MARK: - Supporting Types

enum HTTPMethod: String {
    case GET = "GET"
    case POST = "POST"
    case PUT = "PUT"
    case DELETE = "DELETE"
    case PATCH = "PATCH"
}

struct EmptyResponse: Codable {}

struct ErrorResponse: Codable {
    let error: String?
    let code: String?
    let details: [String: String]?
}

// MARK: - SSL Pinning Delegate

private class SSLPinningDelegate: NSObject, URLSessionDelegate {
    private let config: SSLPinningConfig
    
    init(config: SSLPinningConfig) {
        self.config = config
    }
    
    func urlSession(
        _ session: URLSession,
        didReceive challenge: URLAuthenticationChallenge,
        completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void
    ) {
        guard challenge.protectionSpace.authenticationMethod == NSURLAuthenticationMethodServerTrust,
              let serverTrust = challenge.protectionSpace.serverTrust else {
            completionHandler(.performDefaultHandling, nil)
            return
        }
        
        // Get server certificate data
        guard let serverCertificate = SecTrustGetCertificateAtIndex(serverTrust, 0) else {
            completionHandler(.cancelAuthenticationChallenge, nil)
            return
        }
        
        let serverCertData = SecCertificateCopyData(serverCertificate)
        let serverCertHash = CFDataCreateMutable(nil, 0)!
        
        // Calculate SHA-256 hash of certificate
        let serverCertBytes = CFDataGetBytePtr(CFDataCreateCopy(nil, serverCertData))!
        let serverCertLength = CFDataGetLength(serverCertData)
        
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        CC_SHA256(serverCertBytes, CC_LONG(serverCertLength), &hash)
        
        let serverCertHashString = hash.map { String(format: "%02hhx", $0) }.joined()
        
        // Check if hash matches any pinned certificates
        let isValidCertificate = config.certificateHashes.contains(serverCertHashString)
        
        if isValidCertificate {
            completionHandler(.useCredential, URLCredential(trust: serverTrust))
        } else if config.enforceOnFailure {
            completionHandler(.cancelAuthenticationChallenge, nil)
        } else {
            completionHandler(.performDefaultHandling, nil)
        }
    }
}

import CommonCrypto