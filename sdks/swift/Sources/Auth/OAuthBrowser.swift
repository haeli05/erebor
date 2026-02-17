import Foundation
import AuthenticationServices
import UIKit

/// Generic OAuth browser for various providers (Discord, GitHub, Twitter, etc.)
class OAuthBrowser: NSObject {
    
    private let redirectUri = "com.erebor.app://oauth"
    
    /// Authenticate with an OAuth provider
    /// - Parameters:
    ///   - provider: OAuth provider
    ///   - presentingViewController: View controller to present the auth session
    /// - Returns: Authorization code result
    func authenticate(
        provider: AuthProvider, 
        presenting presentingViewController: UIViewController
    ) async throws -> OAuthResult {
        let authURL = buildAuthURL(for: provider)
        
        return try await withCheckedThrowingContinuation { continuation in
            let session = ASWebAuthenticationSession(
                url: authURL,
                callbackURLScheme: extractScheme(from: redirectUri)
            ) { callbackURL, error in
                if let error = error {
                    if let authError = error as? ASWebAuthenticationSessionError {
                        switch authError.code {
                        case .canceledLogin:
                            continuation.resume(throwing: AuthError.userCancelled)
                        default:
                            continuation.resume(throwing: AuthError.oauthFailed(authError))
                        }
                    } else {
                        continuation.resume(throwing: AuthError.oauthFailed(error))
                    }
                    return
                }
                
                guard let callbackURL = callbackURL else {
                    continuation.resume(throwing: AuthError.oauthFailed(
                        NSError(domain: "OAuth", code: -1, userInfo: [NSLocalizedDescriptionKey: "No callback URL"])
                    ))
                    return
                }
                
                do {
                    let result = try self.parseCallback(url: callbackURL)
                    continuation.resume(returning: result)
                } catch {
                    continuation.resume(throwing: error)
                }
            }
            
            session.presentationContextProvider = self
            session.prefersEphemeralWebBrowserSession = true
            session.start()
        }
    }
    
    // MARK: - Private Methods
    
    private func buildAuthURL(for provider: AuthProvider) -> URL {
        let baseURL: String
        let clientId: String
        let scopes: String
        
        switch provider {
        case .discord:
            baseURL = "https://discord.com/api/oauth2/authorize"
            clientId = getClientId(for: provider)
            scopes = "identify email"
            
        case .github:
            baseURL = "https://github.com/login/oauth/authorize"
            clientId = getClientId(for: provider)
            scopes = "user:email"
            
        case .twitter:
            // Twitter uses OAuth 2.0 with PKCE
            baseURL = "https://twitter.com/i/oauth2/authorize"
            clientId = getClientId(for: provider)
            scopes = "tweet.read users.read"
            
        case .farcaster:
            baseURL = "https://warpcast.com/~/siwf" // Sign In With Farcaster
            clientId = getClientId(for: provider)
            scopes = "profile"
            
        case .telegram:
            // Telegram Login Widget
            baseURL = "https://oauth.telegram.org/auth"
            clientId = getClientId(for: provider) // Bot username
            scopes = ""
            
        default:
            fatalError("Unsupported OAuth provider: \(provider)")
        }
        
        var components = URLComponents(string: baseURL)!
        let state = generateState()
        
        var queryItems = [
            URLQueryItem(name: "client_id", value: clientId),
            URLQueryItem(name: "redirect_uri", value: redirectUri),
            URLQueryItem(name: "response_type", value: "code"),
            URLQueryItem(name: "state", value: state)
        ]
        
        if !scopes.isEmpty {
            queryItems.append(URLQueryItem(name: "scope", value: scopes))
        }
        
        // Add provider-specific parameters
        switch provider {
        case .twitter:
            // Twitter OAuth 2.0 with PKCE
            let codeChallenge = generateCodeChallenge()
            queryItems.append(contentsOf: [
                URLQueryItem(name: "code_challenge", value: codeChallenge),
                URLQueryItem(name: "code_challenge_method", value: "S256")
            ])
            
        case .discord:
            queryItems.append(URLQueryItem(name: "permissions", value: "0"))
            
        case .telegram:
            queryItems.append(URLQueryItem(name: "origin", value: "https://erebor.xyz"))
            
        default:
            break
        }
        
        components.queryItems = queryItems
        return components.url!
    }
    
    private func parseCallback(url: URL) throws -> OAuthResult {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let queryItems = components.queryItems else {
            throw AuthError.oauthFailed(
                NSError(domain: "OAuth", code: -2, userInfo: [NSLocalizedDescriptionKey: "Invalid callback URL"])
            )
        }
        
        // Check for error in callback
        if let error = queryItems.first(where: { $0.name == "error" })?.value {
            let errorDescription = queryItems.first(where: { $0.name == "error_description" })?.value ?? error
            throw AuthError.oauthFailed(
                NSError(domain: "OAuth", code: -3, userInfo: [NSLocalizedDescriptionKey: "OAuth error: \(errorDescription)"])
            )
        }
        
        // Extract authorization code
        guard let code = queryItems.first(where: { $0.name == "code" })?.value else {
            throw AuthError.oauthFailed(
                NSError(domain: "OAuth", code: -4, userInfo: [NSLocalizedDescriptionKey: "No authorization code"])
            )
        }
        
        return OAuthResult(code: code, redirectUri: redirectUri)
    }
    
    private func getClientId(for provider: AuthProvider) -> String {
        // TODO: These should come from configuration or be injected
        switch provider {
        case .discord:
            return "your-discord-client-id"
        case .github:
            return "your-github-client-id"
        case .twitter:
            return "your-twitter-client-id"
        case .farcaster:
            return "your-farcaster-client-id"
        case .telegram:
            return "your-telegram-bot-username"
        default:
            return ""
        }
    }
    
    private func extractScheme(from uri: String) -> String? {
        guard let url = URL(string: uri) else { return nil }
        return url.scheme
    }
    
    private func generateState() -> String {
        let length = 32
        let characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789"
        return String((0..<length).map { _ in characters.randomElement()! })
    }
    
    private func generateCodeChallenge() -> String {
        // Generate a proper PKCE code challenge
        let codeVerifier = generateCodeVerifier()
        return codeVerifier.sha256.base64URLEncoded
    }
    
    private func generateCodeVerifier() -> String {
        let length = 128
        let characters = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-._~"
        return String((0..<length).map { _ in characters.randomElement()! })
    }
}

// MARK: - ASWebAuthenticationPresentationContextProviding

extension OAuthBrowser: ASWebAuthenticationPresentationContextProviding {
    func presentationAnchor(for session: ASWebAuthenticationSession) -> ASPresentationAnchor {
        // Find the key window
        if let windowScene = UIApplication.shared.connectedScenes.first as? UIWindowScene,
           let keyWindow = windowScene.windows.first(where: { $0.isKeyWindow }) {
            return keyWindow
        }
        
        // Fallback to any available window
        return UIApplication.shared.windows.first ?? ASPresentationAnchor()
    }
}

// MARK: - String Extensions for PKCE

private extension String {
    var sha256: Data {
        let data = self.data(using: .utf8)!
        var hash = [UInt8](repeating: 0, count: Int(CC_SHA256_DIGEST_LENGTH))
        data.withUnsafeBytes {
            _ = CC_SHA256($0.baseAddress, CC_LONG(data.count), &hash)
        }
        return Data(hash)
    }
}

private extension Data {
    var base64URLEncoded: String {
        return base64EncodedString()
            .replacingOccurrences(of: "+", with: "-")
            .replacingOccurrences(of: "/", with: "_")
            .replacingOccurrences(of: "=", with: "")
    }
}

// Import CommonCrypto for SHA256
import CommonCrypto