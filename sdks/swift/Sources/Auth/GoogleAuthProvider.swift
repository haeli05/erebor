import Foundation
import AuthenticationServices
import UIKit

/// Google OAuth authentication provider using ASWebAuthenticationSession
class GoogleAuthProvider: NSObject {
    
    /// Google OAuth client configuration
    private let clientId: String
    private let redirectUri: String
    
    /// Public redirect URI for external use
    var redirectUri: String { redirectUri }
    
    init(clientId: String = "", redirectUri: String = "com.erebor.app://oauth") {
        // TODO: These should come from configuration
        self.clientId = clientId.isEmpty ? "your-google-client-id" : clientId
        self.redirectUri = redirectUri
        super.init()
    }
    
    /// Initiate Google OAuth flow
    /// - Parameter presentingViewController: View controller to present the auth session
    /// - Returns: Authorization code result
    func signIn(presenting presentingViewController: UIViewController) async throws -> OAuthResult {
        let authURL = buildAuthURL()
        
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
                            continuation.resume(throwing: AuthError.googleSignInFailed(authError))
                        }
                    } else {
                        continuation.resume(throwing: AuthError.googleSignInFailed(error))
                    }
                    return
                }
                
                guard let callbackURL = callbackURL else {
                    continuation.resume(throwing: AuthError.googleSignInFailed(
                        NSError(domain: "GoogleAuth", code: -1, userInfo: [NSLocalizedDescriptionKey: "No callback URL"])
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
            
            // Set presentation context provider
            session.presentationContextProvider = self
            session.prefersEphemeralWebBrowserSession = true
            session.start()
        }
    }
    
    // MARK: - Private Methods
    
    private func buildAuthURL() -> URL {
        var components = URLComponents(string: "https://accounts.google.com/oauth/v2/auth")!
        
        let state = generateState()
        let codeChallenge = generateCodeChallenge()
        
        components.queryItems = [
            URLQueryItem(name: "client_id", value: clientId),
            URLQueryItem(name: "redirect_uri", value: redirectUri),
            URLQueryItem(name: "response_type", value: "code"),
            URLQueryItem(name: "scope", value: "openid email profile"),
            URLQueryItem(name: "state", value: state),
            URLQueryItem(name: "code_challenge", value: codeChallenge),
            URLQueryItem(name: "code_challenge_method", value: "S256"),
            URLQueryItem(name: "access_type", value: "offline"),
            URLQueryItem(name: "prompt", value: "consent")
        ]
        
        return components.url!
    }
    
    private func parseCallback(url: URL) throws -> OAuthResult {
        guard let components = URLComponents(url: url, resolvingAgainstBaseURL: false),
              let queryItems = components.queryItems else {
            throw AuthError.googleSignInFailed(
                NSError(domain: "GoogleAuth", code: -2, userInfo: [NSLocalizedDescriptionKey: "Invalid callback URL"])
            )
        }
        
        // Check for error in callback
        if let error = queryItems.first(where: { $0.name == "error" })?.value {
            throw AuthError.googleSignInFailed(
                NSError(domain: "GoogleAuth", code: -3, userInfo: [NSLocalizedDescriptionKey: "OAuth error: \(error)"])
            )
        }
        
        // Extract authorization code
        guard let code = queryItems.first(where: { $0.name == "code" })?.value else {
            throw AuthError.googleSignInFailed(
                NSError(domain: "GoogleAuth", code: -4, userInfo: [NSLocalizedDescriptionKey: "No authorization code"])
            )
        }
        
        return OAuthResult(code: code, redirectUri: redirectUri)
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
        // For simplicity, using a fixed code challenge
        // In production, generate a proper PKCE code challenge
        return "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk"
    }
}

// MARK: - ASWebAuthenticationPresentationContextProviding

extension GoogleAuthProvider: ASWebAuthenticationPresentationContextProviding {
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

// MARK: - Data Models

/// OAuth authentication result
struct OAuthResult {
    let code: String
    let redirectUri: String
}

/// Google user information (from ID token)
struct GoogleUser: Codable {
    let sub: String // Google user ID
    let email: String?
    let emailVerified: Bool?
    let name: String?
    let givenName: String?
    let familyName: String?
    let picture: String?
    let locale: String?
    
    enum CodingKeys: String, CodingKey {
        case sub
        case email
        case emailVerified = "email_verified"
        case name
        case givenName = "given_name"
        case familyName = "family_name"
        case picture
        case locale
    }
}