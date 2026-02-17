import Foundation
import AuthenticationServices
import UIKit

/// Apple Sign In authentication provider
class AppleAuthProvider: NSObject {
    
    private var currentContinuation: CheckedContinuation<AppleCredential, Error>?
    
    /// Initiate Apple Sign In flow
    /// - Returns: Apple credential with identity token
    func signIn() async throws -> AppleCredential {
        return try await withCheckedThrowingContinuation { continuation in
            currentContinuation = continuation
            
            let request = ASAuthorizationAppleIDProvider().createRequest()
            request.requestedScopes = [.fullName, .email]
            
            let controller = ASAuthorizationController(authorizationRequests: [request])
            controller.delegate = self
            controller.presentationContextProvider = self
            controller.performRequests()
        }
    }
}

// MARK: - ASAuthorizationControllerDelegate

extension AppleAuthProvider: ASAuthorizationControllerDelegate {
    func authorizationController(
        controller: ASAuthorizationController,
        didCompleteWithAuthorization authorization: ASAuthorization
    ) {
        guard let credential = authorization.credential as? ASAuthorizationAppleIDCredential else {
            currentContinuation?.resume(throwing: AuthError.appleSignInFailed(
                NSError(domain: "AppleSignIn", code: -1, userInfo: [NSLocalizedDescriptionKey: "Invalid credential type"])
            ))
            currentContinuation = nil
            return
        }
        
        guard let identityToken = credential.identityToken,
              let identityTokenString = String(data: identityToken, encoding: .utf8) else {
            currentContinuation?.resume(throwing: AuthError.appleSignInFailed(
                NSError(domain: "AppleSignIn", code: -2, userInfo: [NSLocalizedDescriptionKey: "No identity token"])
            ))
            currentContinuation = nil
            return
        }
        
        let authorizationCode: String?
        if let authorizationCodeData = credential.authorizationCode {
            authorizationCode = String(data: authorizationCodeData, encoding: .utf8)
        } else {
            authorizationCode = nil
        }
        
        let user = AppleUser(
            identifier: credential.user,
            email: credential.email,
            givenName: credential.fullName?.givenName,
            familyName: credential.fullName?.familyName
        )
        
        let appleCredential = AppleCredential(
            identityToken: identityTokenString,
            authorizationCode: authorizationCode,
            user: user
        )
        
        currentContinuation?.resume(returning: appleCredential)
        currentContinuation = nil
    }
    
    func authorizationController(
        controller: ASAuthorizationController,
        didCompleteWithError error: Error
    ) {
        let authError: AuthError
        
        if let authorizationError = error as? ASAuthorizationError {
            switch authorizationError.code {
            case .canceled:
                authError = .userCancelled
            case .unknown:
                authError = .appleSignInFailed(authorizationError)
            case .invalidResponse:
                authError = .appleSignInFailed(authorizationError)
            case .notHandled:
                authError = .appleSignInFailed(authorizationError)
            case .failed:
                authError = .appleSignInFailed(authorizationError)
            case .notInteractive:
                authError = .appleSignInFailed(authorizationError)
            @unknown default:
                authError = .appleSignInFailed(authorizationError)
            }
        } else {
            authError = .appleSignInFailed(error)
        }
        
        currentContinuation?.resume(throwing: authError)
        currentContinuation = nil
    }
}

// MARK: - ASAuthorizationControllerPresentationContextProviding

extension AppleAuthProvider: ASAuthorizationControllerPresentationContextProviding {
    func presentationAnchor(for controller: ASAuthorizationController) -> ASPresentationAnchor {
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

/// Apple credential containing authentication data
struct AppleCredential {
    let identityToken: String
    let authorizationCode: String?
    let user: AppleUser
}

/// Apple user information
struct AppleUser: Codable {
    let identifier: String
    let email: String?
    let givenName: String?
    let familyName: String?
    
    var fullName: String? {
        let components = [givenName, familyName].compactMap { $0 }
        return components.isEmpty ? nil : components.joined(separator: " ")
    }
}