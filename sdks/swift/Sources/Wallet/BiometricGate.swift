import Foundation
import LocalAuthentication

/// Handles biometric authentication (FaceID/TouchID) for secure operations
public class BiometricGate: ObservableObject {
    private let context = LAContext()
    
    /// Whether biometric authentication is available on this device
    public var isAvailable: Bool {
        var error: NSError?
        return context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
    }
    
    /// Type of biometric authentication available
    public var biometricType: BiometricType {
        guard isAvailable else { return .none }
        
        switch context.biometryType {
        case .faceID:
            return .faceID
        case .touchID:
            return .touchID
        case .opticID:
            return .opticID
        case .none:
            return .none
        @unknown default:
            return .none
        }
    }
    
    /// Human-readable name for the available biometric type
    public var biometricDisplayName: String {
        switch biometricType {
        case .faceID:
            return "Face ID"
        case .touchID:
            return "Touch ID"
        case .opticID:
            return "Optic ID"
        case .none:
            return "Biometrics"
        }
    }
    
    /// Prompt user for biometric authentication
    /// - Parameter reason: Reason shown to the user for the authentication request
    /// - Returns: True if authentication succeeded
    public func authenticate(reason: String) async throws -> Bool {
        guard isAvailable else {
            throw BiometricError.notAvailable
        }
        
        return try await withCheckedThrowingContinuation { continuation in
            context.evaluatePolicy(
                .deviceOwnerAuthenticationWithBiometrics,
                localizedReason: reason
            ) { success, error in
                if success {
                    continuation.resume(returning: true)
                } else if let error = error {
                    continuation.resume(throwing: self.mapLAError(error))
                } else {
                    continuation.resume(throwing: BiometricError.unknown)
                }
            }
        }
    }
    
    /// Authenticate with fallback to device passcode
    /// - Parameter reason: Reason shown to the user for the authentication request
    /// - Returns: True if authentication succeeded
    public func authenticateWithFallback(reason: String) async throws -> Bool {
        var error: NSError?
        let canEvaluate = context.canEvaluatePolicy(.deviceOwnerAuthentication, error: &error)
        
        guard canEvaluate else {
            if let error = error {
                throw mapLAError(error)
            }
            throw BiometricError.notAvailable
        }
        
        return try await withCheckedThrowingContinuation { continuation in
            context.evaluatePolicy(
                .deviceOwnerAuthentication,
                localizedReason: reason
            ) { success, error in
                if success {
                    continuation.resume(returning: true)
                } else if let error = error {
                    continuation.resume(throwing: self.mapLAError(error))
                } else {
                    continuation.resume(throwing: BiometricError.unknown)
                }
            }
        }
    }
    
    /// Check if user has set up biometric authentication
    /// - Returns: True if biometrics are enrolled
    public func isBiometricEnrolled() -> Bool {
        var error: NSError?
        let canEvaluate = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
        
        if let error = error as? LAError {
            switch error.code {
            case .biometryNotEnrolled, .biometryNotAvailable:
                return false
            default:
                return canEvaluate
            }
        }
        
        return canEvaluate
    }
    
    /// Get localized error message for biometric setup
    /// - Returns: Error message if biometrics are not properly configured
    public func getBiometricSetupError() -> String? {
        var error: NSError?
        let canEvaluate = context.canEvaluatePolicy(.deviceOwnerAuthenticationWithBiometrics, error: &error)
        
        guard !canEvaluate, let error = error as? LAError else {
            return nil
        }
        
        switch error.code {
        case .biometryNotAvailable:
            return "Biometric authentication is not available on this device."
        case .biometryNotEnrolled:
            return "\(biometricDisplayName) is not set up. Please set up \(biometricDisplayName) in Settings."
        case .biometryLockout:
            return "\(biometricDisplayName) is locked. Please unlock your device to use \(biometricDisplayName)."
        default:
            return "Biometric authentication is not available: \(error.localizedDescription)"
        }
    }
    
    // MARK: - Private Helpers
    
    private func mapLAError(_ error: Error) -> BiometricError {
        guard let laError = error as? LAError else {
            return .unknown
        }
        
        switch laError.code {
        case .userCancel:
            return .userCancelled
        case .userFallback:
            return .userChosePasscode
        case .systemCancel:
            return .systemCancelled
        case .passcodeNotSet:
            return .passcodeNotSet
        case .biometryNotAvailable:
            return .notAvailable
        case .biometryNotEnrolled:
            return .notEnrolled
        case .biometryLockout:
            return .lockout
        case .authenticationFailed:
            return .authenticationFailed
        case .invalidContext:
            return .invalidContext
        case .notInteractive:
            return .notInteractive
        @unknown default:
            return .unknown
        }
    }
}

// MARK: - Types

/// Available biometric authentication types
public enum BiometricType: String, CaseIterable {
    case none = "none"
    case touchID = "touchID"
    case faceID = "faceID"
    case opticID = "opticID"
    
    /// SF Symbol icon name for the biometric type
    public var iconName: String {
        switch self {
        case .none:
            return "person.crop.circle"
        case .touchID:
            return "touchid"
        case .faceID:
            return "faceid"
        case .opticID:
            return "opticid"
        }
    }
}

/// Biometric authentication errors
public enum BiometricError: LocalizedError {
    case notAvailable
    case notEnrolled
    case lockout
    case userCancelled
    case userChosePasscode
    case systemCancelled
    case passcodeNotSet
    case authenticationFailed
    case invalidContext
    case notInteractive
    case unknown
    
    public var errorDescription: String? {
        switch self {
        case .notAvailable:
            return "Biometric authentication is not available on this device."
        case .notEnrolled:
            return "Biometric authentication is not set up. Please configure it in Settings."
        case .lockout:
            return "Biometric authentication is locked. Please unlock your device."
        case .userCancelled:
            return "Authentication was cancelled by the user."
        case .userChosePasscode:
            return "User chose to use device passcode instead of biometrics."
        case .systemCancelled:
            return "Authentication was cancelled by the system."
        case .passcodeNotSet:
            return "Device passcode is not set. Please set up a passcode in Settings."
        case .authenticationFailed:
            return "Biometric authentication failed. Please try again."
        case .invalidContext:
            return "Invalid authentication context."
        case .notInteractive:
            return "Authentication is not interactive."
        case .unknown:
            return "An unknown error occurred during authentication."
        }
    }
    
    /// Whether this error should allow retry
    public var canRetry: Bool {
        switch self {
        case .authenticationFailed, .userCancelled, .systemCancelled:
            return true
        default:
            return false
        }
    }
    
    /// Whether this error indicates a configuration issue
    public var isConfigurationError: Bool {
        switch self {
        case .notAvailable, .notEnrolled, .passcodeNotSet:
            return true
        default:
            return false
        }
    }
}