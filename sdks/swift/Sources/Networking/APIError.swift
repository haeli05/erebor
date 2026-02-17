import Foundation

/// Errors that can occur during API operations
public enum APIError: LocalizedError {
    case authenticationRequired
    case unauthorized
    case forbidden
    case notFound
    case validationError(String)
    case rateLimited
    case serverError(Int)
    case httpError(Int, String)
    case networkError(Error)
    case invalidResponse
    case encodingError(Error)
    case decodingError(Error)
    case invalidURL
    case timeout
    case sslPinningFailed
    
    public var errorDescription: String? {
        switch self {
        case .authenticationRequired:
            return "Authentication is required for this operation."
        case .unauthorized:
            return "Your session has expired or is invalid. Please sign in again."
        case .forbidden:
            return "You don't have permission to perform this operation."
        case .notFound:
            return "The requested resource was not found."
        case .validationError(let message):
            return "Validation error: \(message)"
        case .rateLimited:
            return "Too many requests. Please try again later."
        case .serverError(let code):
            return "Server error (HTTP \(code)). Please try again later."
        case .httpError(let code, let message):
            return "HTTP \(code): \(message)"
        case .networkError(let error):
            return "Network error: \(error.localizedDescription)"
        case .invalidResponse:
            return "Invalid response from server."
        case .encodingError(let error):
            return "Failed to encode request: \(error.localizedDescription)"
        case .decodingError(let error):
            return "Failed to decode response: \(error.localizedDescription)"
        case .invalidURL:
            return "Invalid URL configuration."
        case .timeout:
            return "Request timed out. Please check your connection and try again."
        case .sslPinningFailed:
            return "SSL certificate validation failed. This might indicate a security issue."
        }
    }
    
    /// Error code for debugging and analytics
    public var errorCode: String {
        switch self {
        case .authenticationRequired:
            return "AUTH_REQUIRED"
        case .unauthorized:
            return "UNAUTHORIZED"
        case .forbidden:
            return "FORBIDDEN"
        case .notFound:
            return "NOT_FOUND"
        case .validationError:
            return "VALIDATION_ERROR"
        case .rateLimited:
            return "RATE_LIMITED"
        case .serverError:
            return "SERVER_ERROR"
        case .httpError:
            return "HTTP_ERROR"
        case .networkError:
            return "NETWORK_ERROR"
        case .invalidResponse:
            return "INVALID_RESPONSE"
        case .encodingError:
            return "ENCODING_ERROR"
        case .decodingError:
            return "DECODING_ERROR"
        case .invalidURL:
            return "INVALID_URL"
        case .timeout:
            return "TIMEOUT"
        case .sslPinningFailed:
            return "SSL_PINNING_FAILED"
        }
    }
    
    /// Whether this error is recoverable (user can retry)
    public var isRecoverable: Bool {
        switch self {
        case .authenticationRequired, .unauthorized, .forbidden, .notFound, .validationError, .invalidURL, .sslPinningFailed:
            return false
        case .rateLimited, .serverError, .httpError, .networkError, .invalidResponse, .encodingError, .decodingError, .timeout:
            return true
        }
    }
    
    /// Whether this error requires user authentication
    public var requiresAuthentication: Bool {
        switch self {
        case .authenticationRequired, .unauthorized:
            return true
        default:
            return false
        }
    }
    
    /// Whether this is a client-side error (4xx)
    public var isClientError: Bool {
        switch self {
        case .authenticationRequired, .unauthorized, .forbidden, .notFound, .validationError:
            return true
        case .httpError(let code, _):
            return code >= 400 && code < 500
        default:
            return false
        }
    }
    
    /// Whether this is a server-side error (5xx)
    public var isServerError: Bool {
        switch self {
        case .serverError:
            return true
        case .httpError(let code, _):
            return code >= 500
        default:
            return false
        }
    }
    
    /// HTTP status code if applicable
    public var httpStatusCode: Int? {
        switch self {
        case .unauthorized:
            return 401
        case .forbidden:
            return 403
        case .notFound:
            return 404
        case .validationError:
            return 422
        case .rateLimited:
            return 429
        case .serverError(let code), .httpError(let code, _):
            return code
        default:
            return nil
        }
    }
    
    /// User-facing error message with actionable advice
    public var userMessage: String {
        switch self {
        case .authenticationRequired, .unauthorized:
            return "Please sign in to continue."
        case .forbidden:
            return "You don't have permission to access this resource."
        case .notFound:
            return "The requested item could not be found."
        case .validationError(let message):
            return message
        case .rateLimited:
            return "You're making requests too quickly. Please wait a moment and try again."
        case .serverError, .httpError:
            return "Something went wrong on our end. Please try again in a few moments."
        case .networkError:
            return "Please check your internet connection and try again."
        case .invalidResponse, .encodingError, .decodingError:
            return "Something went wrong. Please try again or contact support if the problem persists."
        case .invalidURL:
            return "Configuration error. Please contact support."
        case .timeout:
            return "The request took too long. Please check your connection and try again."
        case .sslPinningFailed:
            return "Security verification failed. Please ensure you're on a trusted network."
        }
    }
    
    /// Suggested retry delay in seconds
    public var retryDelay: TimeInterval? {
        switch self {
        case .rateLimited:
            return 60.0 // 1 minute
        case .serverError, .networkError, .timeout:
            return 5.0 // 5 seconds
        case .httpError(let code, _):
            return code >= 500 ? 5.0 : nil
        default:
            return nil
        }
    }
}

/// Network connectivity error
public enum NetworkError: LocalizedError {
    case noConnection
    case dnsFailure
    case sslError
    case certificateError
    case connectionTimeout
    case dataNotAllowed
    
    public var errorDescription: String? {
        switch self {
        case .noConnection:
            return "No internet connection available."
        case .dnsFailure:
            return "Unable to resolve server address."
        case .sslError:
            return "SSL connection failed."
        case .certificateError:
            return "Server certificate is invalid."
        case .connectionTimeout:
            return "Connection timed out."
        case .dataNotAllowed:
            return "Data usage is not allowed. Please check your device settings."
        }
    }
}

/// Authentication-specific errors
public enum AuthenticationError: LocalizedError {
    case invalidCredentials
    case accountLocked
    case emailNotVerified
    case phoneNotVerified
    case twoFactorRequired
    case twoFactorInvalid
    case sessionExpired
    case deviceNotTrusted
    
    public var errorDescription: String? {
        switch self {
        case .invalidCredentials:
            return "Invalid email or password."
        case .accountLocked:
            return "Your account has been locked. Please contact support."
        case .emailNotVerified:
            return "Please verify your email address before continuing."
        case .phoneNotVerified:
            return "Please verify your phone number before continuing."
        case .twoFactorRequired:
            return "Two-factor authentication is required."
        case .twoFactorInvalid:
            return "Invalid two-factor authentication code."
        case .sessionExpired:
            return "Your session has expired. Please sign in again."
        case .deviceNotTrusted:
            return "This device is not trusted. Please verify your identity."
        }
    }
}

/// Wallet-specific errors
public enum WalletAPIError: LocalizedError {
    case walletNotFound
    case insufficientBalance
    case invalidTransaction
    case transactionFailed
    case signingNotSupported
    case chainNotSupported
    case gasEstimationFailed
    case nonceError
    
    public var errorDescription: String? {
        switch self {
        case .walletNotFound:
            return "Wallet not found."
        case .insufficientBalance:
            return "Insufficient balance to complete the transaction."
        case .invalidTransaction:
            return "Invalid transaction parameters."
        case .transactionFailed:
            return "Transaction failed to execute."
        case .signingNotSupported:
            return "Message signing is not supported for this wallet type."
        case .chainNotSupported:
            return "This blockchain is not supported."
        case .gasEstimationFailed:
            return "Unable to estimate gas for this transaction."
        case .nonceError:
            return "Transaction nonce error. Please try again."
        }
    }
}