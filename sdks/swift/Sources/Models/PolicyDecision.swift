import Foundation

/// Policy engine decision for transaction or operation approval
public enum PolicyDecision: String, Codable, CaseIterable {
    case allow = "allow"
    case deny = "deny"
    case requireApproval = "require_approval"
    
    /// Whether the operation can proceed without additional approval
    public var canProceed: Bool {
        return self == .allow
    }
    
    /// Whether the operation is blocked
    public var isBlocked: Bool {
        return self == .deny
    }
    
    /// Whether additional approval is needed
    public var requiresApproval: Bool {
        return self == .requireApproval
    }
}

/// Policy evaluation result with context
public struct PolicyResult: Codable {
    /// The policy decision
    public let decision: PolicyDecision
    
    /// Human-readable reason for the decision
    public let reason: String?
    
    /// Specific policy rules that triggered this decision
    public let triggeredRules: [String]
    
    /// Risk score (0.0 = no risk, 1.0 = maximum risk)
    public let riskScore: Double?
    
    /// Additional metadata about the policy evaluation
    public let metadata: [String: String]?
    
    /// Approval request ID (if decision is requireApproval)
    public let approvalRequestId: String?
    
    /// Timestamp when policy was evaluated
    public let evaluatedAt: Date
    
    public init(
        decision: PolicyDecision,
        reason: String? = nil,
        triggeredRules: [String] = [],
        riskScore: Double? = nil,
        metadata: [String: String]? = nil,
        approvalRequestId: String? = nil,
        evaluatedAt: Date = Date()
    ) {
        self.decision = decision
        self.reason = reason
        self.triggeredRules = triggeredRules
        self.riskScore = riskScore
        self.metadata = metadata
        self.approvalRequestId = approvalRequestId
        self.evaluatedAt = evaluatedAt
    }
}

/// Types of operations that can be evaluated by policy engine
public enum PolicyOperation: String, Codable {
    case signMessage = "sign_message"
    case signTransaction = "sign_transaction"
    case sendTransaction = "send_transaction"
    case createWallet = "create_wallet"
    case linkAccount = "link_account"
    case unlinkAccount = "unlink_account"
    case exportPrivateKey = "export_private_key"
    case changeSettings = "change_settings"
    
    /// Display name for the operation
    public var displayName: String {
        switch self {
        case .signMessage:
            return "Sign Message"
        case .signTransaction:
            return "Sign Transaction"
        case .sendTransaction:
            return "Send Transaction"
        case .createWallet:
            return "Create Wallet"
        case .linkAccount:
            return "Link Account"
        case .unlinkAccount:
            return "Unlink Account"
        case .exportPrivateKey:
            return "Export Private Key"
        case .changeSettings:
            return "Change Settings"
        }
    }
    
    /// Risk level of the operation
    public var riskLevel: RiskLevel {
        switch self {
        case .signMessage, .createWallet, .linkAccount:
            return .low
        case .signTransaction, .unlinkAccount, .changeSettings:
            return .medium
        case .sendTransaction, .exportPrivateKey:
            return .high
        }
    }
}

/// Risk levels for different operations
public enum RiskLevel: String, Codable, CaseIterable {
    case low = "low"
    case medium = "medium"
    case high = "high"
    case critical = "critical"
    
    /// Numeric score for risk level (0-100)
    public var score: Int {
        switch self {
        case .low: return 25
        case .medium: return 50
        case .high: return 75
        case .critical: return 100
        }
    }
    
    /// Color for UI display
    public var color: String {
        switch self {
        case .low: return "#10B981" // green
        case .medium: return "#F59E0B" // yellow
        case .high: return "#EF4444" // red
        case .critical: return "#7C2D12" // dark red
        }
    }
}

/// Context for policy evaluation
public struct PolicyContext: Codable {
    /// User ID performing the operation
    public let userId: String
    
    /// Operation being performed
    public let operation: PolicyOperation
    
    /// Wallet ID involved (if applicable)
    public let walletId: String?
    
    /// Transaction details (if applicable)
    public let transactionRequest: TransactionRequest?
    
    /// Message being signed (if applicable)
    public let messageToSign: String?
    
    /// Device information
    public let deviceInfo: DeviceInfo?
    
    /// Location information (if available)
    public let locationInfo: LocationInfo?
    
    /// Additional context data
    public let metadata: [String: String]?
    
    public init(
        userId: String,
        operation: PolicyOperation,
        walletId: String? = nil,
        transactionRequest: TransactionRequest? = nil,
        messageToSign: String? = nil,
        deviceInfo: DeviceInfo? = nil,
        locationInfo: LocationInfo? = nil,
        metadata: [String: String]? = nil
    ) {
        self.userId = userId
        self.operation = operation
        self.walletId = walletId
        self.transactionRequest = transactionRequest
        self.messageToSign = messageToSign
        self.deviceInfo = deviceInfo
        self.locationInfo = locationInfo
        self.metadata = metadata
    }
}

/// Device information for policy context
public struct DeviceInfo: Codable {
    /// Device model (e.g., "iPhone15,2")
    public let model: String?
    
    /// Operating system version
    public let osVersion: String?
    
    /// App version
    public let appVersion: String?
    
    /// Whether device is jailbroken/rooted
    public let isCompromised: Bool?
    
    /// Whether biometric authentication is enabled
    public let biometricEnabled: Bool?
    
    /// Device identifier (anonymized)
    public let deviceId: String?
    
    public init(
        model: String? = nil,
        osVersion: String? = nil,
        appVersion: String? = nil,
        isCompromised: Bool? = nil,
        biometricEnabled: Bool? = nil,
        deviceId: String? = nil
    ) {
        self.model = model
        self.osVersion = osVersion
        self.appVersion = appVersion
        self.isCompromised = isCompromised
        self.biometricEnabled = biometricEnabled
        self.deviceId = deviceId
    }
}

/// Location information for policy context
public struct LocationInfo: Codable {
    /// Country code (ISO 3166-1 alpha-2)
    public let countryCode: String?
    
    /// City name
    public let city: String?
    
    /// Whether location is considered high-risk
    public let isHighRisk: Bool?
    
    /// Whether this is a new location for the user
    public let isNewLocation: Bool?
    
    public init(
        countryCode: String? = nil,
        city: String? = nil,
        isHighRisk: Bool? = nil,
        isNewLocation: Bool? = nil
    ) {
        self.countryCode = countryCode
        self.city = city
        self.isHighRisk = isHighRisk
        self.isNewLocation = isNewLocation
    }
}