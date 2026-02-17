import SwiftUI
import LocalAuthentication

/// SwiftUI component for transaction confirmation with biometric authentication
public struct TransactionConfirmView: View {
    public let transaction: TransactionRequest
    public let wallet: EreborWallet
    public let config: TransactionConfirmConfig
    public let onConfirm: () async throws -> String
    public let onCancel: () -> Void
    
    @State private var isLoading = false
    @State private var showError = false
    @State private var errorMessage = ""
    @State private var transactionHash: String?
    @State private var showSuccess = false
    @State private var gasEstimate: GasEstimate?
    @State private var showAdvanced = false
    
    @StateObject private var biometricGate = BiometricGate()
    
    public init(
        transaction: TransactionRequest,
        wallet: EreborWallet,
        config: TransactionConfirmConfig = TransactionConfirmConfig(),
        onConfirm: @escaping () async throws -> String,
        onCancel: @escaping () -> Void
    ) {
        self.transaction = transaction
        self.wallet = wallet
        self.config = config
        self.onConfirm = onConfirm
        self.onCancel = onCancel
    }
    
    public var body: some View {
        NavigationView {
            ZStack {
                if showSuccess {
                    successView
                } else {
                    confirmationView
                }
            }
            .navigationTitle("Confirm Transaction")
            .navigationBarTitleDisplayMode(.inline)
            .toolbar {
                ToolbarItem(placement: .navigationBarLeading) {
                    Button("Cancel") {
                        onCancel()
                    }
                    .disabled(isLoading)
                }
            }
            .alert("Error", isPresented: $showError) {
                Button("OK") { }
            } message: {
                Text(errorMessage)
            }
            .task {
                await loadGasEstimate()
            }
        }
    }
    
    // MARK: - Confirmation View
    
    @ViewBuilder
    private var confirmationView: some View {
        ScrollView {
            VStack(spacing: 24) {
                // Transaction summary
                transactionSummaryView
                
                // Wallet info
                walletInfoView
                
                // Gas and fees
                if let gasEstimate = gasEstimate {
                    gasInfoView(gasEstimate)
                }
                
                // Advanced options
                advancedOptionsView
                
                // Security notice
                securityNoticeView
                
                // Confirm button
                confirmButtonView
                
                Spacer()
            }
            .padding(20)
        }
        .disabled(isLoading)
    }
    
    @ViewBuilder
    private var transactionSummaryView: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("Transaction Details")
                .font(.headline)
                .foregroundColor(config.primaryTextColor)
            
            VStack(spacing: 12) {
                // To address
                DetailRow(
                    label: "To",
                    value: formatAddress(transaction.to),
                    copyValue: transaction.to
                )
                
                // Amount
                if let value = transaction.value, let amount = formatAmount(value) {
                    DetailRow(
                        label: "Amount",
                        value: amount,
                        isAmount: true
                    )
                }
                
                // Data/Function
                if let data = transaction.data, !data.isEmpty, data != "0x" {
                    DetailRow(
                        label: "Data",
                        value: formatData(data),
                        copyValue: data
                    )
                }
                
                // Description
                if let description = transaction.description {
                    DetailRow(
                        label: "Description",
                        value: description
                    )
                }
            }
            .padding(16)
            .background(
                RoundedRectangle(cornerRadius: 12)
                    .fill(config.cardBackgroundColor)
            )
        }
    }
    
    @ViewBuilder
    private var walletInfoView: some View {
        VStack(alignment: .leading, spacing: 16) {
            Text("From Wallet")
                .font(.headline)
                .foregroundColor(config.primaryTextColor)
            
            HStack(spacing: 12) {
                // Chain icon
                ZStack {
                    Circle()
                        .fill(chainColor)
                        .frame(width: 40, height: 40)
                    
                    Text(chainSymbol)
                        .font(.caption)
                        .fontWeight(.bold)
                        .foregroundColor(.white)
                }
                
                VStack(alignment: .leading, spacing: 2) {
                    if let name = wallet.name {
                        Text(name)
                            .font(.headline)
                            .foregroundColor(config.primaryTextColor)
                    }
                    
                    Text(wallet.displayAddress)
                        .font(.caption)
                        .foregroundColor(config.secondaryTextColor)
                        .fontDesign(.monospaced)
                    
                    Text(chainDisplayName)
                        .font(.caption)
                        .foregroundColor(config.secondaryTextColor)
                }
                
                Spacer()
            }
            .padding(16)
            .background(
                RoundedRectangle(cornerRadius: 12)
                    .fill(config.cardBackgroundColor)
            )
        }
    }
    
    @ViewBuilder
    private func gasInfoView(_ gasEstimate: GasEstimate) -> some View {
        VStack(alignment: .leading, spacing: 16) {
            HStack {
                Text("Network Fee")
                    .font(.headline)
                    .foregroundColor(config.primaryTextColor)
                
                Spacer()
                
                Button(showAdvanced ? "Hide Advanced" : "Advanced") {
                    withAnimation(.easeInOut(duration: 0.3)) {
                        showAdvanced.toggle()
                    }
                }
                .font(.caption)
                .foregroundColor(.accentColor)
            }
            
            VStack(spacing: 8) {
                DetailRow(
                    label: "Estimated Fee",
                    value: gasEstimate.formattedFee
                )
                
                DetailRow(
                    label: "Max Fee",
                    value: gasEstimate.formattedMaxFee
                )
                
                if showAdvanced {
                    Divider()
                    
                    DetailRow(
                        label: "Gas Limit",
                        value: gasEstimate.gasLimit
                    )
                    
                    DetailRow(
                        label: "Gas Price",
                        value: gasEstimate.formattedGasPrice
                    )
                    
                    if let baseFee = gasEstimate.baseFee {
                        DetailRow(
                            label: "Base Fee",
                            value: baseFee
                        )
                    }
                    
                    if let priorityFee = gasEstimate.priorityFee {
                        DetailRow(
                            label: "Priority Fee",
                            value: priorityFee
                        )
                    }
                }
            }
            .padding(16)
            .background(
                RoundedRectangle(cornerRadius: 12)
                    .fill(config.cardBackgroundColor)
            )
        }
    }
    
    @ViewBuilder
    private var advancedOptionsView: some View {
        if config.showAdvancedOptions {
            VStack(alignment: .leading, spacing: 16) {
                Text("Advanced")
                    .font(.headline)
                    .foregroundColor(config.primaryTextColor)
                
                VStack(spacing: 8) {
                    DetailRow(
                        label: "Chain ID",
                        value: "\(transaction.chainId)"
                    )
                    
                    if let nonce = transaction.nonce {
                        DetailRow(
                            label: "Nonce",
                            value: "\(nonce)"
                        )
                    }
                }
                .padding(16)
                .background(
                    RoundedRectangle(cornerRadius: 12)
                        .fill(config.cardBackgroundColor)
                )
            }
        }
    }
    
    @ViewBuilder
    private var securityNoticeView: some View {
        if config.showSecurityNotice {
            HStack(spacing: 12) {
                Image(systemName: "shield.checkered")
                    .foregroundColor(.orange)
                    .font(.title3)
                
                VStack(alignment: .leading, spacing: 4) {
                    Text("Security Notice")
                        .font(.caption)
                        .fontWeight(.semibold)
                        .foregroundColor(config.primaryTextColor)
                    
                    Text(securityNoticeText)
                        .font(.caption2)
                        .foregroundColor(config.secondaryTextColor)
                        .multilineTextAlignment(.leading)
                }
                
                Spacer()
            }
            .padding(12)
            .background(
                RoundedRectangle(cornerRadius: 8)
                    .fill(Color.orange.opacity(0.1))
            )
        }
    }
    
    @ViewBuilder
    private var confirmButtonView: some View {
        VStack(spacing: 12) {
            // Biometric authentication status
            if biometricGate.isAvailable {
                HStack {
                    Image(systemName: biometricGate.biometricType.iconName)
                        .foregroundColor(.accentColor)
                    
                    Text("Transaction will be secured with \(biometricGate.biometricDisplayName)")
                        .font(.caption)
                        .foregroundColor(config.secondaryTextColor)
                }
            }
            
            Button {
                Task {
                    await confirmTransaction()
                }
            } label: {
                HStack {
                    if isLoading {
                        ProgressView()
                            .scaleEffect(0.8)
                            .progressViewStyle(CircularProgressViewStyle(tint: .white))
                    }
                    
                    Text(isLoading ? "Confirming..." : "Confirm Transaction")
                        .fontWeight(.semibold)
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 16)
                .background(
                    RoundedRectangle(cornerRadius: 12)
                        .fill(isLoading ? Color.gray : config.confirmButtonColor)
                )
                .foregroundColor(.white)
            }
            .disabled(isLoading)
        }
    }
    
    // MARK: - Success View
    
    @ViewBuilder
    private var successView: some View {
        VStack(spacing: 32) {
            Spacer()
            
            // Success animation
            Image(systemName: "checkmark.circle.fill")
                .font(.system(size: 80))
                .foregroundColor(.green)
                .scaleEffect(showSuccess ? 1.0 : 0.1)
                .animation(.spring(response: 0.6, dampingFraction: 0.6), value: showSuccess)
            
            VStack(spacing: 16) {
                Text("Transaction Confirmed!")
                    .font(.title2)
                    .fontWeight(.bold)
                    .foregroundColor(config.primaryTextColor)
                
                Text("Your transaction has been successfully submitted to the blockchain.")
                    .font(.body)
                    .foregroundColor(config.secondaryTextColor)
                    .multilineTextAlignment(.center)
                
                if let hash = transactionHash {
                    VStack(spacing: 8) {
                        Text("Transaction Hash")
                            .font(.caption)
                            .foregroundColor(config.secondaryTextColor)
                        
                        Button {
                            UIPasteboard.general.string = hash
                        } label: {
                            Text(formatAddress(hash))
                                .font(.caption)
                                .fontDesign(.monospaced)
                                .foregroundColor(.accentColor)
                        }
                    }
                    .padding()
                    .background(
                        RoundedRectangle(cornerRadius: 8)
                            .fill(config.cardBackgroundColor)
                    )
                }
            }
            
            Spacer()
            
            Button("Done") {
                onCancel() // Close the view
            }
            .font(.headline)
            .frame(maxWidth: .infinity)
            .padding(.vertical, 16)
            .background(
                RoundedRectangle(cornerRadius: 12)
                    .fill(config.confirmButtonColor)
            )
            .foregroundColor(.white)
        }
        .padding(20)
    }
    
    // MARK: - Helper Views
    
    @ViewBuilder
    private func DetailRow(
        label: String,
        value: String,
        copyValue: String? = nil,
        isAmount: Bool = false
    ) -> some View {
        HStack(alignment: .top) {
            Text(label)
                .font(.caption)
                .foregroundColor(config.secondaryTextColor)
                .frame(width: 80, alignment: .leading)
            
            VStack(alignment: .trailing, spacing: 4) {
                Text(value)
                    .font(isAmount ? .body.bold() : .body)
                    .foregroundColor(config.primaryTextColor)
                    .multilineTextAlignment(.trailing)
                
                if let copyValue = copyValue {
                    Button("Copy") {
                        UIPasteboard.general.string = copyValue
                    }
                    .font(.caption2)
                    .foregroundColor(.accentColor)
                }
            }
            
            Spacer()
        }
    }
    
    // MARK: - Actions
    
    private func loadGasEstimate() async {
        // This would typically call an API to estimate gas
        // For now, we'll create a mock estimate
        gasEstimate = GasEstimate(
            gasLimit: "21000",
            gasPrice: "20 Gwei",
            estimatedFee: "0.00042 ETH",
            maxFee: "0.0006 ETH",
            baseFee: "15 Gwei",
            priorityFee: "2 Gwei"
        )
    }
    
    private func confirmTransaction() async {
        isLoading = true
        
        do {
            let hash = try await onConfirm()
            transactionHash = hash
            
            withAnimation(.easeInOut(duration: 0.5)) {
                showSuccess = true
            }
        } catch {
            errorMessage = error.localizedDescription
            showError = true
        }
        
        isLoading = false
    }
    
    // MARK: - Computed Properties
    
    private var chainDisplayName: String {
        switch wallet.chainId {
        case 1: return "Ethereum"
        case 137: return "Polygon"
        case 42161: return "Arbitrum"
        case 10: return "Optimism"
        case 8453: return "Base"
        case 11155111: return "Sepolia"
        default: return "Chain \(wallet.chainId)"
        }
    }
    
    private var chainSymbol: String {
        switch wallet.chainId {
        case 1, 42161, 10, 8453, 11155111: return "ETH"
        case 137: return "MATIC"
        default: return "?"
        }
    }
    
    private var chainColor: Color {
        switch wallet.chainId {
        case 1, 11155111: return Color(hex: "#627EEA")
        case 137: return Color(hex: "#8247E5")
        case 42161: return Color(hex: "#28A0F0")
        case 10: return Color(hex: "#FF0420")
        case 8453: return Color(hex: "#0052FF")
        default: return Color.gray
        }
    }
    
    private var securityNoticeText: String {
        if biometricGate.isAvailable {
            return "This transaction will require \(biometricGate.biometricDisplayName) authentication before signing."
        } else {
            return "Please verify the transaction details carefully before confirming."
        }
    }
    
    // MARK: - Formatting Helpers
    
    private func formatAddress(_ address: String) -> String {
        guard address.count > 10 else { return address }
        let start = address.prefix(6)
        let end = address.suffix(4)
        return "\(start)...\(end)"
    }
    
    private func formatAmount(_ value: String) -> String? {
        guard let valueInt = UInt64(value) else { return nil }
        let eth = Double(valueInt) / 1e18
        return String(format: "%.6f %@", eth, chainSymbol)
    }
    
    private func formatData(_ data: String) -> String {
        if data.isEmpty || data == "0x" {
            return "None"
        }
        
        // Try to detect common function signatures
        if data.hasPrefix("0xa9059cbb") {
            return "ERC-20 Transfer"
        } else if data.hasPrefix("0x095ea7b3") {
            return "ERC-20 Approval"
        } else {
            return "\(data.prefix(10))..."
        }
    }
}

// MARK: - Supporting Types

public struct GasEstimate {
    let gasLimit: String
    let gasPrice: String
    let estimatedFee: String
    let maxFee: String
    let baseFee: String?
    let priorityFee: String?
    
    var formattedFee: String { estimatedFee }
    var formattedMaxFee: String { maxFee }
    var formattedGasPrice: String { gasPrice }
}

// MARK: - Configuration

public struct TransactionConfirmConfig {
    public let primaryTextColor: Color
    public let secondaryTextColor: Color
    public let cardBackgroundColor: Color
    public let confirmButtonColor: Color
    public let showAdvancedOptions: Bool
    public let showSecurityNotice: Bool
    
    public init(
        primaryTextColor: Color = Color(.label),
        secondaryTextColor: Color = Color(.secondaryLabel),
        cardBackgroundColor: Color = Color(.secondarySystemBackground),
        confirmButtonColor: Color = .accentColor,
        showAdvancedOptions: Bool = false,
        showSecurityNotice: Bool = true
    ) {
        self.primaryTextColor = primaryTextColor
        self.secondaryTextColor = secondaryTextColor
        self.cardBackgroundColor = cardBackgroundColor
        self.confirmButtonColor = confirmButtonColor
        self.showAdvancedOptions = showAdvancedOptions
        self.showSecurityNotice = showSecurityNotice
    }
}

// MARK: - Preview

#if DEBUG
struct TransactionConfirmView_Previews: PreviewProvider {
    static var previews: some View {
        TransactionConfirmView(
            transaction: TransactionRequest(
                to: "0x1234567890123456789012345678901234567890",
                value: "1000000000000000000",
                chainId: 1,
                description: "Send ETH to Alice"
            ),
            wallet: EreborWallet(
                id: "wallet-1",
                address: "0x9876543210987654321098765432109876543210",
                chainId: 1,
                chainType: .evm,
                name: "My Wallet"
            ),
            onConfirm: {
                try await Task.sleep(nanoseconds: 2_000_000_000)
                return "0xabcdef1234567890"
            },
            onCancel: { }
        )
    }
}
#endif