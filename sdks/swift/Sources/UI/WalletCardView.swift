import SwiftUI

/// SwiftUI component to display wallet information with balance
public struct WalletCardView: View {
    public let wallet: EreborWallet
    public let config: WalletCardConfig
    public let onTap: (() -> Void)?
    public let onCopy: (() -> Void)?
    
    @State private var showFullAddress = false
    @State private var showCopiedFeedback = false
    
    public init(
        wallet: EreborWallet,
        config: WalletCardConfig = WalletCardConfig(),
        onTap: (() -> Void)? = nil,
        onCopy: (() -> Void)? = nil
    ) {
        self.wallet = wallet
        self.config = config
        self.onTap = onTap
        self.onCopy = onCopy
    }
    
    public var body: some View {
        Button {
            onTap?()
        } label: {
            cardContent
        }
        .buttonStyle(PlainButtonStyle())
        .background(
            RoundedRectangle(cornerRadius: config.cornerRadius)
                .fill(config.backgroundColor)
                .shadow(
                    color: config.shadowColor,
                    radius: config.shadowRadius,
                    x: 0,
                    y: config.shadowOffset
                )
        )
        .overlay(
            RoundedRectangle(cornerRadius: config.cornerRadius)
                .stroke(config.borderColor, lineWidth: config.borderWidth)
        )
    }
    
    @ViewBuilder
    private var cardContent: some View {
        VStack(alignment: .leading, spacing: 12) {
            // Header with chain and status
            headerView
            
            // Address section
            addressView
            
            // Balance section
            if config.showBalance {
                balanceView
            }
            
            // Actions
            if config.showActions {
                actionsView
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
    }
    
    @ViewBuilder
    private var headerView: some View {
        HStack {
            // Chain icon and name
            HStack(spacing: 8) {
                chainIcon
                
                VStack(alignment: .leading, spacing: 2) {
                    if let name = wallet.name {
                        Text(name)
                            .font(.headline)
                            .foregroundColor(config.primaryTextColor)
                    }
                    
                    Text(chainDisplayName)
                        .font(.caption)
                        .foregroundColor(config.secondaryTextColor)
                }
            }
            
            Spacer()
            
            // Status indicators
            statusView
        }
    }
    
    @ViewBuilder
    private var chainIcon: some View {
        ZStack {
            Circle()
                .fill(chainColor)
                .frame(width: 32, height: 32)
            
            Text(chainSymbol)
                .font(.caption2)
                .fontWeight(.bold)
                .foregroundColor(.white)
        }
    }
    
    @ViewBuilder
    private var statusView: some View {
        HStack(spacing: 8) {
            if !wallet.isActive {
                Image(systemName: "pause.circle")
                    .foregroundColor(.orange)
                    .font(.caption)
            }
            
            if wallet.imported {
                Image(systemName: "square.and.arrow.down")
                    .foregroundColor(.blue)
                    .font(.caption)
            }
            
            Image(systemName: "chevron.right")
                .font(.caption2)
                .foregroundColor(config.secondaryTextColor)
        }
    }
    
    @ViewBuilder
    private var addressView: some View {
        VStack(alignment: .leading, spacing: 8) {
            HStack {
                Text("Address")
                    .font(.caption)
                    .foregroundColor(config.secondaryTextColor)
                
                Spacer()
                
                Button {
                    copyAddress()
                } label: {
                    HStack(spacing: 4) {
                        Image(systemName: showCopiedFeedback ? "checkmark" : "doc.on.doc")
                            .font(.caption)
                        
                        if showCopiedFeedback {
                            Text("Copied")
                                .font(.caption2)
                        }
                    }
                    .foregroundColor(.accentColor)
                }
            }
            
            Button {
                showFullAddress.toggle()
            } label: {
                Text(showFullAddress ? wallet.address : wallet.displayAddress)
                    .font(.system(.body, design: .monospaced))
                    .foregroundColor(config.primaryTextColor)
                    .multilineTextAlignment(.leading)
            }
        }
        .padding(.vertical, 8)
        .padding(.horizontal, 12)
        .background(
            RoundedRectangle(cornerRadius: 8)
                .fill(config.backgroundColor.opacity(0.5))
        )
    }
    
    @ViewBuilder
    private var balanceView: some View {
        if let balance = wallet.cachedBalance {
            VStack(alignment: .leading, spacing: 8) {
                Text("Balance")
                    .font(.caption)
                    .foregroundColor(config.secondaryTextColor)
                
                VStack(alignment: .leading, spacing: 4) {
                    // Native balance
                    HStack(alignment: .firstTextBaseline) {
                        Text(balance.nativeFormatted)
                            .font(.title3)
                            .fontWeight(.semibold)
                            .foregroundColor(config.primaryTextColor)
                        
                        Text(chainSymbol)
                            .font(.caption)
                            .foregroundColor(config.secondaryTextColor)
                        
                        Spacer()
                        
                        if let usdValue = balance.nativeUsd {
                            Text("$\(usdValue)")
                                .font(.caption)
                                .foregroundColor(config.secondaryTextColor)
                        }
                    }
                    
                    // Token balances
                    if !balance.tokens.isEmpty && config.showTokens {
                        tokenBalancesView(balance.tokens)
                    }
                }
            }
        } else {
            HStack {
                Text("Balance")
                    .font(.caption)
                    .foregroundColor(config.secondaryTextColor)
                
                Spacer()
                
                Text("Tap to refresh")
                    .font(.caption2)
                    .foregroundColor(.accentColor)
            }
        }
    }
    
    @ViewBuilder
    private func tokenBalancesView(_ tokens: [TokenBalance]) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            ForEach(tokens.prefix(config.maxTokensShown), id: \.address) { token in
                HStack {
                    Text(token.symbol)
                        .font(.caption2)
                        .foregroundColor(config.secondaryTextColor)
                    
                    Spacer()
                    
                    Text(token.balanceFormatted)
                        .font(.caption2)
                        .foregroundColor(config.secondaryTextColor)
                    
                    if let usdValue = token.balanceUsd {
                        Text("$\(usdValue)")
                            .font(.caption2)
                            .foregroundColor(config.secondaryTextColor)
                    }
                }
            }
            
            if tokens.count > config.maxTokensShown {
                Text("and \(tokens.count - config.maxTokensShown) more...")
                    .font(.caption2)
                    .foregroundColor(config.secondaryTextColor)
            }
        }
    }
    
    @ViewBuilder
    private var actionsView: some View {
        HStack(spacing: 12) {
            actionButton("Send", icon: "arrow.up") {
                // Handle send action
            }
            
            actionButton("Receive", icon: "arrow.down") {
                // Handle receive action
            }
            
            if wallet.supportsContracts {
                actionButton("DApps", icon: "globe") {
                    // Handle DApp browser action
                }
            }
        }
    }
    
    @ViewBuilder
    private func actionButton(_ title: String, icon: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            HStack(spacing: 4) {
                Image(systemName: icon)
                    .font(.caption)
                
                Text(title)
                    .font(.caption)
            }
            .padding(.horizontal, 12)
            .padding(.vertical, 6)
            .background(
                RoundedRectangle(cornerRadius: 16)
                    .fill(Color.accentColor.opacity(0.1))
            )
            .foregroundColor(.accentColor)
        }
    }
    
    // MARK: - Computed Properties
    
    private var chainDisplayName: String {
        // This would normally come from a chain registry
        switch wallet.chainId {
        case 1:
            return "Ethereum"
        case 137:
            return "Polygon"
        case 42161:
            return "Arbitrum"
        case 10:
            return "Optimism"
        case 8453:
            return "Base"
        case 11155111:
            return "Sepolia"
        default:
            return "Chain \(wallet.chainId)"
        }
    }
    
    private var chainSymbol: String {
        switch wallet.chainId {
        case 1, 42161, 10, 8453, 11155111:
            return "ETH"
        case 137:
            return "MATIC"
        default:
            return "?"
        }
    }
    
    private var chainColor: Color {
        switch wallet.chainId {
        case 1, 11155111:
            return Color(hex: "#627EEA")
        case 137:
            return Color(hex: "#8247E5")
        case 42161:
            return Color(hex: "#28A0F0")
        case 10:
            return Color(hex: "#FF0420")
        case 8453:
            return Color(hex: "#0052FF")
        default:
            return Color.gray
        }
    }
    
    // MARK: - Actions
    
    private func copyAddress() {
        UIPasteboard.general.string = wallet.address
        onCopy?()
        
        // Show feedback
        withAnimation(.easeInOut(duration: 0.2)) {
            showCopiedFeedback = true
        }
        
        DispatchQueue.main.asyncAfter(deadline: .now() + 2.0) {
            withAnimation(.easeInOut(duration: 0.2)) {
                showCopiedFeedback = false
            }
        }
    }
}

// MARK: - Configuration

public struct WalletCardConfig {
    public let backgroundColor: Color
    public let primaryTextColor: Color
    public let secondaryTextColor: Color
    public let borderColor: Color
    public let shadowColor: Color
    public let cornerRadius: CGFloat
    public let borderWidth: CGFloat
    public let shadowRadius: CGFloat
    public let shadowOffset: CGFloat
    public let showBalance: Bool
    public let showTokens: Bool
    public let showActions: Bool
    public let maxTokensShown: Int
    
    public init(
        backgroundColor: Color = Color(.systemBackground),
        primaryTextColor: Color = Color(.label),
        secondaryTextColor: Color = Color(.secondaryLabel),
        borderColor: Color = Color(.separator),
        shadowColor: Color = Color(.black).opacity(0.1),
        cornerRadius: CGFloat = 16,
        borderWidth: CGFloat = 0.5,
        shadowRadius: CGFloat = 4,
        shadowOffset: CGFloat = 2,
        showBalance: Bool = true,
        showTokens: Bool = true,
        showActions: Bool = true,
        maxTokensShown: Int = 3
    ) {
        self.backgroundColor = backgroundColor
        self.primaryTextColor = primaryTextColor
        self.secondaryTextColor = secondaryTextColor
        self.borderColor = borderColor
        self.shadowColor = shadowColor
        self.cornerRadius = cornerRadius
        self.borderWidth = borderWidth
        self.shadowRadius = shadowRadius
        self.shadowOffset = shadowOffset
        self.showBalance = showBalance
        self.showTokens = showTokens
        self.showActions = showActions
        self.maxTokensShown = maxTokensShown
    }
    
    public static let compact = WalletCardConfig(
        showBalance: false,
        showActions: false
    )
    
    public static let minimal = WalletCardConfig(
        showBalance: false,
        showTokens: false,
        showActions: false,
        shadowRadius: 0,
        borderWidth: 1
    )
}

// MARK: - Preview

#if DEBUG
struct WalletCardView_Previews: PreviewProvider {
    static var previews: some View {
        VStack(spacing: 16) {
            WalletCardView(
                wallet: sampleWallet
            )
            
            WalletCardView(
                wallet: sampleWallet,
                config: .compact
            )
            
            WalletCardView(
                wallet: sampleWallet,
                config: .minimal
            )
        }
        .padding()
        .background(Color(.systemGroupedBackground))
    }
    
    static var sampleWallet: EreborWallet {
        var wallet = EreborWallet(
            id: "wallet-1",
            address: "0x1234567890123456789012345678901234567890",
            chainId: 1,
            chainType: .evm,
            name: "My Wallet"
        )
        
        wallet.cachedBalance = WalletBalance(
            native: "1500000000000000000",
            nativeFormatted: "1.5",
            nativeUsd: "3750.00",
            tokens: [
                TokenBalance(
                    address: "0xa0b86a33e6041b53c8f36510423a13e0ccb0e381",
                    symbol: "USDC",
                    name: "USD Coin",
                    decimals: 6,
                    balance: "1000000000",
                    balanceFormatted: "1,000.00",
                    balanceUsd: "1000.00"
                )
            ]
        )
        
        return wallet
    }
}
#endif