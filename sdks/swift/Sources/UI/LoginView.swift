import SwiftUI
import AuthenticationServices

/// SwiftUI login screen with support for multiple authentication methods
public struct LoginView: View {
    @StateObject private var erebor = Erebor.shared
    @State private var selectedMethod: AuthProvider = .email
    @State private var email = ""
    @State private var phoneNumber = ""
    @State private var otpCode = ""
    @State private var currentOTPSession: OTPSession?
    @State private var showError = false
    @State private var errorMessage = ""
    @State private var isLoading = false
    
    // Configuration
    public let config: LoginViewConfig
    public let onSuccess: (EreborUser) -> Void
    public let onCancel: (() -> Void)?
    
    public init(
        config: LoginViewConfig = LoginViewConfig(),
        onSuccess: @escaping (EreborUser) -> Void,
        onCancel: (() -> Void)? = nil
    ) {
        self.config = config
        self.onSuccess = onSuccess
        self.onCancel = onCancel
    }
    
    public var body: some View {
        NavigationView {
            ScrollView {
                VStack(spacing: 24) {
                    // Logo and title
                    headerView
                    
                    // Login methods
                    loginMethodsView
                    
                    // Selected method form
                    selectedMethodView
                    
                    Spacer()
                }
                .padding(24)
            }
            .navigationTitle("Sign In")
            .navigationBarTitleDisplayMode(.large)
            .toolbar {
                if let onCancel = onCancel {
                    ToolbarItem(placement: .navigationBarLeading) {
                        Button("Cancel", action: onCancel)
                    }
                }
            }
            .alert("Error", isPresented: $showError) {
                Button("OK") { }
            } message: {
                Text(errorMessage)
            }
            .disabled(isLoading || erebor.isLoading)
            .onChange(of: erebor.isAuthenticated) { authenticated in
                if authenticated, let user = erebor.user {
                    onSuccess(user)
                }
            }
        }
    }
    
    // MARK: - Header View
    
    @ViewBuilder
    private var headerView: some View {
        VStack(spacing: 16) {
            // Logo
            if let logoUrl = config.logoUrl,
               let url = URL(string: logoUrl) {
                AsyncImage(url: url) { image in
                    image
                        .resizable()
                        .aspectRatio(contentMode: .fit)
                } placeholder: {
                    RoundedRectangle(cornerRadius: 12)
                        .fill(Color.gray.opacity(0.2))
                        .frame(height: 60)
                }
                .frame(height: 60)
            }
            
            // Title and subtitle
            VStack(spacing: 8) {
                Text(config.title)
                    .font(.title2)
                    .fontWeight(.semibold)
                
                if let subtitle = config.subtitle {
                    Text(subtitle)
                        .font(.subheadline)
                        .foregroundColor(.secondary)
                        .multilineTextAlignment(.center)
                }
            }
        }
    }
    
    // MARK: - Login Methods Picker
    
    @ViewBuilder
    private var loginMethodsView: some View {
        if config.availableMethods.count > 1 {
            VStack(alignment: .leading, spacing: 12) {
                Text("Choose sign-in method")
                    .font(.headline)
                    .foregroundColor(.primary)
                
                LazyVGrid(columns: [
                    GridItem(.flexible()),
                    GridItem(.flexible())
                ], spacing: 12) {
                    ForEach(config.availableMethods, id: \.self) { method in
                        methodButton(for: method)
                    }
                }
            }
        }
    }
    
    @ViewBuilder
    private func methodButton(for method: AuthProvider) -> some View {
        Button {
            selectedMethod = method
            resetForm()
        } label: {
            HStack {
                Image(systemName: iconName(for: method))
                    .foregroundColor(Color(hex: method.brandColor))
                
                Text(method.displayName)
                    .fontWeight(.medium)
                
                Spacer()
                
                if selectedMethod == method {
                    Image(systemName: "checkmark")
                        .foregroundColor(.accentColor)
                }
            }
            .padding(.horizontal, 16)
            .padding(.vertical, 12)
            .background(
                RoundedRectangle(cornerRadius: 12)
                    .fill(selectedMethod == method ? Color.accentColor.opacity(0.1) : Color.gray.opacity(0.1))
                    .overlay(
                        RoundedRectangle(cornerRadius: 12)
                            .stroke(selectedMethod == method ? Color.accentColor : Color.clear, lineWidth: 1)
                    )
            )
        }
        .buttonStyle(PlainButtonStyle())
    }
    
    // MARK: - Selected Method View
    
    @ViewBuilder
    private var selectedMethodView: some View {
        VStack(spacing: 20) {
            switch selectedMethod {
            case .email:
                emailLoginView
            case .phone:
                phoneLoginView
            case .google:
                googleLoginView
            case .apple:
                appleLoginView
            case .siwe:
                siweLoginView
            default:
                oauthLoginView
            }
        }
    }
    
    // MARK: - Email Login
    
    @ViewBuilder
    private var emailLoginView: some View {
        VStack(spacing: 16) {
            if currentOTPSession == nil {
                // Email input
                VStack(alignment: .leading, spacing: 8) {
                    Text("Email Address")
                        .font(.headline)
                    
                    TextField("Enter your email", text: $email)
                        .textFieldStyle(RoundedBorderTextFieldStyle())
                        .keyboardType(.emailAddress)
                        .autocapitalization(.none)
                        .disableAutocorrection(true)
                }
                
                Button {
                    Task {
                        await sendEmailOTP()
                    }
                } label: {
                    HStack {
                        if isLoading {
                            ProgressView()
                                .scaleEffect(0.8)
                        }
                        Text("Send Verification Code")
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 12)
                    .background(Color.accentColor)
                    .foregroundColor(.white)
                    .clipShape(RoundedRectangle(cornerRadius: 12))
                }
                .disabled(email.isEmpty || isLoading)
            } else {
                // OTP verification
                otpVerificationView
            }
        }
    }
    
    // MARK: - Phone Login
    
    @ViewBuilder
    private var phoneLoginView: some View {
        VStack(spacing: 16) {
            if currentOTPSession == nil {
                // Phone input
                VStack(alignment: .leading, spacing: 8) {
                    Text("Phone Number")
                        .font(.headline)
                    
                    TextField("Enter your phone number", text: $phoneNumber)
                        .textFieldStyle(RoundedBorderTextFieldStyle())
                        .keyboardType(.phonePad)
                }
                
                Button {
                    Task {
                        await sendPhoneOTP()
                    }
                } label: {
                    HStack {
                        if isLoading {
                            ProgressView()
                                .scaleEffect(0.8)
                        }
                        Text("Send Verification Code")
                    }
                    .frame(maxWidth: .infinity)
                    .padding(.vertical, 12)
                    .background(Color.accentColor)
                    .foregroundColor(.white)
                    .clipShape(RoundedRectangle(cornerRadius: 12))
                }
                .disabled(phoneNumber.isEmpty || isLoading)
            } else {
                // OTP verification
                otpVerificationView
            }
        }
    }
    
    // MARK: - OTP Verification
    
    @ViewBuilder
    private var otpVerificationView: some View {
        VStack(spacing: 16) {
            VStack(alignment: .leading, spacing: 8) {
                Text("Verification Code")
                    .font(.headline)
                
                Text("Enter the code sent to \(currentOTPSession?.contact ?? "")")
                    .font(.caption)
                    .foregroundColor(.secondary)
                
                TextField("000000", text: $otpCode)
                    .textFieldStyle(RoundedBorderTextFieldStyle())
                    .keyboardType(.numberPad)
                    .multilineTextAlignment(.center)
                    .font(.title2.monospaced())
            }
            
            Button {
                Task {
                    await verifyOTP()
                }
            } label: {
                HStack {
                    if isLoading {
                        ProgressView()
                            .scaleEffect(0.8)
                    }
                    Text("Verify Code")
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 12)
                .background(Color.accentColor)
                .foregroundColor(.white)
                .clipShape(RoundedRectangle(cornerRadius: 12))
            }
            .disabled(otpCode.isEmpty || isLoading)
            
            Button("Back") {
                currentOTPSession = nil
                otpCode = ""
            }
            .foregroundColor(.secondary)
        }
    }
    
    // MARK: - Social Logins
    
    @ViewBuilder
    private var googleLoginView: some View {
        Button {
            Task {
                await loginWithGoogle()
            }
        } label: {
            HStack {
                if isLoading {
                    ProgressView()
                        .scaleEffect(0.8)
                } else {
                    Image(systemName: "globe")
                }
                Text("Continue with Google")
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 12)
            .background(Color(hex: "#4285F4"))
            .foregroundColor(.white)
            .clipShape(RoundedRectangle(cornerRadius: 12))
        }
        .disabled(isLoading)
    }
    
    @ViewBuilder
    private var appleLoginView: some View {
        SignInWithAppleButton(
            onRequest: { request in
                request.requestedScopes = [.fullName, .email]
            },
            onCompletion: { result in
                Task {
                    await handleAppleSignIn(result)
                }
            }
        )
        .frame(height: 44)
        .clipShape(RoundedRectangle(cornerRadius: 12))
    }
    
    @ViewBuilder
    private var siweLoginView: some View {
        VStack(spacing: 16) {
            Text("Sign in with your Ethereum wallet")
                .font(.subheadline)
                .multilineTextAlignment(.center)
                .foregroundColor(.secondary)
            
            Button {
                // This would trigger wallet connection
                // Implementation depends on wallet integration
            } label: {
                HStack {
                    Image(systemName: "bitcoinsign.circle")
                    Text("Connect Wallet")
                }
                .frame(maxWidth: .infinity)
                .padding(.vertical, 12)
                .background(Color(hex: "#627EEA"))
                .foregroundColor(.white)
                .clipShape(RoundedRectangle(cornerRadius: 12))
            }
        }
    }
    
    @ViewBuilder
    private var oauthLoginView: some View {
        Button {
            Task {
                await loginWithOAuth()
            }
        } label: {
            HStack {
                if isLoading {
                    ProgressView()
                        .scaleEffect(0.8)
                } else {
                    Image(systemName: iconName(for: selectedMethod))
                }
                Text("Continue with \(selectedMethod.displayName)")
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 12)
            .background(Color(hex: selectedMethod.brandColor))
            .foregroundColor(.white)
            .clipShape(RoundedRectangle(cornerRadius: 12))
        }
        .disabled(isLoading)
    }
    
    // MARK: - Authentication Methods
    
    private func sendEmailOTP() async {
        isLoading = true
        
        do {
            let session = try await erebor.auth?.loginWithEmail(email)
            currentOTPSession = session
        } catch {
            showError(error.localizedDescription)
        }
        
        isLoading = false
    }
    
    private func sendPhoneOTP() async {
        isLoading = true
        
        do {
            let session = try await erebor.auth?.loginWithPhone(phoneNumber)
            currentOTPSession = session
        } catch {
            showError(error.localizedDescription)
        }
        
        isLoading = false
    }
    
    private func verifyOTP() async {
        guard let session = currentOTPSession else { return }
        
        isLoading = true
        
        do {
            let _ = try await erebor.auth?.verifyEmailOTP(session, code: otpCode)
            // Success handled by onChange observer
        } catch {
            showError(error.localizedDescription)
        }
        
        isLoading = false
    }
    
    private func loginWithGoogle() async {
        guard let presentingVC = UIApplication.shared.windows.first?.rootViewController else {
            return
        }
        
        isLoading = true
        
        do {
            let _ = try await erebor.auth?.loginWithGoogle(presenting: presentingVC)
            // Success handled by onChange observer
        } catch {
            showError(error.localizedDescription)
        }
        
        isLoading = false
    }
    
    private func handleAppleSignIn(_ result: Result<ASAuthorization, Error>) async {
        isLoading = true
        
        switch result {
        case .success(let authorization):
            if authorization.credential is ASAuthorizationAppleIDCredential {
                guard let presentingVC = UIApplication.shared.windows.first?.rootViewController else {
                    return
                }
                
                do {
                    let _ = try await erebor.auth?.loginWithApple(presenting: presentingVC)
                    // Success handled by onChange observer
                } catch {
                    showError(error.localizedDescription)
                }
            }
        case .failure(let error):
            showError(error.localizedDescription)
        }
        
        isLoading = false
    }
    
    private func loginWithOAuth() async {
        guard let presentingVC = UIApplication.shared.windows.first?.rootViewController else {
            return
        }
        
        isLoading = true
        
        do {
            let _ = try await erebor.auth?.loginWithOAuth(selectedMethod, presenting: presentingVC)
            // Success handled by onChange observer
        } catch {
            showError(error.localizedDescription)
        }
        
        isLoading = false
    }
    
    // MARK: - Helpers
    
    private func resetForm() {
        email = ""
        phoneNumber = ""
        otpCode = ""
        currentOTPSession = nil
    }
    
    private func showError(_ message: String) {
        errorMessage = message
        showError = true
    }
    
    private func iconName(for provider: AuthProvider) -> String {
        switch provider {
        case .email:
            return "envelope"
        case .phone:
            return "phone"
        case .google:
            return "globe"
        case .apple:
            return "apple.logo"
        case .siwe:
            return "bitcoinsign.circle"
        case .discord:
            return "gamecontroller"
        case .github:
            return "chevron.left.forwardslash.chevron.right"
        case .twitter:
            return "at"
        case .farcaster:
            return "bubble.left.and.bubble.right"
        case .telegram:
            return "paperplane"
        }
    }
}

// MARK: - Configuration

public struct LoginViewConfig {
    public let title: String
    public let subtitle: String?
    public let logoUrl: String?
    public let availableMethods: [AuthProvider]
    public let primaryColor: Color
    public let cornerRadius: CGFloat
    
    public init(
        title: String = "Welcome to Erebor",
        subtitle: String? = "Sign in to access your wallet",
        logoUrl: String? = nil,
        availableMethods: [AuthProvider] = [.email, .google, .apple],
        primaryColor: Color = .accentColor,
        cornerRadius: CGFloat = 12
    ) {
        self.title = title
        self.subtitle = subtitle
        self.logoUrl = logoUrl
        self.availableMethods = availableMethods
        self.primaryColor = primaryColor
        self.cornerRadius = cornerRadius
    }
}

// MARK: - Color Extension

extension Color {
    init(hex: String) {
        let scanner = Scanner(string: hex.hasPrefix("#") ? String(hex.dropFirst()) : hex)
        var rgbValue: UInt64 = 0
        scanner.scanHexInt64(&rgbValue)
        
        let red = Double((rgbValue & 0xFF0000) >> 16) / 255.0
        let green = Double((rgbValue & 0x00FF00) >> 8) / 255.0
        let blue = Double(rgbValue & 0x0000FF) / 255.0
        
        self.init(red: red, green: green, blue: blue)
    }
}