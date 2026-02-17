// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "EreborSwift",
    platforms: [.iOS(.v15), .macOS(.v13)],
    products: [
        .library(name: "EreborSwift", targets: ["EreborSwift"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "3.0.0"),
    ],
    targets: [
        .target(
            name: "EreborSwift", 
            dependencies: [
                .product(name: "Crypto", package: "swift-crypto"),
            ],
            path: "Sources"
        ),
        .testTarget(
            name: "EreborSwiftTests", 
            dependencies: ["EreborSwift"], 
            path: "Tests"
        ),
    ]
)