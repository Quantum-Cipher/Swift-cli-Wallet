// swift-tools-version: 6.1
import PackageDescription

let package = Package(
    name: "SwiftCliWallet",
    platforms: [.macOS(.v13)],
    products: [
        .executable(name: "swiftcliwallet", targets: ["SwiftCliWallet"])
    ],
    targets: [
        .executableTarget(
            name: "SwiftCliWallet",
            path: "Sources/SwiftCliWallet"
        )
    ]
)
