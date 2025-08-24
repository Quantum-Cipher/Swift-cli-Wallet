// swift-tools-version:6.0
import PackageDescription

let package = Package(
    name: "SwiftCliWallet",
    platforms: [.macOS(.v13)],
    products: [
        .executable(name: "swiftcliwallet", targets: ["SwiftCliWallet"])
    ],
    dependencies: [],
    targets: [
        .executableTarget(
            name: "SwiftCliWallet",
            path: "Sources/SwiftCliWallet"
        )
    ]
)
