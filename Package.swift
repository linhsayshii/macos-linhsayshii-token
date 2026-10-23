// swift-tools-version: 6.0
import PackageDescription

let package = Package(
    name: "TokenSigner",
    platforms: [.macOS(.v14)],
    products: [
        .library(name: "TSShim", type: .dynamic, targets: ["TSShim"]),
    ],
    dependencies: [
        .package(url: "https://github.com/apple/swift-nio.git", from: "2.76.0"),
        .package(url: "https://github.com/apple/swift-nio-ssl.git", from: "2.27.0"),
        .package(url: "https://github.com/apple/swift-certificates.git", from: "1.6.0"),
        .package(url: "https://github.com/apple/swift-asn1.git", from: "1.3.0"),
    ],
    targets: [
        .target(name: "TSShim", linkerSettings: [
            .linkedFramework("PCSC")
        ]),
        .target(name: "CPKCS11"),
        .target(name: "CMinvoiceZIP", linkerSettings: [.linkedLibrary("z")]),
        .target(name: "CFastCA", exclude: ["vendor/COPYING", "vendor/README.md"],
                cSettings: [.define("ENABLE_SM"), .headerSearchPath("vendor")]),
        .target(name: "CPCSC", linkerSettings: [
            .linkedFramework("PCSC")
        ]),
        .target(name: "Core", dependencies: [
            "CPCSC",
            .product(name: "X509", package: "swift-certificates"),
            .product(name: "SwiftASN1", package: "swift-asn1"),
        ]),
        .executableTarget(name: "TokenHelper", dependencies: [
            "Core", "TSShim", "CPKCS11", "CFastCA",
            .product(name: "X509", package: "swift-certificates"),
            .product(name: "SwiftASN1", package: "swift-asn1"),
        ]),
        .target(name: "Bridges", dependencies: [
            "Core", "CMinvoiceZIP",
            .product(name: "NIOCore", package: "swift-nio"),
            .product(name: "NIOPosix", package: "swift-nio"),
            .product(name: "NIOHTTP1", package: "swift-nio"),
            .product(name: "NIOWebSocket", package: "swift-nio"),
            .product(name: "NIOSSL", package: "swift-nio-ssl"),
        ]),
        .executableTarget(name: "App", dependencies: ["Core", "Bridges"]),
        .testTarget(name: "AppTests", dependencies: ["App", "Core", "Bridges"]),
        .testTarget(name: "TokenHelperTests", dependencies: ["TokenHelper", "Core"]),
        .testTarget(name: "CoreTests", dependencies: ["Core"]),
        .testTarget(name: "BridgesTests", dependencies: ["Bridges", "Core"]),
        .testTarget(name: "TSShimTests", dependencies: ["TSShim"]),
    ]
)
