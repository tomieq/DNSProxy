// swift-tools-version: 6.1

import PackageDescription

let package = Package(
    name: "DNSProxy",
    targets: [
        .target(
            name: "DNSProxy"
        ),
        .executableTarget(
            name: "DNSProxyCLI",
            dependencies: ["DNSProxy"]
        ),
        .testTarget(
            name: "DNSProxyTests",
            dependencies: ["DNSProxy"]
        ),
    ]
)
