// swift-tools-version: 5.8

import PackageDescription

let package = Package(
    name: "benchmarks",
    platforms: [
        .macOS(.v13),
    ],
    dependencies: [
        .package(path: "../"), // `swift-certificates`
        .package(url: "https://github.com/ordo-one/package-benchmark", .upToNextMajor(from: "1.0.0")),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "2.5.0"),
        .package(url: "https://github.com/apple/swift-asn1.git", .upToNextMinor(from: "0.10.0")),
    ],
    targets: [
        .executableTarget(
            name: "CertificatesBenchmarks",
            dependencies: [
                "Sources",
                .product(name: "Benchmark", package: "package-benchmark"),
            ],
            path: "Benchmarks/CertificatesBenchmarks",
            plugins: [
                .plugin(name: "BenchmarkPlugin", package: "package-benchmark")
            ]
        ),
        .target(
            name: "Sources",
            dependencies: [
                .product(name: "Benchmark", package: "package-benchmark"),
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "SwiftASN1", package: "swift-asn1"),
                .product(name: "Crypto", package: "swift-crypto"),
            ],
            path: "Sources"
        ),
        .testTarget(
            name: "Tests",
            dependencies: [
                "Sources",
            ],
            path: "Tests"
        )
    ]
)
