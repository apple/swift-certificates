// swift-tools-version: 5.8
// The swift-tools-version declares the minimum version of Swift required to build this package.

import PackageDescription

let package = Package(
    name: "benchmarks",
    platforms: [
        .macOS(.v13),
    ],
    dependencies: [
        .package(path: "../"),
        .package(url: "https://github.com/ordo-one/package-benchmark", .upToNextMajor(from: "1.0.0")),
        .package(url: "https://github.com/apple/swift-crypto.git", from: "2.5.0"),
        //.package(url: "https://github.com/apple/swift-asn1.git", .upToNextMinor(from: "0.10.0")),
        .package(path: "../swift-asn1"),
    ],
    targets: [
        .executableTarget(
            name: "CertificatesBenchmarks",
            dependencies: [
                .product(name: "Benchmark", package: "package-benchmark"),
                .product(name: "X509", package: "swift-certificates"),
                .product(name: "SwiftASN1", package: "swift-asn1"),
                .product(name: "Crypto", package: "swift-crypto"),
            ],
            path: "Benchmarks/CertificatesBenchmarks",
            plugins: [
                .plugin(name: "BenchmarkPlugin", package: "package-benchmark")
            ]
        ),
    ]
)
