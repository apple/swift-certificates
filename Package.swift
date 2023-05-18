// swift-tools-version: 5.7
//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCertificates open source project
//
// Copyright (c) 2022-2023 Apple Inc. and the SwiftCertificates project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCertificates project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import PackageDescription
import class Foundation.ProcessInfo

let package = Package(
    name: "swift-certificates",
    platforms: [
        .macOS(.v10_15),
        .iOS(.v13),
        .watchOS(.v6),
        .tvOS(.v13),
    ],
    products: [
        .library(
            name: "X509",
            targets: ["X509"]),
    ],
    targets: [
        .target(
            name: "X509",
            dependencies: [
                .product(name: "SwiftASN1", package: "swift-asn1"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
            ],
            exclude: [
                "CMakeLists.txt",
            ]),
        .testTarget(
            name: "X509Tests",
            dependencies: [
                "X509",
                .product(name: "SwiftASN1", package: "swift-asn1"),
                .product(name: "Crypto", package: "swift-crypto"),
            ], resources: [
                .copy("OCSP Test Resources/www.apple.com.root.der"),
                .copy("OCSP Test Resources/www.apple.com.intermediate.der"),
                .copy("OCSP Test Resources/www.apple.com.der"),
                .copy("OCSP Test Resources/www.apple.com.ocsp-response.der"),
                .copy("OCSP Test Resources/www.apple.com.intermediate.ocsp-response.der"),
                .copy("PEMTestRSACertificate.pem"),
                .copy("CSR Vectors/"),
            ]),
    ]
)

// If the `SWIFTCI_USE_LOCAL_DEPS` environment variable is set,
// we're building in the Swift.org CI system alongside other projects in the Swift toolchain and
// we can depend on local versions of our dependencies instead of fetching them remotely.
if ProcessInfo.processInfo.environment["SWIFTCI_USE_LOCAL_DEPS"] == nil {
    package.dependencies += [
        .package(url: "https://github.com/apple/swift-crypto.git", from: "2.5.0"),
        .package(url: "https://github.com/apple/swift-asn1.git", .upToNextMinor(from: "0.9.1")),
        .package(url: "https://github.com/apple/swift-docc-plugin", from: "1.0.0"),
    ]
} else {
    package.dependencies += [
        .package(path: "../swift-crypto"),
        .package(path: "../swift-asn1"),
    ]
}
