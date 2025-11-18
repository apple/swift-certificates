// swift-tools-version:6.0
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
    products: [
        .library(
            name: "X509",
            targets: ["X509"]
        )
    ],
    targets: [
        .target(
            name: "X509",
            dependencies: [
                "_CertificateInternals",
                .product(name: "SwiftASN1", package: "swift-asn1"),
                .product(name: "Crypto", package: "swift-crypto"),
                .product(name: "_CryptoExtras", package: "swift-crypto"),
            ],
            exclude: [
                "CMakeLists.txt"
            ]
        ),
        .testTarget(
            name: "X509Tests",
            dependencies: [
                "X509",
                .product(name: "SwiftASN1", package: "swift-asn1"),
                .product(name: "Crypto", package: "swift-crypto"),
            ],
            resources: [
                .copy("OCSP Test Resources/www.apple.com.root.der"),
                .copy("OCSP Test Resources/www.apple.com.intermediate.der"),
                .copy("OCSP Test Resources/www.apple.com.der"),
                .copy("OCSP Test Resources/www.apple.com.ocsp-response.der"),
                .copy("OCSP Test Resources/www.apple.com.intermediate.ocsp-response.der"),
                .copy("PEMTestRSACertificate.pem"),
                .copy("CSR Vectors/"),
                .copy("ca-certificates.crt"),
            ]
        ),
        .target(
            name: "_CertificateInternals",
            exclude: [
                "CMakeLists.txt"
            ]
        ),
        .testTarget(
            name: "CertificateInternalsTests",
            dependencies: [
                "_CertificateInternals"
            ]
        ),
    ]
)

// If the `SWIFTCI_USE_LOCAL_DEPS` environment variable is set,
// we're building in the Swift.org CI system alongside other projects in the Swift toolchain and
// we can depend on local versions of our dependencies instead of fetching them remotely.
if ProcessInfo.processInfo.environment["SWIFTCI_USE_LOCAL_DEPS"] == nil {
    package.dependencies += [
        .package(url: "https://github.com/apple/swift-crypto.git", "3.12.3"..<"5.0.0"),
        .package(url: "https://github.com/apple/swift-asn1.git", from: "1.1.0"),
    ]
} else {
    package.dependencies += [
        .package(path: "../swift-crypto"),
        .package(path: "../swift-asn1"),
    ]
}

// ---    STANDARD CROSS-REPO SETTINGS DO NOT EDIT   --- //
for target in package.targets {
    switch target.type {
    case .regular, .test, .executable:
        var settings = target.swiftSettings ?? []
        // https://github.com/swiftlang/swift-evolution/blob/main/proposals/0444-member-import-visibility.md
        settings.append(.enableUpcomingFeature("MemberImportVisibility"))
        target.swiftSettings = settings
    case .macro, .plugin, .system, .binary:
        ()  // not applicable
    @unknown default:
        ()  // we don't know what to do here, do nothing
    }
}
// --- END: STANDARD CROSS-REPO SETTINGS DO NOT EDIT --- //
