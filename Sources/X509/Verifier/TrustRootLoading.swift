//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCertificates open source project
//
// Copyright (c) 2023 Apple Inc. and the SwiftCertificates project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCertificates project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

#if canImport(FoundationEssentials)
import FoundationEssentials
import Dispatch
#else
import Foundation
#endif
import SwiftASN1

/// This is a list of root CA file search paths. This list contains paths as validated against several distributions.
/// If you are attempting to use swift-certificates on a platform that is not covered here and certificate validation is
/// failing, please open a pull request that adds the appropriate search path.
private let rootCAFileSearchPaths = [
    "/etc/ssl/certs/ca-certificates.crt",  // Ubuntu, Debian, Arch, Alpine,
    "/etc/pki/tls/certs/ca-bundle.crt",  // Fedora
]

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension CertificateStore {
    /// A ``CertificateStore`` that includes all root Certificate Authorities (CAs) that
    /// are installed in the systems trust store.
    ///
    /// You can add additional trust roots by ``CertificateStore/appending(_:)`` them into the returned ``CertificateStore``.
    ///
    /// - Note: Access this property as early as possible. It will start loading and parsing of the certificates in the background.
    /// Accessing this property does **not** block.
    /// - Warning: This is only supported on Linux and will not find the system trust roots on any other platform.
    /// On Darwin based platforms (e.g. macOS, iOS) use Security.framework to validate that a certificate chains up to a trusted root CA.
    /// On other platforms (e.g. Windows) use the platform verifier.
    public static let systemTrustRoots: CertificateStore = {
        // access `cachedTrustRootsFuture` to kick off loading on a background thread
        _ = cachedSystemTrustRootsFuture
        return CertificateStore(systemTrustStore: true)
    }()

    static let cachedSystemTrustRootsFuture: Future<[DistinguishedName: [Certificate]], any Error> =
        DispatchQueue(
            label: "com.apple.swift-certificates.trust-roots",
            qos: .userInteractive
        ).asyncFuture {
            try Self.loadTrustRoots(at: rootCAFileSearchPaths)
        }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension CertificateStore {
    @_spi(Testing)
    public static func loadTrustRoots(at searchPaths: [String]) throws -> [DistinguishedName: [Certificate]] {
        var fileLoadingErrors = [(path: String, error: any Error)]()

        for path in searchPaths {
            let pemEncodedData: Data
            do {
                pemEncodedData = try Data(contentsOf: URL(fileURLWithPath: path))
            } catch {
                // this might fail if the file doesn't exists at which point we try the next path
                // but record the error if all fail
                fileLoadingErrors.append((path, error))
                continue
            }

            return try parseTrustRoot(from: pemEncodedData)
        }

        throw CertificateError.failedToLoadSystemTrustStore(
            reason: fileLoadingErrors.lazy.map {
                "(\(String(reflecting: $0.path)): \(String(reflecting: $0.error)))"
            }.joined(separator: ", ")
        )
    }

    static func parseTrustRoot(from pemEncodedData: Data) throws -> [DistinguishedName: [Certificate]] {
        let pemEncodedString = String(decoding: pemEncodedData, as: UTF8.self)
        let documents = try PEMDocument.parseMultiple(pemString: pemEncodedString)
        return Dictionary(
            grouping: try documents.lazy.map {
                try Certificate(pemDocument: $0)
            },
            by: \.subject
        )
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension DispatchQueue {
    func asyncFuture<Success: Sendable>(
        withResultOf work: @Sendable @escaping () throws -> Success
    ) -> Future<Success, any Error> {
        let promise = Promise<Success, any Error>()
        self.async {
            promise.fulfil(with: Result { try work() })
        }
        return Future(promise)
    }
}
