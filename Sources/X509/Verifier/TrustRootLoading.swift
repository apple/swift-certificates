//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCertificates open source project
//
// Copyright (c) 2022 Apple Inc. and the SwiftCertificates project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCertificates project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Foundation
import SwiftASN1

struct TrustRootsLoadingError: Error {
    var errors: [(path: String, error: any Error)]
}

#if os(Linux)
/// This is a list of root CA file search paths. This list contains paths as validated against several distributions.
/// If you are attempting to use swift-certificates on a platform that is not covered here and certificate validation is
/// failing, please open a pull request that adds the appropriate search path.
private let rootCAFileSearchPaths = [
    "/etc/ssl/certs/ca-certificates.crt",  // Ubuntu, Debian, Arch, Alpine,
    "/etc/pki/tls/certs/ca-bundle.crt",  // Fedora
]

extension CertificateStore {
    /// A ``CertificateStore`` that includes all root Certificate Authorities (CAs) that
    /// are installed in the systems trust store.
    ///
    /// You can add additional trust roots by ``CertificateStore/inserting(_:)-5sc2d`` them into the returned ``CertificateStore``.
    ///
    /// - Note: Access this property as early as possible. It will start loading and parsing of the certificates in the background.
    /// Accessing this property does **not** block.
    /// - Warning: This property is only available on Linux.
    /// On Darwin based platforms (e.g. macOS, iOS) use Security.framework to validate that a certificate chains up to a trusted root CA.
    public static let systemTrustRoots: CertificateStore = {
        // access `cachedTrustRootsFuture` to kick off loading on a background thread
        _ = cachedSystemTrustRootsFuture
        return CertificateStore(elements: CollectionOfOne(.trustRoots))
    }()

    static let cachedSystemTrustRootsFuture: Future<CertificateStore, any Error> = DispatchQueue.global(
        qos: .userInteractive
    ).asyncFuture {
        try Self.loadTrustRoot(at: rootCAFileSearchPaths)
    }
}
#endif

extension CertificateStore {
    @_spi(Testing)
    public static func loadTrustRoot(at searchPaths: [String]) throws -> CertificateStore {
        var fileLoadingError = TrustRootsLoadingError(errors: [])

        for path in searchPaths {
            let pemEncodedData: Data
            do {
                pemEncodedData = try Data(contentsOf: URL(fileURLWithPath: path))
            } catch {
                // this might fail if the file doesn't exists at which point we try the next path
                // but record the error if all fail
                fileLoadingError.errors.append((path, error))
                continue
            }

            return try parseTrustRoot(from: pemEncodedData)
        }

        throw fileLoadingError
    }

    static func parseTrustRoot(from pemEncodedData: Data) throws -> CertificateStore {
        let pemEncodedString = String(decoding: pemEncodedData, as: UTF8.self)
        let documents = try PEMDocument.parseMultiple(pemString: pemEncodedString)
        return CertificateStore(
            try documents.lazy.map {
                try Certificate(pemDocument: $0)
            }
        )
    }
}

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
