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

/// A collection of ``Certificate`` objects for use in a verifier.
public struct CertificateStore: Sendable, Hashable {
    /// Stores the certificates, indexed by subject name.
    @usableFromInline
    var _certificates: [DistinguishedName: [Certificate]]

    @inlinable
    public init() {
        self._certificates = [:]
    }

    @inlinable
    public init<Certificates: Sequence>(_ certificates: Certificates) where Certificates.Element == Certificate {
        self._certificates = Dictionary(grouping: certificates, by: \.subject)
    }

    @inlinable
    mutating func insert(_ certificate: Certificate) {
        self._certificates[certificate.subject, default: []].append(certificate)
    }

    @inlinable
    mutating func insert<Certificates: Sequence>(contentsOf certificates: Certificates) where Certificates.Element == Certificate {
        for certificate in certificates {
            self.insert(certificate)
        }
    }

    @inlinable
    subscript(subject: DistinguishedName) -> [Certificate]? {
        get {
            self._certificates[subject]
        }
        set {
            self._certificates[subject] = newValue
        }
    }

    @inlinable
    func contains(_ certificate: Certificate) -> Bool {
        return self[certificate.subject]?.contains(certificate) ?? false
    }
}
