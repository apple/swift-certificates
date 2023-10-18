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

import _CertificateInternals

/// A collection of ``Certificate`` objects for use in a verifier.
public struct CertificateStore: Sendable, Hashable {

    @usableFromInline
    var systemTrustStore: Bool
    @usableFromInline
    var additionalTrustRoots: [DistinguishedName: [Certificate]]

    @inlinable
    public init() {
        self.init([])
    }

    @inlinable
    public init(_ certificates: some Sequence<Certificate>) {
        self.systemTrustStore = false
        self.additionalTrustRoots = Dictionary(grouping: certificates, by: \.subject)
    }

    init(systemTrustStore: Bool) {
        self.systemTrustStore = systemTrustStore
        self.additionalTrustRoots = [:]
    }

    @inlinable
    public mutating func append(_ certificate: Certificate) {
        self.append(contentsOf: CollectionOfOne(certificate))
    }

    @inlinable
    public mutating func append(contentsOf certificates: some Sequence<Certificate>) {
        for certificate in certificates {
            additionalTrustRoots[certificate.subject, default: []].append(certificate)
        }
    }

    @inlinable
    public func appending(contentsOf certificates: some Sequence<Certificate>) -> Self {
        var copy = self
        copy.append(contentsOf: certificates)
        return copy
    }

    @inlinable
    public func appending(_ certificate: Certificate) -> Self {
        var copy = self
        copy.append(certificate)
        return self
    }

    func resolve(diagnosticsCallback: ((VerificationDiagnostic) -> Void)?) async -> Resolved {
        await Resolved(self, diagnosticsCallback: diagnosticsCallback)
    }
}

extension CertificateStore {
    @usableFromInline
    struct Resolved {

        @usableFromInline
        var systemTrustRoots: [DistinguishedName: [Certificate]]

        @usableFromInline
        var additionalTrustRoots: [DistinguishedName: [Certificate]]

        init(_ store: CertificateStore, diagnosticsCallback: ((VerificationDiagnostic) -> Void)?) async {
            if store.systemTrustStore {
                do {
                    systemTrustRoots = try await CertificateStore.cachedSystemTrustRootsFuture.value
                } catch {
                    diagnosticsCallback?(.loadingTrustRootsFailed(error))
                    systemTrustRoots = [:]
                }
            } else {
                systemTrustRoots = [:]
            }

            additionalTrustRoots = store.additionalTrustRoots
        }
    }
}

extension CertificateStore.Resolved {
    @inlinable
    subscript(subject: DistinguishedName) -> [Certificate]? {
        get {
            var matchingCertificates: [Certificate] = []

            if let matchingCertificatesInSystemTrustStore = systemTrustRoots[subject] {
                matchingCertificates.appendOrReplaceIfEmpty(withContentsOf: matchingCertificatesInSystemTrustStore)
            }

            if let matchingCertificatesInAdditionTrustRoots = additionalTrustRoots[subject] {
                matchingCertificates.appendOrReplaceIfEmpty(withContentsOf: matchingCertificatesInAdditionTrustRoots)
            }

            guard matchingCertificates.isEmpty else {
                return matchingCertificates
            }
            return nil
        }
    }

    @inlinable
    func contains(_ certificate: Certificate) -> Bool {
        if systemTrustRoots[certificate.subject]?.contains(certificate) == true {
            return true
        }

        if additionalTrustRoots[certificate.subject]?.contains(certificate) == true {
            return true
        }

        return false
    }
}

extension Array {
    /// non-allocating version of `append(contentsOf:)` if `self` is empty
    @inlinable
    mutating func appendOrReplaceIfEmpty(withContentsOf newElements: [Element]) {
        if self.isEmpty {
            self = newElements
        } else {
            self.append(contentsOf: newElements)
        }
    }
}
