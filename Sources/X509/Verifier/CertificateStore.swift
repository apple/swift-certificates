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
    enum Element: Sendable, Hashable {
        case systemTrustStore
        /// Stores the certificates, indexed by subject name.
        case customCertificates([DistinguishedName: [Certificate]])
    }

    @usableFromInline
    var _certificates: _TinyArray2<Element>

    @inlinable
    public init() {
        self.init(elements: EmptyCollection())
    }

    @inlinable
    public init(_ certificates: some Sequence<Certificate>) {
        self.init(elements: CollectionOfOne(.customCertificates(Dictionary(grouping: certificates, by: \.subject))))
    }

    @inlinable
    internal init(elements: some Sequence<Element>) {
        self._certificates = .init(elements)
    }

    @inlinable
    public mutating func insert(_ certificate: Certificate) {
        self.insert(contentsOf: CollectionOfOne(certificate))
    }

    @inlinable
    public mutating func insert(contentsOf certificates: some Sequence<Certificate>) {
        if self._certificates.isEmpty {
            self = .init(certificates)
            return
        }
        let lastIndex = self._certificates.index(before: self._certificates.endIndex)
        switch self._certificates[lastIndex] {
        case .customCertificates(var certificatesIndexBySubjectName):
            for certificate in certificates {
                certificatesIndexBySubjectName[certificate.subject, default: []].append(certificate)
            }
            self._certificates[lastIndex] = .customCertificates(certificatesIndexBySubjectName)

        case .systemTrustStore:
            self._certificates.append(.customCertificates(Dictionary(grouping: certificates, by: \.subject)))

        }
    }

    @inlinable
    public func inserting(contentsOf certificates: some Sequence<Certificate>) -> Self {
        var copy = self
        copy.insert(contentsOf: certificates)
        return copy
    }

    @inlinable
    public func inserting(_ certificate: Certificate) -> Self {
        var copy = self
        copy.insert(certificate)
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
        var _certificates: _TinyArray2<[DistinguishedName: [Certificate]]> = .init()

        init(_ store: CertificateStore, diagnosticsCallback: ((VerificationDiagnostic) -> Void)?) async {
            for element in store._certificates {
                switch element {
                case .systemTrustStore:
                    do {
                        _certificates.append(
                            try await CertificateStore.cachedSystemTrustRootsFuture.value
                        )
                    } catch {
                        diagnosticsCallback?(.loadingTrustRootsFailed(error))
                    }

                case .customCertificates(let certificatesIndexedBySubject):
                    _certificates.append(certificatesIndexedBySubject)
                }
            }
        }
    }
}

extension CertificateStore.Resolved {
    @inlinable
    subscript(subject: DistinguishedName) -> [Certificate]? {
        get {
            let matchingCertificates = _certificates.flatMap { $0[subject] ?? [] }
            guard matchingCertificates.isEmpty else {
                return matchingCertificates
            }
            return nil
        }
    }

    @inlinable
    func contains(_ certificate: Certificate) -> Bool {
        for certificatesIndexedBySubject in _certificates {
            if certificatesIndexedBySubject[certificate.subject]?.contains(certificate) == true {
                return true
            }
        }
        return false
    }
}

extension Sequence {
    /// Non-allocating version of `flatMap(_:)` if `transform` only returns a single `Array` with `count` > 0
    @inlinable
    func flatMap<ElementOfResult>(
        _ transform: (Self.Element) throws -> [ElementOfResult]
    ) rethrows -> [ElementOfResult] {
        var result = [ElementOfResult]()
        for element in self {
            let partialResult = try transform(element)
            if partialResult.isEmpty {
                continue
            }
            if result.isEmpty {
                result = partialResult
            } else {
                result.append(contentsOf: partialResult)
            }
        }
        return result
    }
}
