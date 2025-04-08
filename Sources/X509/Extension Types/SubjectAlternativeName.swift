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

import SwiftASN1

/// Allows identities to be bound to the subject of a certificate.
///
/// The identities attested in this extension belong to the subject of the certificate.
/// Users of the certificate may validate that these names correspond to a name they are
/// expecting, depending on the context.
public struct SubjectAlternativeNames {
    @usableFromInline
    var names: [GeneralName]

    /// Construct a Subject Alternative Name extension from a sequence of
    /// ``GeneralName``s.
    ///
    /// - Parameter names: The names to bind to the subject of the certificate.
    @inlinable
    public init<Names: Sequence>(_ names: Names) where Names.Element == GeneralName {
        self.names = Array(names)
    }

    /// Construct a Subject Alternative Name extension that attests to no names.
    @inlinable
    public init() {
        self.names = []
    }

    /// Create a new ``SubjectAlternativeNames`` object
    /// by unwrapping a ``Certificate/Extension``.
    ///
    /// - Parameter ext: The ``Certificate/Extension`` to unwrap
    /// - Throws: if the ``Certificate/Extension/oid`` is not equal to
    ///     `ASN1ObjectIdentifier.X509ExtensionID.subjectAlternativeName`.
    @inlinable
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    public init(_ ext: Certificate.Extension) throws {
        guard ext.oid == .X509ExtensionID.subjectAlternativeName else {
            throw CertificateError.incorrectOIDForExtension(
                reason: "Expected \(ASN1ObjectIdentifier.X509ExtensionID.subjectAlternativeName), got \(ext.oid)"
            )
        }

        let asn1SAN = try GeneralNames(derEncoded: ext.value)
        self.names = asn1SAN.names
    }
}

extension SubjectAlternativeNames: Hashable {}

extension SubjectAlternativeNames: Sendable {}

extension SubjectAlternativeNames: CustomStringConvertible {
    public var description: String {
        self.lazy.map { String(reflecting: $0) }.joined(separator: ", ")
    }
}

extension SubjectAlternativeNames: CustomDebugStringConvertible {
    public var debugDescription: String {
        "SubjectAlternativeNames(\(String(describing: self)))"
    }
}

extension SubjectAlternativeNames: RandomAccessCollection, MutableCollection, RangeReplaceableCollection {
    @inlinable
    public var startIndex: Int {
        self.names.startIndex
    }

    @inlinable
    public var endIndex: Int {
        self.names.endIndex
    }

    @inlinable
    public subscript(position: Int) -> GeneralName {
        get {
            self.names[position]
        }
        set {
            self.names[position] = newValue
        }
    }

    @inlinable
    public mutating func replaceSubrange<NewElements>(_ subrange: Range<Int>, with newElements: NewElements)
    where NewElements: Collection, GeneralName == NewElements.Element {
        self.names.replaceSubrange(subrange, with: newElements)
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.Extension {
    /// Construct an opaque ``Certificate/Extension`` from this Subject Alternative Name extension.
    ///
    /// - Parameters:
    ///   - san: The extension to wrap
    ///   - critical: Whether this extension should have the critical bit set.
    @inlinable
    public init(_ san: SubjectAlternativeNames, critical: Bool) throws {
        let asn1Representation = GeneralNames(san.names)
        var serializer = DER.Serializer()
        try serializer.serialize(asn1Representation)
        self.init(
            oid: .X509ExtensionID.subjectAlternativeName,
            critical: critical,
            value: serializer.serializedBytes[...]
        )
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension SubjectAlternativeNames: CertificateExtensionConvertible {
    public func makeCertificateExtension() throws -> Certificate.Extension {
        return try .init(self, critical: false)
    }
}
