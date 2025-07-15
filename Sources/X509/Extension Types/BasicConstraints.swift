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

/// Identifies whether the subject of the certificate is a CA and the
/// maximum verification depth of valid certificate paths that include this
/// certificate.
public enum BasicConstraints {
    /// This entity is a certificate authority.
    ///
    /// If `maxPathLength` is non-nil, this length is the maximum number of intermediate
    /// certificates that may follow this one in a valid certification path. Note that this
    /// excludes the leaf, so a valid (and common) `maxPathLength` is `0`.
    case isCertificateAuthority(maxPathLength: Int?)

    /// This entity is not a certificate authority, and may not be a valid issuer of any
    /// certificate.
    case notCertificateAuthority

    /// Create a new ``BasicConstraints`` object
    /// by unwrapping a ``Certificate/Extension``.
    ///
    /// - Parameter ext: The ``Certificate/Extension`` to unwrap
    /// - Throws: if the ``Certificate/Extension/oid`` is not equal to
    ///     `ASN1ObjectIdentifier.X509ExtensionID.basicConstraints`.
    @inlinable
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    public init(_ ext: Certificate.Extension) throws {
        guard ext.oid == .X509ExtensionID.basicConstraints else {
            throw CertificateError.incorrectOIDForExtension(
                reason: "Expected \(ASN1ObjectIdentifier.X509ExtensionID.basicConstraints), got \(ext.oid)"
            )
        }

        let basicConstraintsValue = try BasicConstraintsValue(derEncoded: ext.value)
        if basicConstraintsValue.isCA {
            self = .isCertificateAuthority(maxPathLength: basicConstraintsValue.pathLenConstraint)
        } else {
            self = .notCertificateAuthority
        }
    }
}

extension BasicConstraints: Hashable {}

extension BasicConstraints: Sendable {}

extension BasicConstraints: CustomStringConvertible {
    public var description: String {
        switch self {
        case .isCertificateAuthority(maxPathLength: nil):
            return "CA=TRUE"
        case .isCertificateAuthority(maxPathLength: .some(let maxLen)):
            return "CA=TRUE, maxPathLength=\(maxLen)"
        case .notCertificateAuthority:
            return "CA=FALSE"
        }
    }
}

extension BasicConstraints: CustomDebugStringConvertible {
    public var debugDescription: String {
        "BasicConstraints(\(String(describing: self)))"
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.Extension {
    /// Construct an opaque ``Certificate/Extension`` from this Basic Constraints extension.
    ///
    /// - Parameters:
    ///   - basicConstraints: The extension to wrap
    ///   - critical: Whether this extension should have the critical bit set.
    @inlinable
    public init(_ basicConstraints: BasicConstraints, critical: Bool) throws {
        let asn1Representation = BasicConstraintsValue(basicConstraints)
        var serializer = DER.Serializer()
        try serializer.serialize(asn1Representation)
        self.init(oid: .X509ExtensionID.basicConstraints, critical: critical, value: serializer.serializedBytes[...])
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension BasicConstraints: CertificateExtensionConvertible {
    public func makeCertificateExtension() throws -> Certificate.Extension {
        return try .init(self, critical: false)
    }
}

// MARK: ASN1 helpers
@usableFromInline
struct BasicConstraintsValue: DERImplicitlyTaggable, Sendable {
    @inlinable
    static var defaultIdentifier: ASN1Identifier {
        .sequence
    }

    @usableFromInline
    var isCA: Bool

    @usableFromInline
    var pathLenConstraint: Int?

    @inlinable
    init(isCA: Bool, pathLenConstraint: Int?) throws {
        self.isCA = isCA
        self.pathLenConstraint = pathLenConstraint

        // CA's must not assert the path len constraint field unless isCA is true.
        guard pathLenConstraint == nil || isCA else {
            throw ASN1Error.invalidASN1Object(
                reason:
                    "Invalid combination of isCA (\(isCA)) and path length constraint (\(String(describing: pathLenConstraint))"
            )
        }
    }

    @inlinable
    init(_ ext: BasicConstraints) {
        switch ext {
        case .isCertificateAuthority(maxPathLength: let maxPathLen):
            self.isCA = true
            self.pathLenConstraint = maxPathLen
        case .notCertificateAuthority:
            self.isCA = false
            self.pathLenConstraint = nil
        }
    }

    @inlinable
    init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let isCA: Bool = try DER.decodeDefault(&nodes, defaultValue: false)
            let pathLenConstraint: Int? = try DER.optionalImplicitlyTagged(&nodes)
            return try BasicConstraintsValue(isCA: isCA, pathLenConstraint: pathLenConstraint)
        }
    }

    @inlinable
    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            if self.isCA != false {
                try coder.serialize(self.isCA)
            }
            try coder.serializeOptionalImplicitlyTagged(self.pathLenConstraint)
        }
    }
}
