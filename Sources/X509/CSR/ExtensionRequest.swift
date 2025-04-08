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

import SwiftASN1

/// A CSR Attribute that encapsulates the X.509 v3 extensions that the subscriber wishes to apply.
///
/// X.509 certificates contain a number of extensions. This attribute includes the extensions that the
/// subscriber wishes the CA to embed into the certificate.
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public struct ExtensionRequest: Hashable, Sendable {
    /// The underlying extensions.
    public var extensions: Certificate.Extensions

    /// Construct an ``ExtensionRequest`` from a given set of extensions.
    ///
    /// - parameters:
    ///     - extensions: The extensions to attach to this ``ExtensionRequest``.
    @inlinable
    public init(extensions: Certificate.Extensions) {
        self.extensions = extensions
    }

    /// Unwrap a ``CertificateSigningRequest/Attribute`` that contains an ``ExtensionRequest``.
    ///
    /// - parameters:
    ///     - attribute: The attribute to unwrap
    /// - throws: If the attribute is ill-formed, or does not contain an ``ExtensionRequest``.
    @inlinable
    public init(_ attribute: CertificateSigningRequest.Attribute) throws {
        guard attribute.oid == .CSRAttributes.extensionRequest else {
            throw CertificateError.incorrectOIDForAttribute(
                reason: "Expected \(ASN1ObjectIdentifier.CSRAttributes.extensionRequest), got \(attribute.oid)"
            )
        }

        guard attribute.values.count == 1 else {
            throw CertificateError.invalidCSRAttribute(
                reason: "Invalid number of values for extension request attribute: \(attribute.values)"
            )
        }

        let extRequest = try ExtensionRequestAttribute(asn1Any: attribute.values.first!)
        self.extensions = extRequest.extensions
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension CertificateSigningRequest.Attribute {
    /// Wrap an ``ExtensionRequest`` into a ``CertificateSigningRequest/Attribute``.
    ///
    /// - parameters:
    ///     - extensionRequest: The ``ExtensionRequest`` to wrap.
    @inlinable
    public init(_ extensionRequest: ExtensionRequest) throws {
        self.init(
            oid: .CSRAttributes.extensionRequest,
            values: [try ASN1Any(erasing: ExtensionRequestAttribute(extensionRequest))]
        )
    }
}

@usableFromInline
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
struct ExtensionRequestAttribute: Hashable, Sendable, DERImplicitlyTaggable {
    @inlinable
    static var defaultIdentifier: ASN1Identifier {
        .sequence
    }

    @usableFromInline
    var extensions: Certificate.Extensions

    @inlinable
    init(_ extensionRequest: ExtensionRequest) {
        self.extensions = extensionRequest.extensions
    }

    @inlinable
    init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self.extensions = try Certificate.Extensions(
            DER.sequence(
                of: Certificate.Extension.self,
                identifier: identifier,
                rootNode: rootNode
            )
        )
    }

    @inlinable
    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.serializeSequenceOf(self.extensions, identifier: identifier)
    }
}
