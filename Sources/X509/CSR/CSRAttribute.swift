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

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension CertificateSigningRequest {
    /// A general-purpose representation of a ``CertificateSigningRequest`` attribute.
    ///
    /// ``CertificateSigningRequest``s can have a number of attributes applied to them. These attributes are non-binding, but can be
    /// used to encode things like extensions that should be applied to the generated certificate, or challenge material that can
    /// be used to enable later revocation.
    ///
    /// ``Attribute``s are a general representation, keyed by an object identifier and storing a `SET` of arbitrary values.
    /// This `SET` cannot be empty. Individual ``Attribute``s can be parsed into more specific values as-needed.
    public struct Attribute {
        /// The identifier for this attribute type.
        ///
        /// Common values are stored in `ASN1ObjectIdentifier.X509ExtensionID`.
        public var oid: ASN1ObjectIdentifier

        /// The encoded bytes of the values of this attribute.
        ///
        /// This value should be decoded based on the value of ``oid``.
        public var values: [ASN1Any]

        /// Construct a new attribute from its constituent parts.
        ///
        /// - Parameters:
        ///   - oid: The identifier for this extension type.
        ///   - values: The value of this attribute, erased to `ASN1Any`
        @inlinable
        public init(oid: ASN1ObjectIdentifier, values: [ASN1Any]) {
            self.oid = oid
            self.values = values
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension CertificateSigningRequest.Attribute: Hashable {
    @inlinable
    public static func == (lhs: CertificateSigningRequest.Attribute, rhs: CertificateSigningRequest.Attribute) -> Bool {
        if lhs.oid != rhs.oid { return false }
        if lhs.values.count != rhs.values.count { return false }

        for element in lhs.values {
            if !rhs.values.contains(element) { return false }
        }

        return true
    }

    @inlinable
    public func hash(into hasher: inout Hasher) {
        hasher.combine(self.oid)

        // This achieves order-independent hashing without
        // having to sort anything. That relies on the use of XOR,
        // but any associative operation would do.
        var hash = 0
        for element in self.values {
            var newHasher = Hasher()
            element.hash(into: &newHasher)
            hash ^= newHasher.finalize()
        }

        hasher.combine(hash)
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension CertificateSigningRequest.Attribute: Sendable {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension CertificateSigningRequest.Attribute: CustomStringConvertible {
    public var description: String {
        return "Attribute(oid: \(self.oid), values: \(self.values))"
    }
}

// Attribute { ATTRIBUTE:IOSet } ::= SEQUENCE {
//      type   ATTRIBUTE.&id({IOSet}),
//      values SET SIZE(1..MAX) OF ATTRIBUTE.&Type({IOSet}{@type})
// }
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension CertificateSigningRequest.Attribute: DERImplicitlyTaggable {
    @inlinable
    public static var defaultIdentifier: ASN1Identifier {
        .sequence
    }

    @inlinable
    public init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let type = try ASN1ObjectIdentifier(derEncoded: &nodes)
            let values = try DER.set(of: ASN1Any.self, identifier: .set, nodes: &nodes)

            return CertificateSigningRequest.Attribute(oid: type, values: values)
        }
    }

    @inlinable
    public func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(self.oid)
            try coder.serializeSetOf(self.values)
        }
    }
}

extension ASN1ObjectIdentifier {
    /// Object Identifiers that identify attributes applied to CSRs.
    public enum CSRAttributes: Sendable {
        /// A request to apply specific certificate extensions.
        public static let extensionRequest: ASN1ObjectIdentifier = [1, 2, 840, 113549, 1, 9, 14]
    }
}
