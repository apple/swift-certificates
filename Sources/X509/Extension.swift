//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCertificate open source project
//
// Copyright (c) 2022 Apple Inc. and the SwiftCertificate project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.md for the list of SwiftCertificate project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import SwiftASN1

extension Certificate {
    /// A general-purpose representation of a specific X.509 extension.
    ///
    /// X.509 extensions are a general representation, with three properties: an identifier, a critical flag, and the encoded value.
    /// The specific data contained in the encoded value is determined by the value of the identifier stored in ``oid``.
    ///
    /// This value enables ``Certificate/Extensions-swift.struct`` to store the value of all extensions in a certificate, even ones
    /// it does not understand. A number of extensions have built-in support, and can be decoded directly from an ``Extension``
    /// value. These are:
    ///
    /// - ``Certificate/Extensions-swift.struct/AuthorityInformationAccess-swift.struct``
    /// - ``Certificate/Extensions-swift.struct/AuthorityKeyIdentifier-swift.struct``
    /// - ``Certificate/Extensions-swift.struct/BasicConstraints-swift.enum``
    /// - ``Certificate/Extensions-swift.struct/ExtendedKeyUsage-swift.struct``
    /// - ``Certificate/Extensions-swift.struct/KeyUsage-swift.struct``
    /// - ``Certificate/Extensions-swift.struct/NameConstraints-swift.struct``
    /// - ``Certificate/Extensions-swift.struct/SubjectAlternativeNames-swift.struct``
    /// - ``Certificate/Extensions-swift.struct/SubjectKeyIdentifier-swift.struct``
    ///
    /// Users can write their own types by using a similar approach to these types, when it is necessary to add support for
    /// different X.509 extension.
    public struct Extension {
        /// The identifier for this extension type.
        ///
        /// Common values are stored in `ASN1.ASN1ObjectIdentifier.X509ExtensionID`.
        public var oid: ASN1.ASN1ObjectIdentifier

        /// Whether this extension must be processed in order to trust the certificate.
        ///
        /// If the code processing this ``Certificate`` does not understand this extension, the certificate
        /// must not be trusted.
        public var critical: Bool

        /// The encoded bytes of the value of this extension.
        ///
        /// This value should be decoded based on the value of ``oid``.
        public var value: ArraySlice<UInt8>

        /// Construct a new extension from its constituent parts.
        ///
        /// - Parameters:
        ///   - oid: The identifier for this extension type.
        ///   - critical: Whether this extension must be processed in order to trust the certificate.
        ///   - value: The encoded bytes of the value of this extension.
        @inlinable
        public init(oid: ASN1.ASN1ObjectIdentifier, critical: Bool, value: ArraySlice<UInt8>) {
            self.oid = oid
            self.critical = critical
            self.value = value
        }
    }
}

extension Certificate.Extension: Hashable { }

extension Certificate.Extension: Sendable { }

extension Certificate.Extension: CustomStringConvertible {
    public var description: String {
        return "TODO"
    }
}

extension Certificate.Extension: ASN1ImplicitlyTaggable {
    @inlinable
    public static var defaultIdentifier: ASN1.ASN1Identifier {
        .sequence
    }

    @inlinable
    public init(asn1Encoded rootNode: ASN1.ASN1Node, withIdentifier identifier: ASN1.ASN1Identifier) throws {
        self = try ASN1.sequence(rootNode, identifier: identifier) { nodes in
            let extensionID = try ASN1.ASN1ObjectIdentifier(asn1Encoded: &nodes)
            let critical = try ASN1.decodeDefault(&nodes, defaultValue: false)
            let value = try ASN1.ASN1OctetString(asn1Encoded: &nodes)

            return Certificate.Extension(oid: extensionID, critical: critical, value: value.bytes)
        }
    }

    @inlinable
    public func serialize(into coder: inout ASN1.Serializer, withIdentifier identifier: ASN1.ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(self.oid)

            if self.critical {
                try coder.serialize(self.critical)
            }

            try coder.serialize(ASN1.ASN1OctetString(contentBytes: self.value))
        }
    }
}

extension Certificate.Extension: CertificateExtensionConvertible {
    public func makeCertificateExtension() -> Certificate.Extension {
        self
    }
}
