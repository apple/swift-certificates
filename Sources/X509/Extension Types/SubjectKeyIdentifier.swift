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

extension Certificate.Extensions {
    /// Provides a means of identifying a certificate that contains a particular public key.
    ///
    /// This extension contains a value derived from the public key of the certificate in which it appears.
    /// That value can be used to build the ``AuthorityKeyIdentifier-swift.struct/keyIdentifier`` field in
    /// any certificate issued by this certificate. This makes it possible to identify a certificate
    /// possessing the key that issued another certificate.
    public struct SubjectKeyIdentifier {
        public var keyIdentifier: ArraySlice<UInt8>

        /// Construct a Subject Key Identifier extension with a specific key identifier.
        ///
        /// - Parameter keyIdentifier: The identifier to associate with this certificate.
        @inlinable
        public init(keyIdentifier: ArraySlice<UInt8>) {
            self.keyIdentifier = keyIdentifier
        }

        /// Create a new ``Certificate/Extensions-swift.struct/SubjectKeyIdentifier-swift.struct`` object
        /// by unwrapping a ``Certificate/Extension``.
        ///
        /// - Parameter ext: The ``Certificate/Extension`` to unwrap
        /// - Throws: if the ``Certificate/Extension/oid`` is not equal to
        ///     `ASN1ObjectIdentifier.X509ExtensionID.subjectKeyIdentifier`.
        @inlinable
        public init(_ ext: Certificate.Extension) throws {
            guard ext.oid == .X509ExtensionID.subjectKeyIdentifier else {
                throw CertificateError.incorrectOIDForExtension(reason: "Expected \(ASN1.ASN1ObjectIdentifier.X509ExtensionID.subjectKeyIdentifier), got \(ext.oid)")
            }

            let asn1KeyIdentifier = try ASN1.ASN1OctetString(asn1Encoded: ext.value)
            self.keyIdentifier = asn1KeyIdentifier.bytes
        }
    }
}

extension Certificate.Extensions.SubjectKeyIdentifier: Hashable { }

extension Certificate.Extensions.SubjectKeyIdentifier: Sendable { }

extension Certificate.Extensions.SubjectKeyIdentifier: CustomStringConvertible {
    public var description: String {
        return self.keyIdentifier.lazy.map { String($0, radix: 16) }.joined(separator: ":")
    }
}

extension Certificate.Extension {
    /// Construct an opaque ``Certificate/Extension`` from this Subject Key Identifier extension.
    ///
    /// - Parameters:
    ///   - ski: The extension to wrap
    ///   - critical: Whether this extension should have the critical bit set.
    @inlinable
    public init(_ ski: Certificate.Extensions.SubjectKeyIdentifier, critical: Bool) throws {
        let asn1Representation = ASN1.ASN1OctetString(contentBytes: ski.keyIdentifier)
        var serializer = ASN1.Serializer()
        try serializer.serialize(asn1Representation)
        self.init(oid: .X509ExtensionID.subjectKeyIdentifier, critical: critical, value: serializer.serializedBytes[...])
    }
}

extension Certificate.Extensions.SubjectKeyIdentifier: CertificateExtensionConvertible {
    public func makeCertificateExtension() throws -> Certificate.Extension {
        return try .init(self, critical: false)
    }
}
