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
    /// Provides information about the public key corresponding to the private key that was
    /// used to sign a specific certificate.
    public struct AuthorityKeyIdentifier {
        /// An opaque sequence of bytes uniquely derived from the public key of the issuing
        /// CA.
        ///
        /// This is commonly a hash of the subject public key info from the issuing certificate.
        public var keyIdentifier: ArraySlice<UInt8>?

        /// The name of the issuer of the issuing cert.
        public var authorityCertIssuer: [GeneralName]?

        /// The serial number of the issuing cert.
        public var authorityCertSerialNumber: Certificate.SerialNumber?

        /// Create a new ``Certificate/Extensions-swift.struct/AuthorityKeyIdentifier-swift.struct`` extension value.
        ///
        /// - Parameters:
        ///   - keyIdentifier: An opaque sequence of bytes uniquely derived from the public key of the issuing CA.
        ///   - authorityCertIssuer: The name of the issuer of the issuing cert.
        ///   - authorityCertSerialNumber: The serial number of the issuing cert.
        @inlinable
        public init(keyIdentifier: ArraySlice<UInt8>? = nil, authorityCertIssuer: [GeneralName]? = nil, authorityCertSerialNumber: Certificate.SerialNumber? = nil) {
            self.keyIdentifier = keyIdentifier
            self.authorityCertIssuer = authorityCertIssuer
            self.authorityCertSerialNumber = authorityCertSerialNumber
        }

        /// Create a new ``Certificate/Extensions-swift.struct/AuthorityKeyIdentifier-swift.struct`` object
        /// by unwrapping a ``Certificate/Extension``.
        ///
        /// - Parameter ext: The ``Certificate/Extension`` to unwrap
        /// - Throws: if the ``Certificate/Extension/oid`` is not equal to
        ///     `ASN1ObjectIdentifier.X509ExtensionID.authorityKeyIdentifier`.
        @inlinable
        public init(_ ext: Certificate.Extension) throws {
            guard ext.oid == .X509ExtensionID.authorityKeyIdentifier else {
                throw CertificateError.incorrectOIDForExtension(reason: "Expected \(ASN1.ASN1ObjectIdentifier.X509ExtensionID.authorityKeyIdentifier), got \(ext.oid)")
            }

            let asn1KeyIdentifier = try AuthorityKeyIdentifierValue(asn1Encoded: ext.value)
            self.keyIdentifier = asn1KeyIdentifier.keyIdentifier.map { $0.bytes }
            self.authorityCertIssuer = asn1KeyIdentifier.authorityCertIssuer
            self.authorityCertSerialNumber = asn1KeyIdentifier.authorityCertSerialNumber.map { Certificate.SerialNumber(bytes: $0) }
        }
    }
}

extension Certificate.Extensions.AuthorityKeyIdentifier: Hashable { }

extension Certificate.Extensions.AuthorityKeyIdentifier: Sendable { }

extension Certificate.Extensions.AuthorityKeyIdentifier: CustomStringConvertible {
    public var description: String {
        var elements: [String] = []

        if let keyId = self.keyIdentifier {
            elements.append("keyID: \(keyId.map { String($0, radix: 16) }.joined(separator: ":"))")
        }

        if let issuer = self.authorityCertIssuer {
            elements.append("issuer: \(issuer)")
        }

        if let serial = self.authorityCertSerialNumber {
            elements.append("issuerSerial: \(serial)")
        }

        return elements.joined(separator: ", ")
    }
}

extension Certificate.Extension {
    /// Construct an opaque ``Certificate/Extension`` from this AKI extension.
    ///
    /// - Parameters:
    ///   - aki: The extension to wrap
    ///   - critical: Whether this extension should have the critical bit set.
    @inlinable
    public init(_ aki: Certificate.Extensions.AuthorityKeyIdentifier, critical: Bool) throws {
        let asn1Representation = AuthorityKeyIdentifierValue(aki)
        var serializer = ASN1.Serializer()
        try serializer.serialize(asn1Representation)
        self.init(oid: .X509ExtensionID.authorityKeyIdentifier, critical: critical, value: serializer.serializedBytes[...])
    }
}

extension Certificate.Extensions.AuthorityKeyIdentifier: CertificateExtensionConvertible {
    public func makeCertificateExtension() throws -> Certificate.Extension {
        return try .init(self, critical: false)
    }
}

// MARK: ASN1 helpers
@usableFromInline
struct AuthorityKeyIdentifierValue: ASN1ImplicitlyTaggable {
    @inlinable
    static var defaultIdentifier: ASN1.ASN1Identifier {
        .sequence
    }

    @usableFromInline
    var keyIdentifier: ASN1.ASN1OctetString?

    @usableFromInline
    var authorityCertIssuer: [GeneralName]?

    @usableFromInline
    var authorityCertSerialNumber: ArraySlice<UInt8>?

    @inlinable
    init(keyIdentifier: ASN1.ASN1OctetString?, authorityCertIssuer: [GeneralName]?, authorityCertSerialNumber: ArraySlice<UInt8>?) {
        self.keyIdentifier = keyIdentifier
        self.authorityCertIssuer = authorityCertIssuer
        self.authorityCertSerialNumber = authorityCertSerialNumber
    }

    @inlinable
    init(_ aki: Certificate.Extensions.AuthorityKeyIdentifier) {
        self.keyIdentifier = aki.keyIdentifier.map { ASN1.ASN1OctetString(contentBytes: $0) }
        self.authorityCertIssuer = aki.authorityCertIssuer
        self.authorityCertSerialNumber = aki.authorityCertSerialNumber.map { $0.bytes }
    }

    @inlinable
    init(asn1Encoded rootNode: ASN1.ASN1Node, withIdentifier identifier: ASN1.ASN1Identifier) throws {
        self = try ASN1.sequence(rootNode, identifier: identifier) { nodes in
            let keyIdentifier: ASN1.ASN1OctetString? = try ASN1.optionalImplicitlyTagged(&nodes, tag: .init(tagWithNumber: 0, tagClass: .contextSpecific, constructed: false))
            let authorityCertIssuer: GeneralNames? = try ASN1.optionalImplicitlyTagged(&nodes, tag: .init(tagWithNumber: 1, tagClass: .contextSpecific, constructed: true))
            let authorityCertSerialNumber: ArraySlice<UInt8>? = try ASN1.optionalImplicitlyTagged(&nodes, tag: .init(tagWithNumber: 2, tagClass: .contextSpecific, constructed: false))

            return AuthorityKeyIdentifierValue(
                keyIdentifier: keyIdentifier, authorityCertIssuer: authorityCertIssuer?.names, authorityCertSerialNumber: authorityCertSerialNumber
            )
        }
    }

    @inlinable
    func serialize(into coder: inout ASN1.Serializer, withIdentifier identifier: ASN1.ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serializeOptionalImplicitlyTagged(self.keyIdentifier, withIdentifier: .init(tagWithNumber: 0, tagClass: .contextSpecific, constructed: false))
            try coder.serializeOptionalImplicitlyTagged(
                self.authorityCertIssuer.map { GeneralNames($0) }, withIdentifier: .init(tagWithNumber: 1, tagClass: .contextSpecific, constructed: true)
            )
            try coder.serializeOptionalImplicitlyTagged(self.authorityCertSerialNumber, withIdentifier: .init(tagWithNumber: 2, tagClass: .contextSpecific, constructed: false))
        }
    }
}
