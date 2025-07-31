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

/// Provides information about the public key corresponding to the private key that was
/// used to sign a specific certificate.
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
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

    /// Create a new ``AuthorityKeyIdentifier`` extension value.
    ///
    /// - Parameters:
    ///   - keyIdentifier: An opaque sequence of bytes uniquely derived from the public key of the issuing CA.
    ///   - authorityCertIssuer: The name of the issuer of the issuing cert.
    ///   - authorityCertSerialNumber: The serial number of the issuing cert.
    @inlinable
    public init(
        keyIdentifier: ArraySlice<UInt8>? = nil,
        authorityCertIssuer: [GeneralName]? = nil,
        authorityCertSerialNumber: Certificate.SerialNumber? = nil
    ) {
        self.keyIdentifier = keyIdentifier
        self.authorityCertIssuer = authorityCertIssuer
        self.authorityCertSerialNumber = authorityCertSerialNumber
    }

    /// Create a new ``AuthorityKeyIdentifier`` object
    /// by unwrapping a ``Certificate/Extension``.
    ///
    /// - Parameter ext: The ``Certificate/Extension`` to unwrap
    /// - Throws: if the ``Certificate/Extension/oid`` is not equal to
    ///     `ASN1ObjectIdentifier.X509ExtensionID.authorityKeyIdentifier`.
    @inlinable
    public init(_ ext: Certificate.Extension) throws {
        guard ext.oid == .X509ExtensionID.authorityKeyIdentifier else {
            throw CertificateError.incorrectOIDForExtension(
                reason: "Expected \(ASN1ObjectIdentifier.X509ExtensionID.authorityKeyIdentifier), got \(ext.oid)"
            )
        }

        let asn1KeyIdentifier = try AuthorityKeyIdentifierValue(derEncoded: ext.value)
        self.keyIdentifier = asn1KeyIdentifier.keyIdentifier.map { $0.bytes }
        self.authorityCertIssuer = asn1KeyIdentifier.authorityCertIssuer
        self.authorityCertSerialNumber = asn1KeyIdentifier.authorityCertSerialNumber.map {
            Certificate.SerialNumber(bytes: $0)
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension AuthorityKeyIdentifier: Hashable {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension AuthorityKeyIdentifier: Sendable {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension AuthorityKeyIdentifier: CustomStringConvertible {
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

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension AuthorityKeyIdentifier: CustomDebugStringConvertible {
    public var debugDescription: String {
        "AuthorityKeyIdentifier(\(String(describing: self)))"
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.Extension {
    /// Construct an opaque ``Certificate/Extension`` from this AKI extension.
    ///
    /// - Parameters:
    ///   - aki: The extension to wrap
    ///   - critical: Whether this extension should have the critical bit set.
    @inlinable
    public init(_ aki: AuthorityKeyIdentifier, critical: Bool) throws {
        let asn1Representation = AuthorityKeyIdentifierValue(aki)
        var serializer = DER.Serializer()
        try serializer.serialize(asn1Representation)
        self.init(
            oid: .X509ExtensionID.authorityKeyIdentifier,
            critical: critical,
            value: serializer.serializedBytes[...]
        )
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension AuthorityKeyIdentifier: CertificateExtensionConvertible {
    public func makeCertificateExtension() throws -> Certificate.Extension {
        return try .init(self, critical: false)
    }
}

// MARK: ASN1 helpers
@usableFromInline
struct AuthorityKeyIdentifierValue: DERImplicitlyTaggable, Sendable {
    @inlinable
    static var defaultIdentifier: ASN1Identifier {
        .sequence
    }

    @usableFromInline
    var keyIdentifier: ASN1OctetString?

    @usableFromInline
    var authorityCertIssuer: [GeneralName]?

    @usableFromInline
    var authorityCertSerialNumber: ArraySlice<UInt8>?

    @inlinable
    init(
        keyIdentifier: ASN1OctetString?,
        authorityCertIssuer: [GeneralName]?,
        authorityCertSerialNumber: ArraySlice<UInt8>?
    ) {
        self.keyIdentifier = keyIdentifier
        self.authorityCertIssuer = authorityCertIssuer
        self.authorityCertSerialNumber = authorityCertSerialNumber
    }

    @inlinable
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    init(_ aki: AuthorityKeyIdentifier) {
        self.keyIdentifier = aki.keyIdentifier.map { ASN1OctetString(contentBytes: $0) }
        self.authorityCertIssuer = aki.authorityCertIssuer
        self.authorityCertSerialNumber = aki.authorityCertSerialNumber.map { $0.bytes }
    }

    @inlinable
    init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let keyIdentifier: ASN1OctetString? = try DER.optionalImplicitlyTagged(
                &nodes,
                tag: .init(tagWithNumber: 0, tagClass: .contextSpecific)
            )
            let authorityCertIssuer: GeneralNames? = try DER.optionalImplicitlyTagged(
                &nodes,
                tag: .init(tagWithNumber: 1, tagClass: .contextSpecific)
            )
            let authorityCertSerialNumber: ArraySlice<UInt8>? = try DER.optionalImplicitlyTagged(
                &nodes,
                tag: .init(tagWithNumber: 2, tagClass: .contextSpecific)
            )

            return AuthorityKeyIdentifierValue(
                keyIdentifier: keyIdentifier,
                authorityCertIssuer: authorityCertIssuer?.names,
                authorityCertSerialNumber: authorityCertSerialNumber
            )
        }
    }

    @inlinable
    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serializeOptionalImplicitlyTagged(
                self.keyIdentifier,
                withIdentifier: .init(tagWithNumber: 0, tagClass: .contextSpecific)
            )
            try coder.serializeOptionalImplicitlyTagged(
                self.authorityCertIssuer.map { GeneralNames($0) },
                withIdentifier: .init(tagWithNumber: 1, tagClass: .contextSpecific)
            )
            try coder.serializeOptionalImplicitlyTagged(
                self.authorityCertSerialNumber,
                withIdentifier: .init(tagWithNumber: 2, tagClass: .contextSpecific)
            )
        }
    }
}
