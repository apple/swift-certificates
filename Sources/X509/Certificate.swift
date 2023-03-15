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

import Foundation
import SwiftASN1

/// A representation of an X.509 certificate object.
///
/// X.509 certificates are a commonly-used identity format to cryptographically
/// attest to the identity of an actor in a system. They form part of the X.509
/// standard created by the ITU-T for defining a public key infrastructure (PKI).
/// X.509-style PKIs are commonly used in cases where it is necessary to delegate
/// the authority to attest to an actor's identity to a small number of trusted
/// parties (called Certificate Authorities).
///
/// The most common usage of X.509 certificates today is as part of the WebPKI,
/// where they are used to secure TLS connections to websites. X.509 certificates
/// are also used in a wide range of other TLS-based communications, as well as
/// in code signing infrastructure.
///
/// This type is intended to be useful for users both to create new ``Certificate``
/// objects, and to handle existing ones that they have received. In particular,
/// users need to be able to create ``Certificate`` objects directly (in the case
/// of self-signed certificates) and from Certificate Signing Requests, as well
/// as from their serialized DER representation.
///
/// ### Structure
///
/// ``Certificate`` is a representation of an X.509v3 certificate, as defined in
/// [RFC 5280](https://datatracker.ietf.org/doc/html/rfc5280.html). It provides
/// support for the full range of features in RFC 5280.
///
/// The type has two main goals. The first is that it aims to be able to store and
/// represent a parsed X.509 certificate issued by an arbitrary system in full
/// fidelity. As the X.509 standards have evolved over time, a number of certificates
/// exist in circulation that do not meet the current best practice standards. It is
/// important for this type to be able to represent these older certificates.
///
/// The second goal is to make it possible for users to easily construct _new_
/// ``Certificate`` objects from whole cloth. To achieve this there are a number of
/// higher-level APIs that can be used to construct the constituent parts of the
/// certificate. These are discussed at length in their relevant API documentation
/// (e.g. ``Certificate/Extensions-swift.struct`` & ``DistinguishedName``).
///
/// Both of these goals encourage this type to be immutable. A ``Certificate`` represents
/// a specific assertion of identity. Its ``Certificate/signature-swift.property`` is signed
/// across the rest of the data. Allowing users to change this data makes it easy to accidentally modify
/// a ``Certificate`` in one part of your code and not realise that the signature has inevitably
/// been invalidated.
public struct Certificate {
    /// The X.509 version of this certificate.
    ///
    /// This should be set to ``Certificate/Version-swift.struct/v3`` in
    /// almost all cases.
    @inlinable
    public var version: Version {
        self.tbsCertificate.version
    }

    /// The serial number of this certificate.
    ///
    /// This should be a unique, large, random number.
    @inlinable
    public var serialNumber: SerialNumber {
        self.tbsCertificate.serialNumber
    }

    /// The public key associated with this certificate.
    ///
    /// When validating that a certificate belongs to a service, that service should be able to
    /// produce cryptographic proof that it holds the private key associated with this public key.
    @inlinable
    public var publicKey: PublicKey {
        self.tbsCertificate.publicKey
    }

    /// The date before which this certificate is not valid.
    @inlinable
    public var notValidBefore: Date {
        // TODO: Do we need to do this conversion every time? Hard to be sure.
        // Need to work out how costly it is.
        Date(self.tbsCertificate.validity.notBefore)!
    }

    /// The date after which this certificate is not valid.
    @inlinable
    public var notValidAfter: Date {
        Date(self.tbsCertificate.validity.notAfter)!
    }

    /// The ``DistinguishedName`` of the issuer of this certificate.
    @inlinable
    public var issuer: DistinguishedName {
        self.tbsCertificate.issuer
    }

    /// The ``DistinguishedName`` of the subject of this certificate.
    @inlinable
    public var subject: DistinguishedName {
        self.tbsCertificate.subject
    }

    /// The extensions on this certificate.
    @inlinable
    public var extensions: Extensions {
        self.tbsCertificate.extensions
    }

    @usableFromInline
    internal let tbsCertificate: TBSCertificate

    /// The bytes of the `TBSCertificate` structure.
    ///
    /// The ``signature-swift.property`` is calculated over these bytes.
    public let tbsCertificateBytes: ArraySlice<UInt8>

    /// The signature attached to this certificate.
    ///
    /// This signature is computed over ``tbsCertificateBytes``.
    public let signature: Signature

    /// The signature algorithm used to produce ``signature-swift.property``.
    public let signatureAlgorithm: SignatureAlgorithm

    /// The bytes of the ``Signature``.
    ///
    /// These are preserved to ensure that we reserialize exactly what we deserialized, regardless
    /// of any canonicalisation we might do.
    @usableFromInline
    internal let signatureBytes: ArraySlice<UInt8>

    /// The bytes of the ``signatureAlgorithm-swift.property``.
    ///
    /// These are preserved to ensure that we reserialize exactly what we deserialized, regardless of
    /// any canonicalisation we might do.
    @usableFromInline
    internal let signatureAlgorithmBytes: ArraySlice<UInt8>

    /// Construct a certificate from constituent parts.
    ///
    /// This API is generally not recommended for use, as it makes it very easy to construct a ``Certificate``
    /// whose ``signature-swift.property`` is not valid. However, for testing and validation purposes it is useful to be
    /// able to do this.
    ///
    /// - Parameters:
    ///   - version: The X.509 specification version for this certificate.
    ///   - serialNumber: The serial number of this certificate.
    ///   - publicKey: The public key associated with this certificate.
    ///   - notValidBefore: The date before which this certificate is not valid.
    ///   - notValidAfter: The date after which this certificate is not valid.
    ///   - issuer: The ``DistinguishedName`` of the issuer of this certificate.
    ///   - subject: The ``DistinguishedName`` of the subject of this certificate.
    ///   - signatureAlgorithm: The signature algorithm used to produce `signature`
    ///   - extensions: The extensions on this certificate.
    ///   - signature: The signature attached to this certificate.
    @inlinable
    public init(
        version: Version,
        serialNumber: SerialNumber,
        publicKey: PublicKey,
        notValidBefore: Date,
        notValidAfter: Date,
        issuer: DistinguishedName,
        subject: DistinguishedName,
        signatureAlgorithm: SignatureAlgorithm,
        extensions: Extensions,
        signature: Signature
    ) throws {
        self.tbsCertificate = TBSCertificate(
            version: version,
            serialNumber: serialNumber,
            signature: signatureAlgorithm,
            issuer: issuer,
            validity: try Validity(notBefore: .makeTime(from: notValidBefore), notAfter: .makeTime(from: notValidAfter)),
            subject: subject,
            publicKey: publicKey,
            extensions: extensions
        )
        // TODO: enforce that signature algorithm and signature have the same algorithm.
        self.signatureAlgorithm = signatureAlgorithm
        self.signature = signature
        self.tbsCertificateBytes = try DER.Serializer.serialized(element: self.tbsCertificate)[...]
        self.signatureAlgorithmBytes = try DER.Serializer.serialized(element: AlgorithmIdentifier(self.signatureAlgorithm))[...]
        self.signatureBytes = try DER.Serializer.serialized(element: ASN1BitString(self.signature))[...]
    }

    /// Construct a certificate from constituent parts, signed by an issuer key.
    ///
    /// This API can be used to construct a ``Certificate`` directly, without an intermediary
    /// Certificate Signing Request. The ``signature-swift.property`` for this certificate will be produced
    /// automatically, using `issuerPrivateKey`.
    ///
    /// This API can be used to construct a self-signed key by passing the private key for `publicKey` as the
    /// `issuerPrivateKey` argument.
    ///
    /// - Parameters:
    ///   - version: The X.509 specification version for this certificate.
    ///   - serialNumber: The serial number of this certificate.
    ///   - publicKey: The public key associated with this certificate.
    ///   - notValidBefore: The date before which this certificate is not valid.
    ///   - notValidAfter: The date after which this certificate is not valid.
    ///   - issuer: The ``DistinguishedName`` of the issuer of this certificate.
    ///   - subject: The ``DistinguishedName`` of the subject of this certificate.
    ///   - signatureAlgorithm: The signature algorithm that will be used to produce `signature`. Must be compatible with the private key type.
    ///   - extensions: The extensions on this certificate.
    ///   - issuerPrivateKey: The private key to use to sign this certificate.
    @inlinable
    public init(
        version: Version,
        serialNumber: SerialNumber,
        publicKey: PublicKey,
        notValidBefore: Date,
        notValidAfter: Date,
        issuer: DistinguishedName,
        subject: DistinguishedName,
        signatureAlgorithm: SignatureAlgorithm,
        extensions: Extensions,
        issuerPrivateKey: PrivateKey
    ) throws {
        self.tbsCertificate = TBSCertificate(
            version: version,
            serialNumber: serialNumber,
            signature: signatureAlgorithm,
            issuer: issuer,
            validity: try Validity(notBefore: .makeTime(from: notValidBefore), notAfter: .makeTime(from: notValidAfter)),
            subject: subject,
            publicKey: publicKey,
            extensions: extensions
        )
        // TODO: validate that signature algorithm is comoatible with the signature.
        self.signatureAlgorithm = signatureAlgorithm

        let tbsCertificateBytes = try DER.Serializer.serialized(element: self.tbsCertificate)[...]
        self.signature = try issuerPrivateKey.sign(bytes: tbsCertificateBytes, signatureAlgorithm: signatureAlgorithm)
        self.tbsCertificateBytes = tbsCertificateBytes
        self.signatureAlgorithmBytes = try DER.Serializer.serialized(element: AlgorithmIdentifier(self.signatureAlgorithm))[...]
        self.signatureBytes = try DER.Serializer.serialized(element: ASN1BitString(self.signature))[...]
    }

    @inlinable
    init(
        tbsCertificate: TBSCertificate,
        signatureAlgorithm: AlgorithmIdentifier,
        signature: ASN1BitString,
        tbsCertificateBytes: ArraySlice<UInt8>,
        signatureAlgorithmBytes: ArraySlice<UInt8>,
        signatureBytes: ArraySlice<UInt8>
    ) throws {
        self.tbsCertificate = tbsCertificate
        self.signatureAlgorithm = SignatureAlgorithm(algorithmIdentifier: signatureAlgorithm)
        self.signature = try Signature(signatureAlgorithm: self.signatureAlgorithm, signatureBytes: signature)
        self.tbsCertificateBytes = tbsCertificateBytes
        self.signatureAlgorithmBytes = signatureAlgorithmBytes
        self.signatureBytes = signatureBytes
    }
}

extension Certificate: Hashable { }

extension Certificate: Sendable { }

extension Certificate: CustomStringConvertible {
    public var description: String {
        return "\(self.subject) - TODO"
    }
}

extension Certificate: DERImplicitlyTaggable {
    @inlinable
    public static var defaultIdentifier: ASN1Identifier {
        .sequence
    }

    @inlinable
    public init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            guard let tbsCertificateNode = nodes.next(),
                  let signatureAlgorithmNode = nodes.next(),
                  let signatureNode = nodes.next()
            else {
                throw ASN1Error.invalidASN1Object(reason: "Invalid certificate object, insufficient ASN.1 nodes")
            }
            let tbsCertificate = try TBSCertificate(derEncoded: tbsCertificateNode)
            let signatureAlgorithm = try AlgorithmIdentifier(derEncoded: signatureAlgorithmNode)
            let signature = try ASN1BitString(derEncoded: signatureNode)
            return try Certificate(
                tbsCertificate: tbsCertificate,
                signatureAlgorithm: signatureAlgorithm,
                signature: signature,
                tbsCertificateBytes: tbsCertificateNode.encodedBytes,
                signatureAlgorithmBytes: signatureAlgorithmNode.encodedBytes,
                signatureBytes: signatureNode.encodedBytes
            )
        }
    }

    @inlinable
    public func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        coder.appendConstructedNode(identifier: identifier) { coder in
            coder.serializeRawBytes(self.tbsCertificateBytes)
            coder.serializeRawBytes(self.signatureAlgorithmBytes)
            coder.serializeRawBytes(self.signatureBytes)
        }
    }
}

extension DER.Serializer {
    @inlinable
    static func serialized<Element: DERSerializable>(element: Element) throws -> [UInt8] {
        var serializer = DER.Serializer()
        try serializer.serialize(element)
        return serializer.serializedBytes
    }

}
