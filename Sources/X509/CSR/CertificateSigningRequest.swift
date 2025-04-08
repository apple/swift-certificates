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

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import SwiftASN1

/// A representation of a PKCS#10 Certificate Signing Request (CSR).
///
/// Certificate Signing Requests are used to encapsulate information that an end-entity would like
/// encapsulated in a certificate. They are typically processed by Certificate Authorities and turned
/// into certificates signed by that CA.
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public struct CertificateSigningRequest {
    /// The version of this CSR.
    ///
    /// This project has full support for ``CertificateSigningRequest/Version-swift.struct/v1``.
    @inlinable
    public var version: CertificateSigningRequest.Version {
        self.info.version
    }

    /// The subject of this CSR.
    @inlinable
    public var subject: DistinguishedName {
        self.info.subject
    }

    /// The public key corresponding to the private key held by the subject of this CSR.
    ///
    /// This will be embedded in the resulting certificate.
    @inlinable
    public var publicKey: Certificate.PublicKey {
        self.info.publicKey
    }

    /// The bundled attributes for this CSR.
    ///
    /// Certificate Signing Requests can have arbitrary attributes attached to them. Generally these are
    /// expected to be well-known attributes that will be processed by certificate authorities.
    @inlinable
    public var attributes: CertificateSigningRequest.Attributes {
        self.info.attributes
    }

    @usableFromInline
    let info: CertificationRequestInfo

    /// The signature algorithm corresponding to the signature produced over this CSR.
    public let signatureAlgorithm: Certificate.SignatureAlgorithm

    /// The signature attached to this CSR.
    ///
    /// This signature must have been produced by the private key associated with ``publicKey``.
    public let signature: Certificate.Signature

    @usableFromInline
    let infoBytes: ArraySlice<UInt8>

    @usableFromInline
    let signatureAlgorithmBytes: ArraySlice<UInt8>

    @usableFromInline
    let signatureBytes: ArraySlice<UInt8>

    /// Construct a Certificate Signing Request from constituent parts.
    ///
    /// This API is generally not recommended for use, as it makes it very easy to construct a ``CertificateSigningRequest``
    /// whose ``signature`` is not valid. However, for testing and validation purposes it is useful to be
    /// able to do this.
    ///
    /// - Parameters:
    ///   - version: The CSR version.
    ///   - subject: The ``DistinguishedName`` of the subject of this CSR
    ///   - publicKey: The public key associated with this CSR.
    ///   - attributes: The attributes associated with this CSR
    ///   - signatureAlgorithm: The signature algorithm for the signature on this CSR.
    ///   - signature: The signature attached to this CSR.
    @inlinable
    public init(
        version: Version,
        subject: DistinguishedName,
        publicKey: Certificate.PublicKey,
        attributes: Attributes,
        signatureAlgorithm: Certificate.SignatureAlgorithm,
        signature: Certificate.Signature
    ) throws {
        self.info = CertificationRequestInfo(
            version: version,
            subject: subject,
            publicKey: publicKey,
            attributes: attributes
        )
        self.signatureAlgorithm = signatureAlgorithm
        self.signature = signature
        self.infoBytes = try DER.Serializer.serialized(element: self.info)[...]
        self.signatureAlgorithmBytes = try DER.Serializer.serialized(
            element: AlgorithmIdentifier(self.signatureAlgorithm)
        )[...]
        self.signatureBytes = try DER.Serializer.serialized(element: ASN1BitString(self.signature))[...]
    }

    /// Construct a CSR for a specific private key.
    ///
    /// This API can be used to construct a certificate signing request that can be passed to a certificate
    /// authority. It will correctly generate a signature over the request.
    ///
    /// - Parameters:
    ///   - version: The CSR version.
    ///   - subject: The ``DistinguishedName`` of the subject of this CSR
    ///   - privateKey: The private key associated with this CSR.
    ///   - attributes: The attributes associated with this CSR
    ///   - signatureAlgorithm: The signature algorithm to use for the signature on this CSR.
    @inlinable
    public init(
        version: Version,
        subject: DistinguishedName,
        privateKey: Certificate.PrivateKey,
        attributes: Attributes,
        signatureAlgorithm: Certificate.SignatureAlgorithm
    ) throws {
        self.info = CertificationRequestInfo(
            version: version,
            subject: subject,
            publicKey: privateKey.publicKey,
            attributes: attributes
        )
        self.signatureAlgorithm = signatureAlgorithm

        let infoBytes = try DER.Serializer.serialized(element: self.info)
        self.signature = try privateKey.sign(bytes: infoBytes, signatureAlgorithm: signatureAlgorithm)
        self.infoBytes = infoBytes[...]
        self.signatureAlgorithmBytes = try DER.Serializer.serialized(
            element: AlgorithmIdentifier(self.signatureAlgorithm)
        )[...]
        self.signatureBytes = try DER.Serializer.serialized(element: ASN1BitString(self.signature))[...]
    }

    /// Construct a CSR for a specific private key.
    ///
    /// This API can be used to construct a certificate signing request that can be passed to a certificate
    /// authority. It will correctly generate a signature over the request.
    ///
    /// A default signature algorithm to use for the signature of this CSR is automatically chosen based on
    /// the type of the private key.
    ///
    /// - Parameters:
    ///   - version: The CSR version.
    ///   - subject: The ``DistinguishedName`` of the subject of this CSR
    ///   - privateKey: The private key associated with this CSR.
    ///   - attributes: The attributes associated with this CSR
    @inlinable
    public init(
        version: Version,
        subject: DistinguishedName,
        privateKey: Certificate.PrivateKey,
        attributes: Attributes
    ) throws {
        try self.init(
            version: version,
            subject: subject,
            privateKey: privateKey,
            attributes: attributes,
            signatureAlgorithm: privateKey.defaultSignatureAlgorithm
        )
    }

    @inlinable
    internal init(
        info: CertificationRequestInfo,
        signatureAlgorithm: AlgorithmIdentifier,
        signature: ASN1BitString,
        infoBytes: ArraySlice<UInt8>,
        signatureAlgorithmBytes: ArraySlice<UInt8>,
        signatureBytes: ArraySlice<UInt8>
    ) throws {
        self.info = info
        self.signatureAlgorithm = Certificate.SignatureAlgorithm(algorithmIdentifier: signatureAlgorithm)
        self.signature = try Certificate.Signature(
            signatureAlgorithm: self.signatureAlgorithm,
            signatureBytes: signature
        )
        self.infoBytes = infoBytes
        self.signatureAlgorithmBytes = signatureAlgorithmBytes
        self.signatureBytes = signatureBytes
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension CertificateSigningRequest: Hashable {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension CertificateSigningRequest: Sendable {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension CertificateSigningRequest: CustomStringConvertible {
    @inlinable
    public var description: String {
        return
            "CertificateSigningRequest(version: \(self.version), subject: \(self.subject), publicKey: \(self.publicKey), attributes: \(self.attributes), signatureAlgorithm: \(self.signatureAlgorithm), signature: \(self.signature)"
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension CertificateSigningRequest: DERImplicitlyTaggable {
    @inlinable
    public static var defaultIdentifier: ASN1Identifier {
        .sequence
    }

    @inlinable
    public init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            guard let infoNode = nodes.next(),
                let signatureAlgorithmNode = nodes.next(),
                let signatureNode = nodes.next()
            else {
                throw ASN1Error.invalidASN1Object(reason: "Invalid CSR object, insufficient ASN.1 nodes")
            }
            let info = try CertificationRequestInfo(derEncoded: infoNode)
            let signatureAlgorithm = try AlgorithmIdentifier(derEncoded: signatureAlgorithmNode)
            let signature = try ASN1BitString(derEncoded: signatureNode)
            return try CertificateSigningRequest(
                info: info,
                signatureAlgorithm: signatureAlgorithm,
                signature: signature,
                infoBytes: infoNode.encodedBytes,
                signatureAlgorithmBytes: signatureAlgorithmNode.encodedBytes,
                signatureBytes: signatureNode.encodedBytes
            )
        }
    }

    @inlinable
    public func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        coder.appendConstructedNode(identifier: identifier) { coder in
            coder.serializeRawBytes(self.infoBytes)
            coder.serializeRawBytes(self.signatureAlgorithmBytes)
            coder.serializeRawBytes(self.signatureBytes)
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension CertificateSigningRequest: PEMRepresentable {
    @inlinable
    public static var defaultPEMDiscriminator: String {
        "CERTIFICATE REQUEST"
    }
}
