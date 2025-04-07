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

@usableFromInline
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
struct CertificationRequestInfo {
    @usableFromInline
    var version: CertificateSigningRequest.Version

    @usableFromInline
    var subject: DistinguishedName

    @usableFromInline
    var publicKey: Certificate.PublicKey

    @usableFromInline
    var attributes: CertificateSigningRequest.Attributes

    @inlinable
    init(
        version: CertificateSigningRequest.Version,
        subject: DistinguishedName,
        publicKey: Certificate.PublicKey,
        attributes: CertificateSigningRequest.Attributes
    ) {
        self.version = version
        self.subject = subject
        self.publicKey = publicKey
        self.attributes = attributes
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension CertificationRequestInfo: Hashable {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension CertificationRequestInfo: Sendable {}

// CertificationRequestInfo ::= SEQUENCE {
//      version       INTEGER { v1(0) } (v1,...),
//      subject       Name,
//      subjectPKInfo SubjectPublicKeyInfo{{ PKInfoAlgorithms }},
//      attributes    [0] Attributes{{ CRIAttributes }}
// }
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension CertificationRequestInfo: DERImplicitlyTaggable {
    @inlinable
    static var defaultIdentifier: ASN1Identifier {
        .sequence
    }

    @inlinable
    init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let version = try CertificateSigningRequest.Version(rawValue: Int(derEncoded: &nodes))
            let subject = try DistinguishedName.derEncoded(&nodes)
            let spki = try Certificate.PublicKey(spki: SubjectPublicKeyInfo(derEncoded: &nodes))
            let attributes = try CertificateSigningRequest.Attributes(
                DER.set(
                    of: CertificateSigningRequest.Attribute.self,
                    identifier: .init(tagWithNumber: 0, tagClass: .contextSpecific),
                    nodes: &nodes
                )
            )

            return .init(version: version, subject: subject, publicKey: spki, attributes: attributes)
        }
    }

    @inlinable
    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(self.version.rawValue)
            try coder.serialize(self.subject)
            try coder.serialize(SubjectPublicKeyInfo(self.publicKey))
            try coder.serializeSetOf(self.attributes, identifier: .init(tagWithNumber: 0, tagClass: .contextSpecific))
        }
    }
}
