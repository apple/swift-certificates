//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCertificates open source project
//
// Copyright (c) 2026 Apple Inc. and the SwiftCertificates project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCertificates project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import SwiftASN1

/// ``AuthenticatedData`` is defined in ASN.1 as:
/// ```
/// AuthenticatedData ::= SEQUENCE {
///   version CMSVersion,
///   originatorInfo [0] IMPLICIT OriginatorInfo OPTIONAL,
///   recipientInfos RecipientInfos,
///   macAlgorithm MessageAuthenticationCodeAlgorithm,
///   digestAlgorithm [1] IMPLICIT DigestAlgorithmIdentifier OPTIONAL,
///   encapContentInfo EncapsulatedContentInfo,
///   authAttrs [2] IMPLICIT AuthAttributes OPTIONAL,
///   mac OCTET STRING,
///   unauthAttrs [3] IMPLICIT UnauthAttributes OPTIONAL }
///
/// RecipientInfos ::= SET OF RecipientInfo
/// MessageAuthenticationCodeAlgorithm ::= AlgorithmIdentifier
/// DigestAlgorithmIdentifier ::= AlgorithmIdentifier
/// AuthAttributes ::= SET SIZE (1..MAX) OF Attribute
/// UnauthAttributes ::= SET SIZE (1..MAX) OF Attribute
/// ```
@usableFromInline
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
struct CMSAuthenticatedData: DERImplicitlyTaggable, BERImplicitlyTaggable, Hashable, Sendable {
    @usableFromInline
    static let originatorInfoIdentifier = ASN1Identifier(tagWithNumber: 0, tagClass: .contextSpecific)

    @usableFromInline
    static let digestAlgorithmIdentifier = ASN1Identifier(tagWithNumber: 1, tagClass: .contextSpecific)

    @usableFromInline
    static let authAttrsIdentifier = ASN1Identifier(tagWithNumber: 2, tagClass: .contextSpecific)

    @usableFromInline
    static let unauthAttrsIdentifier = ASN1Identifier(tagWithNumber: 3, tagClass: .contextSpecific)

    @inlinable
    static var defaultIdentifier: ASN1Identifier {
        .sequence
    }

    @usableFromInline var version: CMSVersion
    @usableFromInline var originatorInfo: CMSOriginatorInfo?
    @usableFromInline var recipientInfos: [CMSRecipientInfo]
    @usableFromInline var macAlgorithm: AlgorithmIdentifier
    @usableFromInline var digestAlgorithm: AlgorithmIdentifier?
    @usableFromInline var encapContentInfo: CMSEncapsulatedContentInfo
    @usableFromInline var authAttrs: [CMSAttribute]?
    @usableFromInline var mac: ASN1OctetString
    @usableFromInline var unauthAttrs: [CMSAttribute]?

    @inlinable
    init(
        version: CMSVersion,
        originatorInfo: CMSOriginatorInfo?,
        recipientInfos: [CMSRecipientInfo],
        macAlgorithm: AlgorithmIdentifier,
        digestAlgorithm: AlgorithmIdentifier?,
        encapContentInfo: CMSEncapsulatedContentInfo,
        authAttrs: [CMSAttribute]?,
        mac: ASN1OctetString,
        unauthAttrs: [CMSAttribute]?
    ) {
        self.version = version
        self.originatorInfo = originatorInfo
        self.recipientInfos = recipientInfos
        self.macAlgorithm = macAlgorithm
        self.digestAlgorithm = digestAlgorithm
        self.encapContentInfo = encapContentInfo
        self.authAttrs = authAttrs
        self.mac = mac
        self.unauthAttrs = unauthAttrs
    }

    @inlinable
    init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let version = try CMSVersion(rawValue: Int(derEncoded: &nodes))
            let originatorInfo = try DER.optionalImplicitlyTagged(
                &nodes,
                tagNumber: Self.originatorInfoIdentifier.tagNumber,
                tagClass: Self.originatorInfoIdentifier.tagClass
            ) { node in
                try CMSOriginatorInfo(derEncoded: node, withIdentifier: Self.originatorInfoIdentifier)
            }
            let recipientInfos = try DER.set(of: CMSRecipientInfo.self, identifier: .set, nodes: &nodes)
            let macAlgorithm = try AlgorithmIdentifier(derEncoded: &nodes)
            let digestAlgorithm = try DER.optionalImplicitlyTagged(
                &nodes,
                tagNumber: Self.digestAlgorithmIdentifier.tagNumber,
                tagClass: Self.digestAlgorithmIdentifier.tagClass
            ) { node in
                try AlgorithmIdentifier(derEncoded: node, withIdentifier: Self.digestAlgorithmIdentifier)
            }
            let encapContentInfo = try CMSEncapsulatedContentInfo(derEncoded: &nodes)
            let authAttrs = try DER.optionalImplicitlyTagged(
                &nodes,
                tagNumber: Self.authAttrsIdentifier.tagNumber,
                tagClass: Self.authAttrsIdentifier.tagClass
            ) { node in
                try DER.set(of: CMSAttribute.self, identifier: Self.authAttrsIdentifier, rootNode: node)
            }
            let mac = try ASN1OctetString(derEncoded: &nodes)
            let unauthAttrs = try DER.optionalImplicitlyTagged(
                &nodes,
                tagNumber: Self.unauthAttrsIdentifier.tagNumber,
                tagClass: Self.unauthAttrsIdentifier.tagClass
            ) { node in
                try DER.set(of: CMSAttribute.self, identifier: Self.unauthAttrsIdentifier, rootNode: node)
            }

            return .init(
                version: version,
                originatorInfo: originatorInfo,
                recipientInfos: recipientInfos,
                macAlgorithm: macAlgorithm,
                digestAlgorithm: digestAlgorithm,
                encapContentInfo: encapContentInfo,
                authAttrs: authAttrs,
                mac: mac,
                unauthAttrs: unauthAttrs
            )
        }
    }

    @inlinable
    init(berEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try BER.sequence(rootNode, identifier: identifier) { nodes in
            let version = try CMSVersion(rawValue: Int(berEncoded: &nodes))
            let originatorInfo = try BER.optionalImplicitlyTagged(
                &nodes,
                tagNumber: Self.originatorInfoIdentifier.tagNumber,
                tagClass: Self.originatorInfoIdentifier.tagClass
            ) { node in
                try CMSOriginatorInfo(berEncoded: node, withIdentifier: Self.originatorInfoIdentifier)
            }
            let recipientInfos = try BER.set(of: CMSRecipientInfo.self, identifier: .set, nodes: &nodes)
            let macAlgorithm = try AlgorithmIdentifier(berEncoded: &nodes)
            let digestAlgorithm = try BER.optionalImplicitlyTagged(
                &nodes,
                tagNumber: Self.digestAlgorithmIdentifier.tagNumber,
                tagClass: Self.digestAlgorithmIdentifier.tagClass
            ) { node in
                try AlgorithmIdentifier(berEncoded: node, withIdentifier: Self.digestAlgorithmIdentifier)
            }
            let encapContentInfo = try CMSEncapsulatedContentInfo(berEncoded: &nodes)
            let authAttrs = try BER.optionalImplicitlyTagged(
                &nodes,
                tagNumber: Self.authAttrsIdentifier.tagNumber,
                tagClass: Self.authAttrsIdentifier.tagClass
            ) { node in
                try BER.set(of: CMSAttribute.self, identifier: Self.authAttrsIdentifier, rootNode: node)
            }
            let mac = try ASN1OctetString(berEncoded: &nodes)
            let unauthAttrs = try BER.optionalImplicitlyTagged(
                &nodes,
                tagNumber: Self.unauthAttrsIdentifier.tagNumber,
                tagClass: Self.unauthAttrsIdentifier.tagClass
            ) { node in
                try BER.set(of: CMSAttribute.self, identifier: Self.unauthAttrsIdentifier, rootNode: node)
            }

            return .init(
                version: version,
                originatorInfo: originatorInfo,
                recipientInfos: recipientInfos,
                macAlgorithm: macAlgorithm,
                digestAlgorithm: digestAlgorithm,
                encapContentInfo: encapContentInfo,
                authAttrs: authAttrs,
                mac: mac,
                unauthAttrs: unauthAttrs
            )
        }
    }

    @inlinable
    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(self.version.rawValue)
            if let originatorInfo {
                try originatorInfo.serialize(into: &coder, withIdentifier: Self.originatorInfoIdentifier)
            }
            try coder.serializeSetOf(self.recipientInfos)
            try coder.serialize(self.macAlgorithm)
            if let digestAlgorithm {
                try digestAlgorithm.serialize(into: &coder, withIdentifier: Self.digestAlgorithmIdentifier)
            }
            try coder.serialize(self.encapContentInfo)
            if let authAttrs {
                try coder.serializeSetOf(authAttrs, identifier: Self.authAttrsIdentifier)
            }
            try coder.serialize(self.mac)
            if let unauthAttrs {
                try coder.serializeSetOf(unauthAttrs, identifier: Self.unauthAttrsIdentifier)
            }
        }
    }
}
