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

/// Let's talk about OCSP.
///
/// We can provide the needed type definitions from RFC 6960 to construct BasicOCSPResponse:
///
/// ```
/// BasicOCSPResponse       ::= SEQUENCE {
///    tbsResponseData      ResponseData,
///    signatureAlgorithm   AlgorithmIdentifier,
///    signature            BIT STRING,
///    certs            [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
///
/// ResponseData ::= SEQUENCE {
///    version              [0] EXPLICIT Version DEFAULT v1,
///    responderID              ResponderID,
///    producedAt               GeneralizedTime,
///    responses                SEQUENCE OF SingleResponse,
///    responseExtensions   [1] EXPLICIT Extensions OPTIONAL }
///
/// ResponderID ::= CHOICE {
///    byName               [1] Name,
///    byKey                [2] KeyHash }
///
/// KeyHash ::= OCTET STRING -- SHA-1 hash of responder's public key
///    (excluding the tag and length fields)
///
/// SingleResponse ::= SEQUENCE {
///    certID                       CertID,
///    certStatus                   CertStatus,
///    thisUpdate                   GeneralizedTime,
///    nextUpdate         [0]       EXPLICIT GeneralizedTime OPTIONAL,
///    singleExtensions   [1]       EXPLICIT Extensions OPTIONAL }
///
/// CertStatus ::= CHOICE {
///    good        [0]     IMPLICIT NULL,
///    revoked     [1]     IMPLICIT RevokedInfo,
///    unknown     [2]     IMPLICIT UnknownInfo }
///
/// RevokedInfo ::= SEQUENCE {
///    revocationTime              GeneralizedTime,
///    revocationReason    [0]     EXPLICIT CRLReason OPTIONAL }
///
/// UnknownInfo ::= NULL
///
/// Version ::= INTEGER {  v1(0) }
///
/// CertID ::= SEQUENCE {
///    hashAlgorithm       AlgorithmIdentifier,
///    issuerNameHash      OCTET STRING,
///    issuerKeyHash       OCTET STRING,
///    serialNumber        CertificateSerialNumber }
/// ```

/// A Basic OCSP Response is laid out as follows:
///
/// ```
/// BasicOCSPResponse       ::= SEQUENCE {
///    tbsResponseData      ResponseData,
///    signatureAlgorithm   AlgorithmIdentifier,
///    signature            BIT STRING,
///    certs            [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
/// ```
///
/// This type is generic because our different backends want to use different bignum representations.
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
struct BasicOCSPResponse: DERImplicitlyTaggable, Hashable {
    static var defaultIdentifier: ASN1Identifier {
        .sequence
    }

    var responseData: OCSPResponseData

    var responseDataBytes: ArraySlice<UInt8>

    var signatureAlgorithm: AlgorithmIdentifier

    var signature: ASN1BitString

    var certs: [Certificate]?

    init(
        responseData: OCSPResponseData,
        responseDataBytes: ArraySlice<UInt8>,
        signatureAlgorithm: AlgorithmIdentifier,
        signature: ASN1BitString,
        certs: [Certificate]?
    ) {
        self.responseData = responseData
        self.responseDataBytes = responseDataBytes
        self.signatureAlgorithm = signatureAlgorithm
        self.signature = signature
        self.certs = certs
    }
    init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            guard let responseDataNode = nodes.next() else {
                throw ASN1Error.invalidASN1Object(reason: "missing OCSP response data")
            }
            let responseData = try OCSPResponseData(derEncoded: responseDataNode)
            let signatureAlgorithm = try AlgorithmIdentifier(derEncoded: &nodes)
            let signature = try ASN1BitString(derEncoded: &nodes)

            let certs = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 0, tagClass: .contextSpecific) { node in
                try DER.sequence(of: Certificate.self, identifier: .sequence, rootNode: node)
            }

            return .init(
                responseData: responseData,
                responseDataBytes: responseDataNode.encodedBytes,
                signatureAlgorithm: signatureAlgorithm,
                signature: signature,
                certs: certs
            )
        }
    }

    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            coder.serializeRawBytes(self.responseDataBytes)
            try coder.serialize(self.signatureAlgorithm)
            try coder.serialize(self.signature)
            if let certs {
                try coder.serialize(explicitlyTaggedWithTagNumber: 0, tagClass: .contextSpecific) { coder in
                    try coder.serializeSequenceOf(certs)
                }
            }
        }
    }
}

enum ResponderID: DERParseable, DERSerializable, Hashable {
    case byName(DistinguishedName)
    /// SHA-1 hash of responder's public key (excluding the tag and length fields)
    case byKey(ASN1OctetString)

    private static let nameIdentifier = ASN1Identifier(tagWithNumber: 1, tagClass: .contextSpecific)
    private static let keyIdentifier = ASN1Identifier(tagWithNumber: 2, tagClass: .contextSpecific)

    init(derEncoded: ASN1Node) throws {
        switch derEncoded.identifier {
        case ResponderID.nameIdentifier:
            guard case .constructed(let nodes) = derEncoded.content else {
                throw ASN1Error.invalidASN1Object(reason: "ResponderID content must be constructed.")
            }
            var iterator = nodes.makeIterator()
            guard let rootNode = iterator.next(), iterator.next() == nil else {
                throw ASN1Error.invalidASN1Object(reason: "Invalid number of responder nodes.")
            }

            self = try .byName(.init(derEncoded: rootNode))
        case ResponderID.keyIdentifier:
            guard case .constructed(let nodes) = derEncoded.content else {
                throw ASN1Error.invalidASN1Object(reason: "ResponderID content must be constructed")
            }
            var iterator = nodes.makeIterator()
            guard let rootNode = iterator.next(), iterator.next() == nil else {
                throw ASN1Error.invalidASN1Object(reason: "Invalid number of responder nodes")
            }

            self = try .byKey(.init(derEncoded: rootNode))
        default:
            throw ASN1Error.unexpectedFieldType(derEncoded.identifier)
        }
    }

    func serialize(into coder: inout DER.Serializer) throws {
        switch self {
        case .byName(let name):
            try coder.appendConstructedNode(identifier: ResponderID.nameIdentifier) { coder in
                try name.serialize(into: &coder)
            }
        case .byKey(let key):
            try coder.appendConstructedNode(identifier: ResponderID.keyIdentifier) { coder in
                try key.serialize(into: &coder)
            }
        }
    }
}
