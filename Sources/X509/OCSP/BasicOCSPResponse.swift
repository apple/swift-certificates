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
/// KeyHash ::= OCTET STRING
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
struct BasicOCSPResponse: DERImplicitlyTaggable, Hashable {
    static var defaultIdentifier: ASN1Identifier {
        .sequence
    }

    var responseData: OCSPResponseData

    var signatureAlgorithm: AlgorithmIdentifier

    var signature: ASN1BitString

    // Yup, you read this right: for the moment, we don't decode certs. We need a strategy for this.
    //var certs: []

    init(responseData: OCSPResponseData, signatureAlgorithm: AlgorithmIdentifier, signature: ASN1BitString) {
        self.responseData = responseData
        self.signatureAlgorithm = signatureAlgorithm
        self.signature = signature
    }

    init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let responseData = try OCSPResponseData(derEncoded: &nodes)
            let signatureAlgorithm = try AlgorithmIdentifier(derEncoded: &nodes)
            let signature = try ASN1BitString(derEncoded: &nodes)

            // We need to consume the certificate nodes, but we don't _yet_ parse it.
            _ = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 0, tagClass: .contextSpecific) { _ in }

            return .init(responseData: responseData, signatureAlgorithm: signatureAlgorithm, signature: signature)
        }
    }

    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(self.responseData)
            try coder.serialize(self.signatureAlgorithm)
            try coder.serialize(self.signature)
        }
    }
}

enum ResponderID: DERParseable, DERSerializable, Hashable {
    case byName(DistinguishedName)
    case byKey(ASN1OctetString)

    private static let nameIdentifier = ASN1Identifier(tagWithNumber: 1, tagClass: .contextSpecific)
    private static let keyIdentifier = ASN1Identifier(tagWithNumber: 2, tagClass: .contextSpecific)

    init(derEncoded: ASN1Node) throws {
        switch derEncoded.identifier {
        case ResponderID.nameIdentifier:
            guard case .constructed(let nodes) = derEncoded.content else {
                throw ASN1Error.invalidASN1Object
            }
            var iterator = nodes.makeIterator()
            guard let rootNode = iterator.next(), iterator.next() == nil else {
                throw ASN1Error.invalidASN1Object
            }

            self = try .byName(.init(derEncoded: rootNode))
        case ResponderID.keyIdentifier:
            guard case .constructed(let nodes) = derEncoded.content else {
                throw ASN1Error.invalidASN1Object
            }
            var iterator = nodes.makeIterator()
            guard let rootNode = iterator.next(), iterator.next() == nil else {
                throw ASN1Error.invalidASN1Object
            }

            self = try .byKey(.init(derEncoded: rootNode))
        default:
            throw ASN1Error.unexpectedFieldType
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
