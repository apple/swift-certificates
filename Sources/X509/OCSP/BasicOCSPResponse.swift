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
struct BasicOCSPResponse: ASN1ImplicitlyTaggable, Hashable {
    static var defaultIdentifier: ASN1.ASN1Identifier {
        .sequence
    }

    var responseData: OCSPResponseData

    var signatureAlgorithm: AlgorithmIdentifier

    var signature: ASN1.ASN1BitString

    // Yup, you read this right: for the moment, we don't decode certs. We need a strategy for this.
    //var certs: []

    init(responseData: OCSPResponseData, signatureAlgorithm: AlgorithmIdentifier, signature: ASN1.ASN1BitString) {
        self.responseData = responseData
        self.signatureAlgorithm = signatureAlgorithm
        self.signature = signature
    }

    init(asn1Encoded rootNode: ASN1.ASN1Node, withIdentifier identifier: ASN1.ASN1Identifier) throws {
        self = try ASN1.sequence(rootNode, identifier: identifier) { nodes in
            let responseData = try OCSPResponseData(asn1Encoded: &nodes)
            let signatureAlgorithm = try AlgorithmIdentifier(asn1Encoded: &nodes)
            let signature = try ASN1.ASN1BitString(asn1Encoded: &nodes)

            // We need to consume the certificate nodes, but we don't _yet_ parse it.
            _ = try ASN1.optionalExplicitlyTagged(&nodes, tagNumber: 0, tagClass: .contextSpecific) { _ in }

            return .init(responseData: responseData, signatureAlgorithm: signatureAlgorithm, signature: signature)
        }
    }

    func serialize(into coder: inout ASN1.Serializer, withIdentifier identifier: ASN1.ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(self.responseData)
            try coder.serialize(self.signatureAlgorithm)
            try coder.serialize(self.signature)
        }
    }
}

enum ResponderID: ASN1Parseable, ASN1Serializable, Hashable {
    case byName(DistinguishedName)
    case byKey(ASN1.ASN1OctetString)

    private static let nameIdentifier = ASN1.ASN1Identifier(tagWithNumber: 1, tagClass: .contextSpecific, constructed: true)
    private static let keyIdentifier = ASN1.ASN1Identifier(tagWithNumber: 2, tagClass: .contextSpecific, constructed: true)

    init(asn1Encoded: ASN1.ASN1Node) throws {
        switch asn1Encoded.identifier {
        case ResponderID.nameIdentifier:
            guard case .constructed(let nodes) = asn1Encoded.content else {
                throw ASN1Error.invalidASN1Object
            }
            var iterator = nodes.makeIterator()
            guard let rootNode = iterator.next(), iterator.next() == nil else {
                throw ASN1Error.invalidASN1Object
            }

            self = try .byName(.init(asn1Encoded: rootNode))
        case ResponderID.keyIdentifier:
            guard case .constructed(let nodes) = asn1Encoded.content else {
                throw ASN1Error.invalidASN1Object
            }
            var iterator = nodes.makeIterator()
            guard let rootNode = iterator.next(), iterator.next() == nil else {
                throw ASN1Error.invalidASN1Object
            }

            self = try .byKey(.init(asn1Encoded: rootNode))
        default:
            throw ASN1Error.unexpectedFieldType
        }
    }

    func serialize(into coder: inout ASN1.Serializer) throws {
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
