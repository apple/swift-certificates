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

/// An OCSPResponseData is defined as:
///
/// ```
/// ResponseData ::= SEQUENCE {
///    version              [0] EXPLICIT Version DEFAULT v1,
///    responderID              ResponderID,
///    producedAt               GeneralizedTime,
///    responses                SEQUENCE OF SingleResponse,
///    responseExtensions   [1] EXPLICIT Extensions OPTIONAL }
///
/// Version         ::=             INTEGER  {  v1(0) }
/// ```
///
struct OCSPResponseData: ASN1ImplicitlyTaggable, Hashable {
    static var defaultIdentifier: ASN1.ASN1Identifier {
        .sequence
    }

    var version: Int

    var responderID: ResponderID

    var producedAt: ASN1.GeneralizedTime

    var responses: [OCSPSingleResponse]

    var responseExtensions: [Certificate.Extension]?

    init(version: Int = 0,
         responderID: ResponderID,
         producedAt: ASN1.GeneralizedTime,
         responses: [OCSPSingleResponse],
         responseExtensions: [Certificate.Extension]?) {
        self.version = version
        self.responderID = responderID
        self.producedAt = producedAt
        self.responses = responses
        self.responseExtensions = responseExtensions
    }

    init(asn1Encoded rootNode: ASN1.ASN1Node, withIdentifier identifier: ASN1.ASN1Identifier) throws {
        self = try ASN1.sequence(rootNode, identifier: identifier) { nodes in
            let version = try ASN1.decodeDefaultExplicitlyTagged(&nodes,
                                                                 tagNumber: 0,
                                                                 tagClass: .contextSpecific,
                                                                 defaultValue: 0) { try Int(asn1Encoded: $0) }
            let responderID = try ResponderID(asn1Encoded: &nodes)
            let producedAt = try ASN1.GeneralizedTime(asn1Encoded: &nodes)
            let responses = try ASN1.sequence(of: OCSPSingleResponse.self, identifier: .sequence, nodes: &nodes)
            let responseExtensions = try ASN1.optionalExplicitlyTagged(&nodes, tagNumber: 1, tagClass: .contextSpecific) { node in
                try ASN1.sequence(of: Certificate.Extension.self, identifier: .sequence, rootNode: node)
            }

            return .init(version: version, responderID: responderID, producedAt: producedAt, responses: responses, responseExtensions: responseExtensions)
        }
    }

    func serialize(into coder: inout ASN1.Serializer, withIdentifier identifier: ASN1.ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            if self.version != 0 {
                try coder.serialize(self.version, explicitlyTaggedWithTagNumber: 0, tagClass: .contextSpecific)
            }

            try coder.serialize(self.responderID)
            try coder.serialize(self.producedAt)
            try coder.serializeSequenceOf(self.responses)

            if let responseExtensions = self.responseExtensions {
                try coder.serialize(explicitlyTaggedWithTagNumber: 1, tagClass: .contextSpecific) { coder in
                    try coder.serializeSequenceOf(responseExtensions)
                }
            }
        }
    }
}
