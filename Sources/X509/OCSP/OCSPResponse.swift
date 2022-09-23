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

/// An OCSPResponse is defined as:
///
/// ```
/// OCSPResponse ::= SEQUENCE {
///    responseStatus         OCSPResponseStatus,
///    responseBytes          [0] EXPLICIT ResponseBytes OPTIONAL }
///
/// ```
///
struct OCSPResponse: ASN1ImplicitlyTaggable, Hashable {
    static var defaultIdentifier: ASN1.ASN1Identifier {
        .sequence
    }

    var responseStatus: OCSPResponseStatus

    var responseBytes: OCSPResponseBytes?

    init(responseStatus: OCSPResponseStatus, responseBytes: OCSPResponseBytes?) {
        self.responseStatus = responseStatus
        self.responseBytes = responseBytes
    }

    init(asn1Encoded rootNode: ASN1.ASN1Node, withIdentifier identifier: ASN1.ASN1Identifier) throws {
        self = try ASN1.sequence(rootNode, identifier: identifier) { nodes in
            let responseStatus = try OCSPResponseStatus(asn1Encoded: &nodes)
            let responseBytes = try ASN1.optionalExplicitlyTagged(&nodes, tagNumber: 0, tagClass: .contextSpecific) { node in
                try OCSPResponseBytes(asn1Encoded: node)
            }

            return .init(responseStatus: responseStatus, responseBytes: responseBytes)
        }
    }

    func serialize(into coder: inout ASN1.Serializer, withIdentifier identifier: ASN1.ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(self.responseStatus)
            if let responseBytes = self.responseBytes {
                try coder.serialize(responseBytes, explicitlyTaggedWithTagNumber: 0, tagClass: .contextSpecific)
            }
        }
    }
}
