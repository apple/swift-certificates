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
struct OCSPResponse: DERImplicitlyTaggable, Hashable {
    static var defaultIdentifier: ASN1Identifier {
        .sequence
    }

    var responseStatus: OCSPResponseStatus

    var responseBytes: OCSPResponseBytes?

    init(responseStatus: OCSPResponseStatus, responseBytes: OCSPResponseBytes?) {
        self.responseStatus = responseStatus
        self.responseBytes = responseBytes
    }

    init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let responseStatus = try OCSPResponseStatus(derEncoded: &nodes)
            let responseBytes = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 0, tagClass: .contextSpecific) { node in
                try OCSPResponseBytes(derEncoded: node)
            }

            return .init(responseStatus: responseStatus, responseBytes: responseBytes)
        }
    }

    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(self.responseStatus)
            if let responseBytes = self.responseBytes {
                try coder.serialize(responseBytes, explicitlyTaggedWithTagNumber: 0, tagClass: .contextSpecific)
            }
        }
    }
}
