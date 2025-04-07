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

/// ``OCSPRequest`` is defined in ASN.1 as:
/// ```
/// OCSPRequest ::= SEQUENCE {
///    tbsRequest              TBSRequest,
///    optionalSignature   [0] EXPLICIT Signature OPTIONAL }
/// ```
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
struct OCSPRequest: DERImplicitlyTaggable, Hashable {
    static var defaultIdentifier: ASN1Identifier {
        .sequence
    }

    var tbsRequest: OCSPTBSRequest

    var signature: OCSPSignature?

    init(tbsRequest: OCSPTBSRequest, signature: OCSPSignature? = nil) {
        self.tbsRequest = tbsRequest
        self.signature = signature
    }

    init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let tbsRequest = try OCSPTBSRequest(derEncoded: &nodes)
            let signature = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 0, tagClass: .contextSpecific) {
                try OCSPSignature(derEncoded: $0)
            }
            return .init(tbsRequest: tbsRequest, signature: signature)
        }
    }

    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(self.tbsRequest)
            if let signature = self.signature {
                try coder.serialize(signature, explicitlyTaggedWithTagNumber: 0, tagClass: .contextSpecific)
            }
        }
    }
}
