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

/// An OCSPResponseBytes is defined as:
///
/// ```
/// ResponseBytes ::=       SEQUENCE {
///     responseType   OBJECT IDENTIFIER,
///     response       OCTET STRING }
///
/// For a basic OCSP responder, responseType will be id-pkix-ocsp-basic.
///
/// id-pkix-ocsp           OBJECT IDENTIFIER ::= { id-ad-ocsp }
/// id-pkix-ocsp-basic     OBJECT IDENTIFIER ::= { id-pkix-ocsp 1 }
/// ```
///
struct OCSPResponseBytes: ASN1ImplicitlyTaggable, Hashable {
    static var defaultIdentifier: ASN1.ASN1Identifier {
        .sequence
    }

    var responseType: ASN1.ASN1ObjectIdentifier

    var response: ASN1.ASN1OctetString

    init(responseType: ASN1.ASN1ObjectIdentifier, response: ASN1.ASN1OctetString) {
        self.responseType = responseType
        self.response = response
    }

    init(asn1Encoded rootNode: ASN1.ASN1Node, withIdentifier identifier: ASN1.ASN1Identifier) throws {
        self = try ASN1.sequence(rootNode, identifier: identifier) { nodes in
            let responseType = try ASN1.ASN1ObjectIdentifier(asn1Encoded: &nodes)
            let response = try ASN1.ASN1OctetString(asn1Encoded: &nodes)
            return .init(responseType: responseType, response: response)
        }
    }

    func serialize(into coder: inout ASN1.Serializer, withIdentifier identifier: ASN1.ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(self.responseType)
            try coder.serialize(self.response)
        }
    }
}

extension BasicOCSPResponse {
    init(decoding original: OCSPResponseBytes) throws {
        guard original.responseType == .OCSP.basicResponse else {
            throw ASN1Error.invalidObjectIdentifier
        }

        self = try .init(asn1Encoded: original.response.bytes)
    }
}

extension OCSPResponseBytes {
    init(encoding original: BasicOCSPResponse) throws {
        self.responseType = .OCSP.basicResponse

        var serializer = ASN1.Serializer()
        try serializer.serialize(original)
        self.response = ASN1.ASN1OctetString(contentBytes: serializer.serializedBytes[...])
    }
}
