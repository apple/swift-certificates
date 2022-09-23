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

/// A CertID is defined as:
///
/// ```
/// CertID          ::=     SEQUENCE {
///     hashAlgorithm       AlgorithmIdentifier,
///     issuerNameHash      OCTET STRING, -- Hash of issuer's DN
///     issuerKeyHash       OCTET STRING, -- Hash of issuer's public key
///     serialNumber        CertificateSerialNumber }
///
/// CertificateSerialNumber ::= INTEGER
/// ```
///
struct OCSPCertID: ASN1ImplicitlyTaggable, Hashable {
    var hashAlgorithm: AlgorithmIdentifier

    var issuerNameHash: ASN1.ASN1OctetString

    var issuerKeyHash: ASN1.ASN1OctetString

    var serialNumber: ArraySlice<UInt8>

    static var defaultIdentifier: ASN1.ASN1Identifier {
        .sequence
    }

    init(hashAlgorithm: AlgorithmIdentifier,
         issuerNameHash: ASN1.ASN1OctetString,
         issuerKeyHash: ASN1.ASN1OctetString,
         serialNumber: ArraySlice<UInt8>) {
        self.hashAlgorithm = hashAlgorithm
        self.issuerNameHash = issuerNameHash
        self.issuerKeyHash = issuerKeyHash
        self.serialNumber = serialNumber
    }

    init(asn1Encoded node: ASN1.ASN1Node, withIdentifier identifier: ASN1.ASN1Identifier) throws {
        self = try ASN1.sequence(node, identifier: identifier) { nodes in
            let hashAlgorithm = try AlgorithmIdentifier(asn1Encoded: &nodes)
            let issuerNameHash = try ASN1.ASN1OctetString(asn1Encoded: &nodes)
            let issuerKeyHash = try ASN1.ASN1OctetString(asn1Encoded: &nodes)
            let serialNumber = try ArraySlice<UInt8>(asn1Encoded: &nodes)

            return .init(hashAlgorithm: hashAlgorithm,
                         issuerNameHash: issuerNameHash,
                         issuerKeyHash: issuerKeyHash,
                         serialNumber: serialNumber)
        }
    }

    func serialize(into coder: inout ASN1.Serializer, withIdentifier identifier: ASN1.ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try self.hashAlgorithm.serialize(into: &coder)
            try self.issuerNameHash.serialize(into: &coder)
            try self.issuerKeyHash.serialize(into: &coder)
            try self.serialNumber.serialize(into: &coder)
        }
    }
}
