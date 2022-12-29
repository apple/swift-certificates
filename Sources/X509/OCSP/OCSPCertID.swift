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
struct OCSPCertID: DERImplicitlyTaggable, Hashable {
    var hashAlgorithm: AlgorithmIdentifier

    /// Hash of issuer's DN
    var issuerNameHash: ASN1OctetString

    /// Hash of issuer's public key
    var issuerKeyHash: ASN1OctetString

    var serialNumber: ArraySlice<UInt8>

    static var defaultIdentifier: ASN1Identifier {
        .sequence
    }

    init(hashAlgorithm: AlgorithmIdentifier,
         issuerNameHash: ASN1OctetString,
         issuerKeyHash: ASN1OctetString,
         serialNumber: ArraySlice<UInt8>) {
        self.hashAlgorithm = hashAlgorithm
        self.issuerNameHash = issuerNameHash
        self.issuerKeyHash = issuerKeyHash
        self.serialNumber = serialNumber
    }

    init(derEncoded node: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(node, identifier: identifier) { nodes in
            let hashAlgorithm = try AlgorithmIdentifier(derEncoded: &nodes)
            let issuerNameHash = try ASN1OctetString(derEncoded: &nodes)
            let issuerKeyHash = try ASN1OctetString(derEncoded: &nodes)
            let serialNumber = try ArraySlice<UInt8>(derEncoded: &nodes)

            return .init(hashAlgorithm: hashAlgorithm,
                         issuerNameHash: issuerNameHash,
                         issuerKeyHash: issuerKeyHash,
                         serialNumber: serialNumber)
        }
    }

    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try self.hashAlgorithm.serialize(into: &coder)
            try self.issuerNameHash.serialize(into: &coder)
            try self.issuerKeyHash.serialize(into: &coder)
            try self.serialNumber.serialize(into: &coder)
        }
    }
}
