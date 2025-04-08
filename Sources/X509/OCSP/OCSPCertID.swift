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
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
struct OCSPCertID: DERImplicitlyTaggable, Hashable {
    var hashAlgorithm: AlgorithmIdentifier

    /// Hash of issuer's DN
    var issuerNameHash: ASN1OctetString

    /// Hash of issuer's public key
    var issuerKeyHash: ASN1OctetString

    var serialNumber: Certificate.SerialNumber

    static var defaultIdentifier: ASN1Identifier {
        .sequence
    }

    init(
        hashAlgorithm: AlgorithmIdentifier,
        issuerNameHash: ASN1OctetString,
        issuerKeyHash: ASN1OctetString,
        serialNumber: Certificate.SerialNumber
    ) {
        self.hashAlgorithm = hashAlgorithm
        self.issuerNameHash = issuerNameHash
        self.issuerKeyHash = issuerKeyHash
        self.serialNumber = serialNumber
    }

    init(derEncoded node: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(node, identifier: identifier) { nodes in
            let hashAlgorithm: AlgorithmIdentifier = try {
                let hashAlgorithm = try AlgorithmIdentifier(derEncoded: &nodes)
                switch hashAlgorithm {
                case .sha1, .sha1UsingNil:
                    return .sha1UsingNil
                case .sha256, .sha256UsingNil:
                    return .sha256UsingNil
                case .sha384, .sha384UsingNil:
                    return .sha384UsingNil
                case .sha512, .sha1UsingNil:
                    return .sha512UsingNil
                default:
                    return hashAlgorithm
                }
            }()
            let issuerNameHash = try ASN1OctetString(derEncoded: &nodes)
            let issuerKeyHash = try ASN1OctetString(derEncoded: &nodes)
            let serialNumber = try ArraySlice<UInt8>(derEncoded: &nodes)

            return .init(
                hashAlgorithm: hashAlgorithm,
                issuerNameHash: issuerNameHash,
                issuerKeyHash: issuerKeyHash,
                serialNumber: .init(bytes: serialNumber)
            )
        }
    }

    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try self.hashAlgorithm.serialize(into: &coder)
            try self.issuerNameHash.serialize(into: &coder)
            try self.issuerKeyHash.serialize(into: &coder)
            try self.serialNumber.bytes.serialize(into: &coder)
        }
    }
}
