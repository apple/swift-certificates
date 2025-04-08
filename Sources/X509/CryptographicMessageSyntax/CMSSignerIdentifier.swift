//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCertificates open source project
//
// Copyright (c) 2023 Apple Inc. and the SwiftCertificates project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCertificates project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import SwiftASN1

/// ``CMSSignerIdentifier`` is defined in ASN.1 as:
/// ```
/// SignerIdentifier ::= CHOICE {
///   issuerAndSerialNumber IssuerAndSerialNumber,
///   subjectKeyIdentifier [0] SubjectKeyIdentifier }
///  ```
@usableFromInline
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
enum CMSSignerIdentifier: DERParseable, BERParseable, DERSerializable, BERSerializable, Hashable, Sendable {
    @usableFromInline
    static let skiIdentifier = ASN1Identifier(tagWithNumber: 0, tagClass: .contextSpecific)

    case issuerAndSerialNumber(CMSIssuerAndSerialNumber)
    case subjectKeyIdentifier(SubjectKeyIdentifier)

    @inlinable
    init(derEncoded node: ASN1Node) throws {
        switch node.identifier {
        case CMSIssuerAndSerialNumber.defaultIdentifier:
            self = try .issuerAndSerialNumber(.init(derEncoded: node))

        case Self.skiIdentifier:
            self = try .subjectKeyIdentifier(
                .init(
                    keyIdentifier: ASN1OctetString(
                        derEncoded: node,
                        withIdentifier: Self.skiIdentifier
                    ).bytes
                )
            )

        default:
            throw ASN1Error.unexpectedFieldType(node.identifier)
        }
    }

    @inlinable
    func serialize(into coder: inout DER.Serializer) throws {
        switch self {
        case .issuerAndSerialNumber(let issuerAndSerialNumber):
            try issuerAndSerialNumber.serialize(into: &coder)

        case .subjectKeyIdentifier(let subjectKeyIdentifier):
            try ASN1OctetString(contentBytes: subjectKeyIdentifier.keyIdentifier)
                .serialize(into: &coder, withIdentifier: Self.skiIdentifier)
        }
    }

    @inlinable
    init(issuerAndSerialNumber certificate: Certificate) {
        self = .issuerAndSerialNumber(.init(issuer: certificate.issuer, serialNumber: certificate.serialNumber))
    }
}
