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
enum CMSSignerIdentifier: DERParseable, DERSerializable, Hashable {
    
    private static let subjectKeyIdentifierIdentifier = ASN1Identifier(tagWithNumber: 0, tagClass: .contextSpecific)
    
    case issuerAndSerialNumber(CMSIssuerAndSerialNumber)
    case subjectKeyIdentifier(Certificate.Extensions.SubjectKeyIdentifier)
    
    init(derEncoded node: ASN1Node) throws {
        switch node.identifier {
        case CMSIssuerAndSerialNumber.defaultIdentifier:
            self = try .issuerAndSerialNumber(.init(derEncoded: node))

        case Self.subjectKeyIdentifierIdentifier:
            self = try .subjectKeyIdentifier(.init(keyIdentifier: .init(derEncoded: node, withIdentifier: Self.subjectKeyIdentifierIdentifier)))

        default:
            throw ASN1Error.invalidASN1Object
        }
    }
    
    func serialize(into coder: inout DER.Serializer) throws {
        switch self {
        case .issuerAndSerialNumber(let issuerAndSerialNumber):
            try issuerAndSerialNumber.serialize(into: &coder)

        case .subjectKeyIdentifier(let subjectKeyIdentifier):
            try subjectKeyIdentifier.keyIdentifier.serialize(into: &coder, withIdentifier: Self.subjectKeyIdentifierIdentifier)
            
        }
    }
}