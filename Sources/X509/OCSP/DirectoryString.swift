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
/// A DirectoryString is defined as:
///
/// ```
/// DirectoryString ::= CHOICE {
///       teletexString       TeletexString   (SIZE (1..MAX)),
///       printableString     PrintableString (SIZE (1..MAX)),
///       universalString     UniversalString (SIZE (1..MAX)),
///       utf8String          UTF8String      (SIZE (1..MAX)),
///       bmpString           BMPString       (SIZE (1..MAX)) }
/// ```
///
/// Note that these upper bounds are measured in _characters_, not bytes.
///
@usableFromInline
enum DirectoryString: ASN1Parseable, ASN1Serializable, Hashable {
    case teletexString(ASN1.ASN1TeletexString)
    case printableString(ASN1.ASN1PrintableString)
    case universalString(ASN1.ASN1UniversalString)
    case utf8String(ASN1.ASN1UTF8String)
    case bmpString(ASN1.ASN1BMPString)

    @inlinable
    init(asn1Encoded rootNode: ASN1.ASN1Node) throws {
        switch rootNode.identifier {
        case .primitiveTeletexString:
            self = .teletexString(try ASN1.ASN1TeletexString(asn1Encoded: rootNode))
        case .primitivePrintableString:
            self = .printableString(try ASN1.ASN1PrintableString(asn1Encoded: rootNode))
        case .primitiveUniversalString:
            self = .universalString(try ASN1.ASN1UniversalString(asn1Encoded: rootNode))
        case .primitiveUTF8String:
            self = .utf8String(try ASN1.ASN1UTF8String(asn1Encoded: rootNode))
        case .primitiveBMPString:
            self = .bmpString(try ASN1.ASN1BMPString(asn1Encoded: rootNode))
        default:
            throw ASN1Error.unexpectedFieldType
        }
    }

    @inlinable
    func serialize(into coder: inout ASN1.Serializer) throws {
        switch self {
        case .teletexString(let string):
            try string.serialize(into: &coder)
        case .printableString(let string):
            try string.serialize(into: &coder)
        case .universalString(let string):
            try string.serialize(into: &coder)
        case .utf8String(let string):
            try string.serialize(into: &coder)
        case .bmpString(let string):
            try string.serialize(into: &coder)
        }
    }
}
