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
enum DirectoryString: DERParseable, DERSerializable, Hashable, Sendable {
    case teletexString(ASN1TeletexString)
    case printableString(ASN1PrintableString)
    case universalString(ASN1UniversalString)
    case utf8String(ASN1UTF8String)
    case bmpString(ASN1BMPString)

    @inlinable
    init(derEncoded rootNode: ASN1Node) throws {
        switch rootNode.identifier {
        case .teletexString:
            self = .teletexString(try ASN1TeletexString(derEncoded: rootNode))
        case .printableString:
            self = .printableString(try ASN1PrintableString(derEncoded: rootNode))
        case .universalString:
            self = .universalString(try ASN1UniversalString(derEncoded: rootNode))
        case .utf8String:
            self = .utf8String(try ASN1UTF8String(derEncoded: rootNode))
        case .bmpString:
            self = .bmpString(try ASN1BMPString(derEncoded: rootNode))
        default:
            throw ASN1Error.unexpectedFieldType(rootNode.identifier)
        }
    }

    @inlinable
    func serialize(into coder: inout DER.Serializer) throws {
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
