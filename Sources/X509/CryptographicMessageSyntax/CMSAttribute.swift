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

/// ``CMSAttribute`` is defined in ASN.1 as:
/// ```
/// Attribute ::= SEQUENCE {
///     attrType OBJECT IDENTIFIER,
///     attrValues SET OF AttributeValue }
///
/// AttributeValue ::= ANY
/// ```
@usableFromInline
struct CMSAttribute: DERImplicitlyTaggable, BERImplicitlyTaggable, Hashable, Sendable {

    @inlinable
    static var defaultIdentifier: ASN1Identifier {
        .sequence
    }

    @usableFromInline var attrType: ASN1ObjectIdentifier
    @usableFromInline var attrValues: [ASN1Any]

    @inlinable
    init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let attrType = try ASN1ObjectIdentifier(derEncoded: &nodes)
            let attrValues = try DER.set(of: ASN1Any.self, identifier: .set, nodes: &nodes)

            return .init(attrType: attrType, attrValues: attrValues)
        }
    }

    @inlinable
    init(berEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try BER.sequence(rootNode, identifier: identifier) { nodes in
            let attrType = try ASN1ObjectIdentifier(berEncoded: &nodes)
            let attrValues = try BER.set(of: ASN1Any.self, identifier: .set, nodes: &nodes)

            return .init(attrType: attrType, attrValues: attrValues)
        }
    }

    @inlinable
    init(attrType: ASN1ObjectIdentifier, attrValues: [ASN1Any]) {
        self.attrType = attrType
        self.attrValues = attrValues
    }

    @inlinable
    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(self.attrType)
            try coder.serializeSetOf(self.attrValues)
        }
    }
}
