//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftASN1 open source project
//
// Copyright (c) 2021 Apple Inc. and the SwiftASN1 project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftASN1 project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

/// An ASN1 NULL represents nothing.
public struct ASN1Null: DERImplicitlyTaggable, Hashable, Sendable {
    @inlinable
    public static var defaultIdentifier: ASN1Identifier {
        .null
    }

    /// Construct a new ASN.1 null.
    @inlinable
    public init() { }

    @inlinable
    public init(derEncoded node: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        guard node.identifier == identifier, case .primitive(let content) = node.content else {
            throw ASN1Error.unexpectedFieldType(node.identifier)
        }

        guard content.count == 0 else {
            throw ASN1Error.invalidASN1Object(reason: "ASN1Null must be empty, received \(content.count) bytes")
        }
    }

    @inlinable
    public func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) {
        coder.appendPrimitiveNode(identifier: identifier, { _ in })
    }
}
