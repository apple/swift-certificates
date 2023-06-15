//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftASN1 open source project
//
// Copyright (c) 2019-2020 Apple Inc. and the SwiftASN1 project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftASN1 project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

/// An OCTET STRING is a representation of a string of octets.
public struct ASN1OctetString: DERImplicitlyTaggable {
    @inlinable
    public static var defaultIdentifier: ASN1Identifier {
        .octetString
    }

    /// The octets that make up this OCTET STRING.
    public var bytes: ArraySlice<UInt8>

    @inlinable
    public init(derEncoded node: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        guard node.identifier == identifier else {
            throw ASN1Error.unexpectedFieldType(node.identifier)
        }

        guard case .primitive(let content) = node.content else {
            preconditionFailure("ASN.1 parser generated primitive node with constructed content")
        }

        self.bytes = content
    }

    /// Construct an OCTET STRING from a sequence of bytes.
    ///
    /// - parameters:
    ///     - contentBytes: The bytes that make up this OCTET STRING.
    @inlinable
    public init(contentBytes: ArraySlice<UInt8>) {
        self.bytes = contentBytes
    }

    @inlinable
    public func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        coder.appendPrimitiveNode(identifier: identifier) { bytes in
            bytes.append(contentsOf: self.bytes)
        }
    }
}

extension ASN1OctetString: Hashable { }

extension ASN1OctetString: Sendable { }

extension ASN1OctetString {
    @inlinable
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        return try self.bytes.withUnsafeBytes(body)
    }
}
