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

/// A bitstring is a representation of a sequence of bits.
///
/// In ASN.1, bitstrings serve two different use-cases. The first is as arbitrary-length sequences of bits.
/// These are typically used to encode cryptographic keys, such as RSA keys. The second is as a form of bitset.
///
/// In the case of a bitset, DER has additional requirements as to how to represent the object. This type does not
/// enforce those additional rules: users are expected to implement that validation themselves.
public struct ASN1BitString: DERImplicitlyTaggable {
    /// The default identifier for this type.
    ///
    /// Evaluates to ``ASN1Identifier/bitString``.
    @inlinable
    public static var defaultIdentifier: ASN1Identifier {
        .bitString
    }

    /// The raw bytes that make up this bitstring.
    ///
    /// The last ``paddingBits`` number of bits in the final octet of this byte sequence must be zero.
    public var bytes: ArraySlice<UInt8> {
        didSet {
            try! self._validate()
        }
    }

    /// The number of bits in the last octet of ``bytes`` that are not part of this bitstring.
    ///
    /// The excluded bits are the least significant bits.
    ///
    /// If ``bytes`` is empty then this value must be 0.
    public var paddingBits: Int {
        didSet {
            precondition((0..<8).contains(self.paddingBits))
            try! self._validate()
        }
    }

    @inlinable
    public init(derEncoded node: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        guard node.identifier == identifier else {
            throw ASN1Error.unexpectedFieldType(node.identifier)
        }

        guard case .primitive(let content) = node.content else {
            preconditionFailure("ASN.1 parser generated primitive node with constructed content")
        }

        // The initial octet explains how many of the bits in the _final_ octet are not part of the bitstring.
        guard let paddingBits = content.first, (0..<8).contains(paddingBits) else {
            throw ASN1Error.invalidASN1Object(reason: "Unable to determine a valid number of padding bits for ASN1BitString")
        }

        self.paddingBits = Int(paddingBits)
        self.bytes = content.dropFirst()

        try self._validate()
    }

    /// Construct an ``ASN1BitString`` from raw components.
    ///
    /// - parameters:
    ///     - bytes: The bytes to represent this bitstring
    ///     - paddingBits: The number of bits in the trailing byte that are not actually part of this bitstring.
    @inlinable
    public init(bytes: ArraySlice<UInt8>, paddingBits: Int = 0) {
        self.bytes = bytes
        self.paddingBits = paddingBits
        try! self._validate()
    }

    @inlinable
    public func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        coder.appendPrimitiveNode(identifier: identifier) { bytes in
            bytes.append(UInt8(truncatingIfNeeded: self.paddingBits))
            bytes.append(contentsOf: self.bytes)
        }
    }

    @inlinable
    internal func _validate() throws {
        guard let finalByte = self.bytes.last else {
            if self.paddingBits != 0 {
                // If there are no bytes, there must be no padding bits.
                throw ASN1Error.invalidASN1Object(reason: "Invalid number of padding bits for ASN1BitString: \(self.paddingBits)")
            }

            return
        }

        // Oooh, bit twiddling.
        //
        // All joking aside, this sets the bottom `self.paddingBits` to 1.
        let mask = ~(UInt8.max << self.paddingBits)
        if (finalByte & mask) != 0 {
            throw ASN1Error.invalidASN1Object(reason: "Invalid padding bits in ASN1BitString: \(self.paddingBits) of padding, \(finalByte) final byte")
        }
    }
}

extension ASN1BitString: Hashable { }

extension ASN1BitString: Sendable { }

extension ASN1BitString {
    @inlinable
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        return try self.bytes.withUnsafeBytes(body)
    }
}
