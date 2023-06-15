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

/// A protocol that represents any internal object that can present itself as an INTEGER, or be parsed from
/// an INTEGER.
///
/// This protocol exists to allow users to handle the possibility of decoding integers that cannot fit into
/// UInt64 or Int64. While both of those types conform by default, users can conform their preferred
/// arbitrary-width integer type as well, or use `ArraySlice<UInt8>` to store the raw bytes of the
/// integer directly.
public protocol ASN1IntegerRepresentable: DERImplicitlyTaggable {
    associatedtype IntegerBytes: RandomAccessCollection where IntegerBytes.Element == UInt8

    /// Whether this type can represent signed integers.
    ///
    /// If this is set to false, the serializer and parser will automatically handle padding
    /// with leading zero bytes as needed.
    static var isSigned: Bool { get }

    /// Construct the integer value from the integer bytes. These will be big-endian, and encoded
    /// according to DER requirements.
    init(derIntegerBytes: ArraySlice<UInt8>) throws

    /// Provide the big-endian bytes corresponding to this integer.
    func withBigEndianIntegerBytes<ReturnType>(_ body: (IntegerBytes) throws -> ReturnType) rethrows -> ReturnType
}

extension ASN1IntegerRepresentable {
    @inlinable
    public static var defaultIdentifier: ASN1Identifier {
        .integer
    }

    @inlinable
    public init(derEncoded node: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        guard node.identifier == identifier else {
            throw ASN1Error.unexpectedFieldType(node.identifier)
        }

        guard case .primitive(var dataBytes) = node.content else {
            preconditionFailure("ASN.1 parser generated primitive node with constructed content")
        }

        // Zero bytes of integer is not an acceptable encoding.
        guard dataBytes.count > 0 else {
            throw ASN1Error.invalidASN1IntegerEncoding(reason: "INTEGER encoded with zero bytes")
        }

        // 8.3.2 If the contents octets of an integer value encoding consist of more than one octet, then the bits of the first octet and bit 8 of the second octet:
        //
        // a) shall not all be ones; and
        // b) shall not all be zero.
        //
        // NOTE – These rules ensure that an integer value is always encoded in the smallest possible number of octets.
        if let first = dataBytes.first, let second = dataBytes.dropFirst().first {
            if (first == 0xFF) && second._topBitSet ||
                (first == 0x00) && !second._topBitSet {
                throw ASN1Error.invalidASN1IntegerEncoding(reason: "INTEGER not encoded in fewest number of octets")
            }
        }

        // If the type we're trying to decode is unsigned, and the top byte is zero, we should strip it.
        // If the top bit is set, however, this is an invalid conversion: the number needs to be positive!
        if !Self.isSigned, let first = dataBytes.first {
            if first == 0x00 {
                dataBytes = dataBytes.dropFirst()
            } else if first & 0x80 == 0x80 {
                throw ASN1Error.invalidASN1IntegerEncoding(reason: "INTEGER encoded with top bit set!")
            }
        }

        self = try Self(derIntegerBytes: dataBytes)
    }

    @inlinable
    public func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        coder.appendPrimitiveNode(identifier: identifier) { bytes in
            self.withBigEndianIntegerBytes { integerBytes in
                // If the number of bytes is 0, we're encoding a zero. That actually _does_ require one byte.
                if integerBytes.count == 0 {
                    bytes.append(0)
                    return
                }

                // If self is unsigned and the first byte has the top bit set, we need to prepend a 0 byte.
                if !Self.isSigned, let topByte = integerBytes.first, topByte._topBitSet {
                    bytes.append(0)
                    bytes.append(contentsOf: integerBytes)
                } else {
                    // Either self is signed, or the top bit isn't set. Either way, trim to make sure the representation is minimal.
                    bytes.append(contentsOf: integerBytes._trimLeadingExcessBytes())
                }
            }
        }
    }
}

// MARK: - Auto-conformance for FixedWidthInteger with fixed width magnitude.
extension ASN1IntegerRepresentable where Self: FixedWidthInteger {
    @inlinable
    public init(derIntegerBytes bytes: ArraySlice<UInt8>) throws {
        // Defer to the FixedWidthInteger constructor.
        // There's a wrinkle here: if this is a signed integer, and the top bit of the data bytes was set,
        // then we need to 1-extend the bytes. This is because ASN.1 tries to delete redundant bytes that
        // are all 1.
        self = try Self(bigEndianBytes: bytes)

        if Self.isSigned, let first = bytes.first, first._topBitSet {
            for shift in stride(from: self.bitWidth - self.leadingZeroBitCount, to: self.bitWidth, by: 8) {
                self |= 0xFF << shift
            }
        }
    }

    @inlinable
    public func withBigEndianIntegerBytes<ReturnType>(_ body: (IntegerBytesCollection<Self>) throws -> ReturnType) rethrows -> ReturnType {
        return try body(IntegerBytesCollection(self))
    }
}

/// A big-endian `Collection` of bytes representing a fixed width integer.
public struct IntegerBytesCollection<Integer: FixedWidthInteger & Sendable> {
    @usableFromInline var integer: Integer

    /// Construct an ``IntegerBytesCollection`` representing the bytes of this integer.
    @inlinable
    public init(_ integer: Integer) {
        self.integer = integer
    }
}

extension IntegerBytesCollection: Hashable { }

extension IntegerBytesCollection: Sendable { }

extension IntegerBytesCollection: RandomAccessCollection {
    public struct Index {
        @usableFromInline
        var _byteNumber: Int

        @inlinable
        init(byteNumber: Int) {
            self._byteNumber = byteNumber
        }

        @inlinable
        var _shift: Integer {
            // As byte number 0 is the end index, the byte number is one byte too large for the shift.
            return Integer((self._byteNumber - 1) * 8)
        }
    }

    @inlinable
    public var startIndex: Index {
        return Index(byteNumber: Int(self.integer.neededBytes))
    }

    @inlinable
    public var endIndex: Index {
        return Index(byteNumber: 0)
    }

    @inlinable
    public var count: Int {
        return Int(self.integer.neededBytes)
    }

    @inlinable
    public subscript(index: Index) -> UInt8 {
        // We perform the bitwise operations in magnitude space.
        let shifted = Integer.Magnitude(truncatingIfNeeded: self.integer) >> index._shift
        let masked = shifted & 0xFF
        return UInt8(masked)
    }
}

extension IntegerBytesCollection.Index: Hashable { }

extension IntegerBytesCollection.Index: Sendable { }

extension IntegerBytesCollection.Index: Comparable {
    // Comparable here is backwards to the original ordering.
    @inlinable
    public static func <(lhs: Self, rhs: Self) -> Bool {
        return lhs._byteNumber > rhs._byteNumber
    }

    @inlinable
    public static func >(lhs: Self, rhs: Self) -> Bool {
        return lhs._byteNumber < rhs._byteNumber
    }

    @inlinable
    public static func <=(lhs: Self, rhs: Self) -> Bool {
        return lhs._byteNumber >= rhs._byteNumber
    }

    @inlinable
    public static func >=(lhs: Self, rhs: Self) -> Bool {
        return lhs._byteNumber <= rhs._byteNumber
    }
}

extension IntegerBytesCollection.Index: Strideable {
    @inlinable
    public func advanced(by n: Int) -> IntegerBytesCollection<Integer>.Index {
        return IntegerBytesCollection.Index(byteNumber: self._byteNumber - n)
    }

    @inlinable
    public func distance(to other: IntegerBytesCollection<Integer>.Index) -> Int {
        // Remember that early indices have high byte numbers and later indices have low ones.
        return self._byteNumber - other._byteNumber
    }
}

extension Int8: ASN1IntegerRepresentable { }

extension UInt8: ASN1IntegerRepresentable { }

extension Int16: ASN1IntegerRepresentable { }

extension UInt16: ASN1IntegerRepresentable { }

extension Int32: ASN1IntegerRepresentable { }

extension UInt32: ASN1IntegerRepresentable { }

extension Int64: ASN1IntegerRepresentable { }

extension UInt64: ASN1IntegerRepresentable { }

extension Int: ASN1IntegerRepresentable { }

extension UInt: ASN1IntegerRepresentable { }

extension RandomAccessCollection where Element == UInt8 {
    @inlinable
    func _trimLeadingExcessBytes() -> SubSequence {
        var slice = self[...]
        guard let first = slice.first else {
            // Easy case, empty.
            return slice
        }

        let wholeByte: UInt8

        switch first {
        case 0:
            wholeByte = 0
        case 0xFF:
            wholeByte = 0xFF
        default:
            // We're already fine, this is maximally compact. We need the whole thing.
            return slice
        }

        // We never trim this to less than one byte, as that's always the smallest representation.
        while slice.count > 1 {
            // If the first byte is equal to our original first byte, and the top bit
            // of the next byte is also equal to that, then we need to drop the byte and
            // go again.
            if slice.first != wholeByte {
                break
            }

            guard let second = slice.dropFirst().first else {
                preconditionFailure("Loop condition violated: must be at least two bytes left")
            }

            if second & 0x80 != wholeByte & 0x80 {
                // Different top bit, we need the leading byte.
                break
            }

            // Both the first byte and the top bit of the next are all zero or all 1, drop the leading
            // byte.
            slice = slice.dropFirst()
        }

        return slice
    }
}

extension UInt8 {
    @inlinable
    var _topBitSet: Bool {
        return (self & 0x80) != 0
    }
}
