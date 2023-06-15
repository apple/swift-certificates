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

/// A UTF8String represents a string made up of UTF-8 bytes.
public struct ASN1UTF8String: DERImplicitlyTaggable, Hashable, Sendable, ExpressibleByStringLiteral {
    @inlinable
    public static var defaultIdentifier: ASN1Identifier {
        .utf8String
    }

    /// The raw bytes that make up this string.
    public var bytes: ArraySlice<UInt8>

    @inlinable
    public init(derEncoded node: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self.bytes = try ASN1OctetString(derEncoded: node, withIdentifier: identifier).bytes
    }

    /// Construct a UTF8STRING from raw bytes.
    @inlinable
    public init(contentBytes: ArraySlice<UInt8>) {
        self.bytes = contentBytes
    }

    @inlinable
    public init(stringLiteral value: StringLiteralType) {
        self.bytes = ArraySlice(value.utf8)
    }

    /// Construct a UTF8STRING from a String.
    @inlinable
    public init(_ string: String) {
        self.bytes = ArraySlice(string.utf8)
    }

    @inlinable
    public func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        let octet = ASN1OctetString(contentBytes: self.bytes)
        try octet.serialize(into: &coder, withIdentifier: identifier)
    }

    @inlinable
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        return try self.bytes.withUnsafeBytes(body)
    }
}

/// TeletexString is an uncommon ASN.1 string type.
///
/// This module represents a TeletexString as an opaque sequence of bytes.
public struct ASN1TeletexString: DERImplicitlyTaggable, Hashable, Sendable, ExpressibleByStringLiteral {
    @inlinable
    public static var defaultIdentifier: ASN1Identifier {
        .teletexString
    }

    /// The raw bytes that make up this string.
    public var bytes: ArraySlice<UInt8>

    @inlinable
    public init(derEncoded node: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self.bytes = try ASN1OctetString(derEncoded: node, withIdentifier: identifier).bytes
    }

    /// Construct a TeletexString from raw bytes.
    @inlinable
    public init(contentBytes: ArraySlice<UInt8>) {
        self.bytes = contentBytes
    }

    @inlinable
    public init(stringLiteral value: StringLiteralType) {
        self.bytes = ArraySlice(value.utf8)
    }

    @inlinable
    public func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        let octet = ASN1OctetString(contentBytes: self.bytes)
        try octet.serialize(into: &coder, withIdentifier: identifier)
    }

    @inlinable
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        return try self.bytes.withUnsafeBytes(body)
    }
}

/// PrintableString represents a String made up of bytes that can reliably be printed in a terminal.
///
/// This string will be validated when it is constructed, and will reject characters outside of this
/// space.
///
/// PrintableString is deprecated for most use-cases and generally ``ASN1UTF8String`` should be
/// preferred.
public struct ASN1PrintableString: DERImplicitlyTaggable, Hashable, Sendable, ExpressibleByStringLiteral {
    @inlinable
    public static var defaultIdentifier: ASN1Identifier {
        .printableString
    }

    /// The raw bytes that make up this string.
    public var bytes: ArraySlice<UInt8> {
        didSet {
            precondition(Self._isValid(self.bytes))
        }
    }

    @inlinable
    public init(derEncoded node: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self.bytes = try ASN1OctetString(derEncoded: node, withIdentifier: identifier).bytes
        guard Self._isValid(self.bytes) else {
            throw ASN1Error.invalidStringRepresentation(reason: "Invalid bytes for ASN1PrintableString")
        }
    }

    /// Construct a PrintableString from raw bytes.
    @inlinable
    public init(contentBytes: ArraySlice<UInt8>) throws {
        self.bytes = contentBytes
        guard Self._isValid(self.bytes) else {
            throw ASN1Error.invalidStringRepresentation(reason: "Invalid bytes for ASN1PrintableString")
        }
    }

    @inlinable
    public init(stringLiteral value: StringLiteralType) {
        self.bytes = ArraySlice(value.utf8)
        precondition(Self._isValid(self.bytes))
    }

    /// Construct a PrintableString from a String.
    @inlinable
    public init(_ string: String) throws {
        self.bytes = ArraySlice(string.utf8)

        guard Self._isValid(self.bytes) else {
            throw ASN1Error.invalidStringRepresentation(reason: "Invalid bytes for ASN1PrintableString")
        }
    }

    @inlinable
    public func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        let octet = ASN1OctetString(contentBytes: self.bytes)
        try octet.serialize(into: &coder, withIdentifier: identifier)
    }

    @inlinable
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        return try self.bytes.withUnsafeBytes(body)
    }

    @inlinable
    static func _isValid(_ bytes: ArraySlice<UInt8>) -> Bool {
        bytes.allSatisfy {
            switch $0 {
            case UInt8(ascii: "a")...UInt8(ascii: "z"),
                UInt8(ascii: "A")...UInt8(ascii: "Z"),
                UInt8(ascii: "0")...UInt8(ascii: "9"),
                UInt8(ascii: "'"), UInt8(ascii: "("),
                UInt8(ascii: ")"), UInt8(ascii: "+"),
                UInt8(ascii: "-"), UInt8(ascii: "?"),
                UInt8(ascii: ":"), UInt8(ascii: "/"),
                UInt8(ascii: "="), UInt8(ascii: " "),
                UInt8(ascii: ","), UInt8(ascii: "."):
                return true
            default:
                return false
            }
        }
    }
}

/// UniversalString is an uncommon ASN.1 string type.
///
/// This module represents a UniversalString as an opaque sequence of bytes.
public struct ASN1UniversalString: DERImplicitlyTaggable, Hashable, Sendable, ExpressibleByStringLiteral {
    @inlinable
    public static var defaultIdentifier: ASN1Identifier {
        .universalString
    }

    /// The raw bytes that make up this string.
    public var bytes: ArraySlice<UInt8>

    @inlinable
    public init(derEncoded node: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self.bytes = try ASN1OctetString(derEncoded: node, withIdentifier: identifier).bytes
    }

    /// Construct a UniversalString from raw bytes.
    @inlinable
    public init(contentBytes: ArraySlice<UInt8>) {
        self.bytes = contentBytes
    }

    @inlinable
    public init(stringLiteral value: StringLiteralType) {
        self.bytes = ArraySlice(value.utf8)
    }

    @inlinable
    public func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        let octet = ASN1OctetString(contentBytes: self.bytes)
        try octet.serialize(into: &coder, withIdentifier: identifier)
    }

    @inlinable
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        return try self.bytes.withUnsafeBytes(body)
    }
}

/// BMPString is an uncommon ASN.1 string type.
///
/// This module represents a BMPString as an opaque sequence of bytes.
public struct ASN1BMPString: DERImplicitlyTaggable, Hashable, Sendable, ExpressibleByStringLiteral {
    @inlinable
    public static var defaultIdentifier: ASN1Identifier {
        .bmpString
    }

    /// The raw bytes that make up this string.
    public var bytes: ArraySlice<UInt8>

    @inlinable
    public init(derEncoded node: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self.bytes = try ASN1OctetString(derEncoded: node, withIdentifier: identifier).bytes
    }

    /// Construct a BMPString from raw bytes.
    @inlinable
    public init(contentBytes: ArraySlice<UInt8>) {
        self.bytes = contentBytes
    }

    @inlinable
    public init(stringLiteral value: StringLiteralType) {
        self.bytes = ArraySlice(value.utf8)
    }

    @inlinable
    public func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        let octet = ASN1OctetString(contentBytes: self.bytes)
        try octet.serialize(into: &coder, withIdentifier: identifier)
    }

    @inlinable
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        return try self.bytes.withUnsafeBytes(body)
    }
}

/// IA5String represents a String made up of ASCII characters.
///
/// This string will be validated when it is constructed, and will reject characters outside of this
/// space.
///
/// IA5String is deprecated for most use-cases and generally ``ASN1UTF8String`` should be
/// preferred.
public struct ASN1IA5String: DERImplicitlyTaggable, Hashable, Sendable, ExpressibleByStringLiteral {
    @inlinable
    public static var defaultIdentifier: ASN1Identifier {
        .ia5String
    }

    /// The raw bytes that make up this string.
    public var bytes: ArraySlice<UInt8> {
        didSet {
            precondition(Self._isValid(self.bytes))
        }
    }

    @inlinable
    public init(derEncoded node: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self.bytes = try ASN1OctetString(derEncoded: node, withIdentifier: identifier).bytes
        guard Self._isValid(self.bytes) else {
            throw ASN1Error.invalidStringRepresentation(reason: "Invalid bytes for ASN1IA5String")
        }
    }

    /// Construct an IA5String from raw bytes.
    @inlinable
    public init(contentBytes: ArraySlice<UInt8>) throws {
        self.bytes = contentBytes
        guard Self._isValid(self.bytes) else {
            throw ASN1Error.invalidStringRepresentation(reason: "Invalid bytes for ASN1IA5String")
        }
    }

    @inlinable
    public init(stringLiteral value: StringLiteralType) {
        self.bytes = ArraySlice(value.utf8)
        precondition(Self._isValid(self.bytes))
    }

    /// Construct an IA5String from a String.
    @inlinable
    public init(_ string: String) throws {
        self.bytes = ArraySlice(string.utf8)

        guard Self._isValid(self.bytes) else {
            throw ASN1Error.invalidStringRepresentation(reason: "Invalid bytes for ASN1IA5String")
        }
    }
    @inlinable
    public func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        let octet = ASN1OctetString(contentBytes: self.bytes)
        try octet.serialize(into: &coder, withIdentifier: identifier)
    }

    @inlinable
    public func withUnsafeBytes<R>(_ body: (UnsafeRawBufferPointer) throws -> R) rethrows -> R {
        return try self.bytes.withUnsafeBytes(body)
    }

    @inlinable
    static func _isValid(_ bytes: ArraySlice<UInt8>) -> Bool {
        // Valid IA5Strings are ASCII characters.
        bytes.allSatisfy { $0 < 128 }
    }
}

extension String {
    /// Construct a `String` from an ``ASN1UTF8String``.
    public init(_ utf8String: ASN1UTF8String) {
        self = String(decoding: utf8String.bytes, as: UTF8.self)
    }

    /// Construct a `String` from an ``ASN1PrintableString``.
    public init(_ printableString: ASN1PrintableString) {
        self = String(decoding: printableString.bytes, as: UTF8.self)
    }

    /// Construct a `String` from an ``ASN1IA5String``.
    public init(_ ia5String: ASN1IA5String) {
        self = String(decoding: ia5String.bytes, as: UTF8.self)
    }
}
