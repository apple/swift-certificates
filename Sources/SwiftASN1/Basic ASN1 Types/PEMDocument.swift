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

#if canImport(Foundation)
import Foundation

/// Defines a type that can be serialized in PEM-encoded form.
///
/// Users implementing this type are expected to just provide the ``defaultPEMDiscriminator``
///
/// A PEM `String` can be serialized by constructing a ``PEMDocument`` by calling ``PEMSerializable/serializeAsPEM()`` and then accessing the ``PEMDocument/pemString`` preropty.
public protocol PEMSerializable: DERSerializable {
    /// The PEM discriminator identifying this object type.
    ///
    /// The PEM discriminator is in the first line of a PEM string after `BEGIN` and at the end of the string after `END` e.g.
    /// ```
    /// -----BEGIN defaultPEMDiscriminator-----
    /// <base 64 DER representation of this object>
    /// -----END defaultPEMDiscriminator-----
    /// ```
    static var defaultPEMDiscriminator: String { get }
    
    func serializeAsPEM(discriminator: String) throws -> PEMDocument
}

/// Defines a type that can be parsed from a PEM-encoded form.
///
/// Users implementing this type are expected to just provide the ``defaultPEMDiscriminator``.
///
/// Objects that are ``PEMParseable`` can be construct from a PEM `String` through ``PEMParseable/init(pemEncoded:)``.
public protocol PEMParseable: DERParseable {
    /// The PEM discriminator identifying this object type.
    ///
    /// The PEM discriminator is in the first line of a PEM string after `BEGIN` and at the end of the string after `END` e.g.
    /// ```
    /// -----BEGIN defaultPEMDiscriminator-----
    /// <base 64 DER representation of this object>
    /// -----END defaultPEMDiscriminator-----
    /// ```
    static var defaultPEMDiscriminator: String { get }
    
    init(pemDocument: PEMDocument) throws
}

/// Defines a type that can be serialized in and parsed from PEM-encoded form.
///
/// Users implementing this type are expected to just provide the ``PEMParseable/defaultPEMDiscriminator``.
///
/// Objects that are ``PEMRepresentable`` can be construct from a PEM `String` through ``PEMParseable/init(pemEncoded:)``.
///
/// A PEM `String` can be serialized by constructing a ``PEMDocument`` by calling ``PEMSerializable/serializeAsPEM()`` and then accessing the ``PEMDocument/pemString`` preropty.
public typealias PEMRepresentable = PEMSerializable & PEMParseable

extension PEMParseable {
    
    /// Initialize this object from a serialized PEM representation.
    /// 
    /// This will check that the discriminator matches ``PEMParseable/defaultPEMDiscriminator``, decode the base64 encoded string and
    /// then decode the DER encoded bytes using ``DERParseable/init(derEncoded:)-i2rf``.
    ///
    /// - parameters:
    ///     - pemEncoded: The PEM-encoded string representing this object.
    @inlinable
    public init(pemEncoded pemString: String) throws {
        try self.init(pemDocument: try PEMDocument(pemString: pemString))
    }
    
    /// Initialize this object from a serialized PEM representation.
    /// This will check that the ``PEMParseable/pemDiscriminator`` matches and
    /// forward the DER encoded bytes to ``DERParseable/init(derEncoded:)-i2rf``.
    ///
    /// - parameters:
    ///     - pemDocument: DER-encoded PEM document
    @inlinable
    public init(pemDocument: PEMDocument) throws {
        guard pemDocument.discriminator == Self.defaultPEMDiscriminator else {
            throw ASN1Error.invalidPEMDocument(reason: "PEMDocument has incorrect discriminator \(pemDocument.discriminator). Expected \(Self.defaultPEMDiscriminator) instead")
        }
            
        try self.init(derEncoded: pemDocument.derBytes)
    }
}

extension PEMSerializable {
    /// Serializes `self` as a PEM document with given `discriminator`.
    /// - Parameter discriminator: PEM discriminator used in for the BEGIN and END encapsulation boundaries.
    /// - Returns: DER encoded PEM document
    @inlinable
    public func serializeAsPEM(discriminator: String) throws -> PEMDocument {
        var serializer = DER.Serializer()
        try serializer.serialize(self)
        
        return PEMDocument(type: discriminator, derBytes: serializer.serializedBytes)
    }
    
    /// Serializes `self` as a PEM document with the ``defaultPEMDiscriminator``.
    @inlinable
    public func serializeAsPEM() throws -> PEMDocument {
        try self.serializeAsPEM(discriminator: Self.defaultPEMDiscriminator)
    }
}

/// A PEM document is some data, and a discriminator type that is used to advertise the content.
public struct PEMDocument: Hashable, Sendable {
    fileprivate static let lineLength = 64

    
    @available(*, deprecated, renamed: "discriminator")
    public var type: String {
        get { discriminator }
        set { discriminator = newValue }
    }
    
    /// The PEM discriminator is in the first line of a PEM string after `BEGIN` and at the end of the string after `END` e.g.
    /// ```
    /// -----BEGIN discriminator-----
    /// <base 64 encoded derBytes>
    /// -----END discriminator-----
    /// ```
    public var discriminator: String
    
    public var derBytes: [UInt8]

    public init(pemString: String) throws {
        // A PEM document looks like this:
        //
        // -----BEGIN <SOME DISCRIMINATOR>-----
        // <base64 encoded bytes, 64 characters per line>
        // -----END <SOME DISCRIMINATOR>-----
        //
        // This function attempts to parse this string as a PEM document, and returns the discriminator type
        // and the base64 decoded bytes.
        var lines = pemString.split { $0.isNewline }[...]
        guard let first = lines.first, let last = lines.last else {
            throw ASN1Error.invalidPEMDocument(reason: "Leading or trailing line missing.")
        }

        guard let discriminator = first.pemStartDiscriminator, discriminator == last.pemEndDiscriminator else {
            throw ASN1Error.invalidPEMDocument(reason: "Leading or trailing line missing PEM discriminator")
        }

        // All but the last line must be 64 bytes. The force unwrap is safe because we require the lines to be
        // greater than zero.
        lines = lines.dropFirst().dropLast()
        guard lines.count > 0,
            lines.dropLast().allSatisfy({ $0.utf8.count == PEMDocument.lineLength }),
            lines.last!.utf8.count <= PEMDocument.lineLength else {
            throw ASN1Error.invalidPEMDocument(reason: "PEMDocument has incorrect line lengths")
        }

        guard let derBytes = Data(base64Encoded: lines.joined()) else {
            throw ASN1Error.invalidPEMDocument(reason: "PEMDocument not correctly base64 encoded")
        }

        self.discriminator = discriminator
        self.derBytes = Array(derBytes)
    }

    public init(type: String, derBytes: [UInt8]) {
        self.discriminator = type
        self.derBytes = derBytes
    }

    /// PEM string is a base 64 encoded string of ``derBytes`` enclosed in BEGIN and END encapsulation boundaries with the specified ``discriminator`` type.
    ///
    /// Example PEM string:
    /// ```
    /// -----BEGIN discriminator-----
    /// <base 64 encoded derBytes>
    /// -----END discriminator-----
    /// ```
    public var pemString: String {
        var encoded = Data(self.derBytes).base64EncodedString()[...]
        let pemLineCount = (encoded.utf8.count + Self.lineLength) / Self.lineLength
        var pemLines = [Substring]()
        pemLines.reserveCapacity(pemLineCount + 2)

        pemLines.append("-----BEGIN \(self.discriminator)-----")

        while encoded.count > 0 {
            let prefixIndex = encoded.index(encoded.startIndex, offsetBy: Self.lineLength, limitedBy: encoded.endIndex) ?? encoded.endIndex
            pemLines.append(encoded[..<prefixIndex])
            encoded = encoded[prefixIndex...]
        }

        pemLines.append("-----END \(self.discriminator)-----")

        return pemLines.joined(separator: "\n")
    }
}

extension Substring {
    fileprivate var pemStartDiscriminator: String? {
        return self.pemDiscriminator(expectedPrefix: "-----BEGIN ", expectedSuffix: "-----")
    }

    fileprivate var pemEndDiscriminator: String? {
        return self.pemDiscriminator(expectedPrefix: "-----END ", expectedSuffix: "-----")
    }

    private func pemDiscriminator(expectedPrefix: String, expectedSuffix: String) -> String? {
        var utf8Bytes = self.utf8[...]

        // We want to split this sequence into three parts: the prefix, the middle, and the end
        let prefixSize = expectedPrefix.utf8.count
        let suffixSize = expectedSuffix.utf8.count

        let prefix = utf8Bytes.prefix(prefixSize)
        utf8Bytes = utf8Bytes.dropFirst(prefixSize)
        let suffix = utf8Bytes.suffix(suffixSize)
        utf8Bytes = utf8Bytes.dropLast(suffixSize)

        guard prefix.elementsEqual(expectedPrefix.utf8), suffix.elementsEqual(expectedSuffix.utf8) else {
            return nil
        }

        return String(utf8Bytes)
    }
}

#endif
