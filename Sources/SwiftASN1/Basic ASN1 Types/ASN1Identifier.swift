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

/// An ``ASN1Identifier`` is a representation of the abstract notion of an ASN.1 identifier.
public struct ASN1Identifier {
    /// The base tag.
    public var tagNumber: UInt

    /// The class of the tag.
    public var tagClass: TagClass

    @inlinable
    var _shortForm: UInt8? {
        // An ASN.1 identifier can be encoded in short form iff the tag number is strictly
        // less than 0x1f.
        guard self.tagNumber < 0x1f else { return nil }

        var baseNumber = UInt8(truncatingIfNeeded: self.tagNumber)
        baseNumber |= self.tagClass._topByteFlags
        return baseNumber
    }

    /// The class of an ASN.1 tag.
    public enum TagClass: Hashable, Sendable {
        case universal
        case application
        case contextSpecific
        case `private`

        @inlinable
        init(topByteInWireFormat topByte: UInt8) {
            switch topByte >> 6 {
            case 0x00:
                self = .universal
            case 0x01:
                self = .application
            case 0x02:
                self = .contextSpecific
            case 0x03:
                self = .private
            default:
                fatalError("Unreachable")
            }
        }

        @inlinable
        var _topByteFlags: UInt8 {
            switch self {
            case .universal:
                return 0x00
            case .application:
                return 0x01 << 6
            case .contextSpecific:
                return 0x02 << 6
            case .private:
                return 0x03 << 6
            }
        }
    }

    @inlinable
    init(shortIdentifier: UInt8) {
        precondition(shortIdentifier & 0x1F != 0x1F)
        self.tagClass = TagClass(topByteInWireFormat: shortIdentifier)
        self.tagNumber = UInt(shortIdentifier & 0x1f)
    }

    /// Produces a tag from components.
    ///
    /// This is equivalent to ``init(tagWithNumber:tagClass:constructed:)``, but sets
    /// `constructed` to `true` in all cases.
    ///
    /// - parameters:
    ///     - number: The tag number.
    ///     - tagClass: The class of the ASN.1 tag.
    ///     - constructed: Whether this is a constructed tag.
    @inlinable
    public init(tagWithNumber number: UInt, tagClass: TagClass) {
        self.tagNumber = number
        self.tagClass = tagClass
    }
}

extension ASN1Identifier {
    /// This tag represents an OBJECT IDENTIFIER.
    public static let objectIdentifier = ASN1Identifier(shortIdentifier: 0x06)

    /// This tag represents a BIT STRING.
    public static let bitString = ASN1Identifier(shortIdentifier: 0x03)

    /// This tag represents an OCTET STRING.
    public static let octetString = ASN1Identifier(shortIdentifier: 0x04)

    /// This tag represents an INTEGER.
    public static let integer = ASN1Identifier(shortIdentifier: 0x02)

    /// This tag represents a SEQUENCE or SEQUENCE OF.
    public static let sequence = ASN1Identifier(shortIdentifier: 0x30)

    /// This tag represents a SET or SET OF.
    public static let set = ASN1Identifier(shortIdentifier: 0x31)

    /// This tag represents an ASN.1 NULL.
    public static let null = ASN1Identifier(shortIdentifier: 0x05)

    /// This tag represents a BOOLEAN.
    public static let boolean = ASN1Identifier(shortIdentifier: 0x01)

    /// This tag represents an ENUMERATED.
    public static let enumerated = ASN1Identifier(shortIdentifier: 0x0a)

    /// This tag represents a UTF8STRING.
    public static let utf8String = ASN1Identifier(shortIdentifier: 0x0c)

    /// This tag represents a NumericString.
    public static let numericString = ASN1Identifier(shortIdentifier: 0x12)

    /// This tag represents a PrintableString.
    public static let printableString = ASN1Identifier(shortIdentifier: 0x13)

    /// This tag represents a TeletexString.
    public static let teletexString = ASN1Identifier(shortIdentifier: 0x14)

    /// This tag represents a VideotexString.
    public static let videotexString = ASN1Identifier(shortIdentifier: 0x15)

    /// This tag represents an IA5String.
    public static let ia5String = ASN1Identifier(shortIdentifier: 0x16)

    /// This tag represents a GraphicString.
    public static let graphicString = ASN1Identifier(shortIdentifier: 0x19)

    /// This tag represents a VisibleString.
    public static let visibleString = ASN1Identifier(shortIdentifier: 0x1a)

    /// This tag represents a GeneralString.
    public static let generalString = ASN1Identifier(shortIdentifier: 0x1b)

    /// This tag represents a UniversalString.
    public static let universalString = ASN1Identifier(shortIdentifier: 0x1c)

    /// This tag represents a BMPString.
    public static let bmpString = ASN1Identifier(shortIdentifier: 0x1e)

    /// This tag represents a GeneralizedTime.
    public static let generalizedTime = ASN1Identifier(shortIdentifier: 0x18)

    /// This tag represents a UTCTime.
    public static let utcTime = ASN1Identifier(shortIdentifier: 0x17)
}

extension ASN1Identifier: Hashable { }

extension ASN1Identifier: Sendable { }

extension ASN1Identifier: CustomStringConvertible {
    @inlinable
    public var description: String {
        return "ASN1Identifier(tagNumber: \(self.tagNumber), tagClass: \(self.tagClass))"
    }
}

extension Array where Element == UInt8 {
    @inlinable
    mutating func writeIdentifier(_ identifier: ASN1Identifier, constructed: Bool) {
        if var shortForm = identifier._shortForm {
            if constructed {
                shortForm |= 0x20
            }
            self.append(shortForm)
        } else {
            // Long-form encoded. The top byte is 0x1f plus the various flags.
            var topByte = UInt8(0x1f)
            if constructed {
                topByte |= 0x20
            }
            topByte |= identifier.tagClass._topByteFlags
            self.append(topByte)

            // Then we encode this in base128, just like an OID subidentifier.
            // TODO: Adjust the ASN1Identifier to use UInt for its storage.
            self.writeUsing7BitBytesASN1Discipline(unsignedInteger: UInt(identifier.tagNumber))
        }
    }
}
