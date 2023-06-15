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

/// An Object Identifier is a representation of some kind of object.
///
/// It represents a node in an OID hierarchy, and is usually represented as an ordered sequence of numbers. Object identifiers
/// form a nested tree of namespaces.
///
/// The most common way to construct an OID is to create one using an array literal. For example, the OID 2.5.4.41 can be created
/// as:
///
/// ```swift
/// let name: ASN1ObjectIdentifier = [2, 5, 4, 41]
/// ```
///
/// This object also has a number of pre-existing values defined in namespaces. Users are encouraged to create their own namespaces to
/// make it easier to use OIDs in their own serialization code.
public struct ASN1ObjectIdentifier: DERImplicitlyTaggable {
    @inlinable
    public static var defaultIdentifier: ASN1Identifier {
        .objectIdentifier
    }

    @usableFromInline
    var _oidComponents: [UInt]

    @inlinable
    public init(derEncoded node: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        guard node.identifier == identifier else {
            throw ASN1Error.unexpectedFieldType(node.identifier)
        }

        guard case .primitive(var content) = node.content else {
            preconditionFailure("ASN.1 parser generated primitive node with constructed content")
        }

        // We have to parse the content. From the spec:
        //
        // > Each subidentifier is represented as a series of (one or more) octets. Bit 8 of each octet indicates whether it
        // > is the last in the series: bit 8 of the last octet is zero, bit 8 of each preceding octet is one. Bits 7 to 1 of
        // > the octets in the series collectively encode the subidentifier. Conceptually, these groups of bits are concatenated
        // > to form an unsigned binary number whose most significant bit is bit 7 of the first octet and whose least significant
        // > bit is bit 1 of the last octet. The subidentifier shall be encoded in the fewest possible octets[...].
        // >
        // > The number of subidentifiers (N) shall be one less than the number of object identifier components in the object identifier
        // > value being encoded.
        // >
        // > The numerical value of the first subidentifier is derived from the values of the first _two_ object identifier components
        // > in the object identifier value being encoded, using the formula:
        // >
        // >  (X*40) + Y
        // >
        // > where X is the value of the first object identifier component and Y is the value of the second object identifier component.
        //
        // Yeah, this is a bit bananas, but basically there are only 3 first OID components (0, 1, 2) and there are no more than 39 children
        // of nodes 0 or 1. In my view this is too clever by half, but the ITU.T didn't ask for my opinion when they were coming up with this
        // scheme, likely because I was in middle school at the time.
        var subcomponents = [UInt]()
        while content.count > 0 {
            subcomponents.append(try content.readUIntUsing8BitBytesASN1Discipline())
        }

        // Now we need to expand the subcomponents out. This means we need to undo the step above. We can do this by
        // taking the quotient and remainder when dividing by 40.
        var oidComponents = [UInt]()
        oidComponents.reserveCapacity(subcomponents.count + 1)

        // We'd like to work on the slice here.
        var subcomponentSlice = subcomponents[...]
        guard let firstEncodedSubcomponent = subcomponentSlice.popFirst() else {
            throw ASN1Error.invalidASN1Object(reason: "Zero components in OID")
        }

        let (firstSubcomponent, secondSubcomponent) = firstEncodedSubcomponent.quotientAndRemainder(dividingBy: 40)
        oidComponents.append(firstSubcomponent)
        oidComponents.append(secondSubcomponent)
        oidComponents.append(contentsOf: subcomponentSlice)

        self._oidComponents = oidComponents
    }

    @inlinable
    public func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        coder.appendPrimitiveNode(identifier: identifier) { bytes in
            var components = self._oidComponents[...]
            guard let firstComponent = components.popFirst(), let secondComponent = components.popFirst() else {
                preconditionFailure("Invalid number of OID components: must be at least two!")
            }

            let serializedFirstComponent = (firstComponent * 40) + secondComponent
            ASN1ObjectIdentifier._writeOIDSubidentifier(serializedFirstComponent, into: &bytes)

            while let component = components.popFirst() {
                ASN1ObjectIdentifier._writeOIDSubidentifier(component, into: &bytes)
            }
        }
    }

    @inlinable
    static func _writeOIDSubidentifier(_ identifier: UInt, into array: inout [UInt8]) {
        array.writeUsing7BitBytesASN1Discipline(unsignedInteger: identifier)
    }
}

extension ASN1ObjectIdentifier: Hashable {}

extension ASN1ObjectIdentifier: Sendable { }

extension ASN1ObjectIdentifier: ExpressibleByArrayLiteral {
    @inlinable
    public init(arrayLiteral elements: UInt...) {
        self._oidComponents = elements
    }
}

extension ASN1ObjectIdentifier: CustomStringConvertible {
    @inlinable
    public var description: String {
        self._oidComponents.map { String($0) }.joined(separator: ".")
    }
}

extension ASN1ObjectIdentifier {
    /// Represents a namespace for OIDs that identify named Elliptic Curves.
    ///
    /// These OIDs are defined in RFC 5480.
    public enum NamedCurves {
        /// Represents the NIST P256 curve. Also called `prime256v1`.
        public static let secp256r1: ASN1ObjectIdentifier = [1, 2, 840, 10_045, 3, 1, 7]

        /// Represents the NIST P384 curve.
        public static let secp384r1: ASN1ObjectIdentifier = [1, 3, 132, 0, 34]

        /// Represents the NIST P521 curve.
        public static let secp521r1: ASN1ObjectIdentifier = [1, 3, 132, 0, 35]
    }

    /// Represents a namespace for OIDs that identify an algorithm within an
    /// `AlgorithmIdentifier` object.
    public enum AlgorithmIdentifier {
        /// Identifies an elliptic curve public key.
        ///
        /// This identifier is defined in RFC 5480. `AlgorithmIdentifier` objects with this key have a parameters
        /// value defined in that RFC.
        public static let idEcPublicKey: ASN1ObjectIdentifier = [1, 2, 840, 10_045, 2, 1]

        /// Identifies a PKCS#1v1.5 RSA signature using SHA256 as the hash algorithm.
        ///
        /// This identifier is defined in RFC 4055. When used, the parameters MUST be NULL.
        public static let sha256WithRSAEncryption: ASN1ObjectIdentifier = [1, 2, 840, 11_3549, 1, 1, 11]

        /// Identifies a PKCS#1v1.5 RSA signature using SHA384 as the hash algorithm.
        ///
        /// This identifier is defined in RFC 4055. When used, the parameters MUST be NULL.
        public static let sha384WithRSAEncryption: ASN1ObjectIdentifier = [1, 2, 840, 11_3549, 1, 1, 12]

        /// Identifies a PKCS#1v1.5 RSA signature using SHA512 as the hash algorithm.
        ///
        /// This identifier is defined in RFC 4055. When used, the parameters MUST be NULL.
        public static let sha512WithRSAEncryption: ASN1ObjectIdentifier = [1, 2, 840, 11_3549, 1, 1, 13]

        /// Identifies an RSA PSS signature.
        ///
        /// This identifier is defined in RFC 4055. When used, the parameters will be `RSASSA-PSS-params` as
        /// defined in that RFC.
        public static let rsaPSS: ASN1ObjectIdentifier = [1, 2, 840, 11_3549, 1, 1, 10]

        /// Identifies an RSA public key.
        ///
        /// This identifier is defined in RFC 4055. When used, the parameters MUST be NULL.
        public static let rsaEncryption: ASN1ObjectIdentifier = [1, 2, 840, 11_3549, 1, 1, 1]
    }

    /// Represents a namespace for OIDs that identify Relative Distinguished Name components.
    ///
    /// An enormous number of these identifiers exist. A non-exhaustive list of them is available in
    /// RFC 4519.
    public enum NameAttributes {
        /// The 'name' attribute type is the attribute supertype from which user
        /// attribute types with the name syntax inherit.  Such attribute types
        /// are typically used for naming.  The attribute type is multi-valued.
        public static let name: ASN1ObjectIdentifier = [2, 5, 4, 41]

        /// The 'sn' ('surname' in X.500) attribute type contains name strings
        /// for the family names of a person.
        public static let surname: ASN1ObjectIdentifier = [2, 5, 4, 4]

        /// The 'givenName' attribute type contains name strings that are the
        /// part of a person's name that is not their surname.
        public static let givenName: ASN1ObjectIdentifier = [2, 5, 4, 42]

        /// The 'initials' attribute type contains strings of initials of some or
        /// all of an individual's names, except the surname(s).
        public static let initials: ASN1ObjectIdentifier = [2, 5, 4, 43]

        /// The 'generationQualifier' attribute type contains name strings that
        /// are typically the suffix part of a person's name.
        public static let generationQualifier: ASN1ObjectIdentifier = [2, 5, 4, 44]

        /// The 'cn' ('commonName' in X.500) attribute type contains names of an
        /// object.  If the object corresponds to a person, it is typically the person's full
        /// name.
        ///
        /// In modern usage, the common name typically represents a general identifier of an actor.
        public static let commonName: ASN1ObjectIdentifier = [2, 5, 4, 3]

        /// The 'l' ('localityName' in X.500) attribute type contains names of a
        /// locality or place, such as a city, county, or other geographic
        /// region.
        public static let localityName: ASN1ObjectIdentifier = [2, 5, 4, 7]

        /// The 'st' ('stateOrProvinceName' in X.500) attribute type contains the
        /// full names of states or provinces.
        public static let stateOrProvinceName: ASN1ObjectIdentifier = [2, 5, 4, 8]

        /// The 'o' ('organizationName' in X.500) attribute type contains the
        /// names of an organization.
        public static let organizationName: ASN1ObjectIdentifier = [2, 5, 4, 10]

        /// The 'ou' ('organizationalUnitName' in X.500) attribute type contains
        /// the names of an organizational unit.
        public static let organizationalUnitName: ASN1ObjectIdentifier = [2, 5, 4, 11]

        /// The 'title' attribute type contains the title of a person in their
        /// organizational context.
        public static let title: ASN1ObjectIdentifier = [2, 5, 4, 12]

        /// The 'dnQualifier' attribute type contains disambiguating information
        /// strings to add to the relative distinguished name of an entry.  The
        /// information is intended for use when merging data from multiple
        /// sources in order to prevent conflicts between entries that would
        /// otherwise have the same name.
        public static let dnQualifier: ASN1ObjectIdentifier = [2, 5, 4, 46]

        /// The 'c' ('countryName' in X.500) attribute type contains a two-letter
        /// ISO 3166 [ISO3166] country code.
        public static let countryName: ASN1ObjectIdentifier = [2, 5, 4, 6]

        /// The 'serialNumber' attribute type contains the serial numbers of
        /// devices.
        public static let serialNumber: ASN1ObjectIdentifier = [2, 5, 4, 5]

        /// The pseudonym attribute type contains a pseudonym of the subject.
        public static let pseudonym: ASN1ObjectIdentifier = [2, 5, 4, 65]

        /// The 'dc' ('domainComponent' in RFC 1274) attribute type is a string
        /// holding one component, a label, of a DNS domain name naming a host.
        public static let domainComponent: ASN1ObjectIdentifier = [0, 9, 2342, 19200300, 100, 1, 25]

        /// The emailAddress attribute type specifies the electronic-mail address
        /// or addresses of a subject as an unstructured ASCII string.
        public static let emailAddress: ASN1ObjectIdentifier = [1, 2, 840, 113549, 1, 9, 1]
    }

    /// Represents a namespace for OIDs corresponding to OCSP identifiers.
    ///
    /// The meaning of these OIDs is defined in RFC 6960.
    public enum OCSP {
        /// Identifies a `BasicOCSPResponse`.
        public static let basicResponse: ASN1ObjectIdentifier = [1, 3, 6, 1, 5, 5, 7, 48, 1, 1]
    }
}

extension ArraySlice where Element == UInt8 {
    @inlinable
    mutating func readUIntUsing8BitBytesASN1Discipline() throws -> UInt {
        // In principle OID subidentifiers and long tags can be too large to fit into a UInt. We are choosing to not care about that
        // because for us it shouldn't matter.
        guard let subidentifierEndIndex = self.firstIndex(where: { $0 & 0x80 == 0x00 }) else {
            throw ASN1Error.invalidASN1Object(reason: "Invalid encoding for OID subidentifier")
        }

        let oidSlice = self[self.startIndex ... subidentifierEndIndex]

        guard let firstByte = oidSlice.first, firstByte != 0x80 else {
            // If the first byte is 0x80 then we have a leading 0 byte. All numbers encoded this way
            // need to be encoded in the minimal number of bytes, so we need to reject this.
            throw ASN1Error.invalidASN1Object(reason: "OID subidentifier encoded with leading 0 byte")
        }

        self = self[self.index(after: subidentifierEndIndex)...]

        // We need to compact the bits. These are 7-bit integers, which is really awkward.
        return try UInt(sevenBitBigEndianBytes: oidSlice)
    }
}

extension UInt {
    @inlinable
    init<Bytes: Collection>(sevenBitBigEndianBytes bytes: Bytes) throws where Bytes.Element == UInt8 {
        // We need to know how many bytes we _need_ to store this "int". As a base optimization we refuse to parse
        // anything larger than 9 bytes wide, even though conceptually we could fit a few more bits.
        guard ((bytes.count * 7) + 7) / 8 <= MemoryLayout<UInt>.size else {
            throw ASN1Error.invalidASN1Object(reason: "Unable to store OID subidentifier")
        }

        self = 0

        // Unchecked subtraction because bytes.count must be positive, so we can safely subtract 7 after the
        // multiply. The same logic applies to the math in the loop. Finally, the multiply can be unchecked because
        // we already did it above and we didn't overflow there.
        var shift = (bytes.count &* 7) &- 7

        var index = bytes.startIndex
        while shift >= 0 {
            self |= UInt(bytes[index] & 0x7F) << shift
            bytes.formIndex(after: &index)
            shift &-= 7
        }
    }
}

extension Array where Element == UInt8 {
    @inlinable
    mutating func writeUsing7BitBytesASN1Discipline(unsignedInteger identifier: UInt) {
        // An OID subidentifier or long-form tag is written as an integer over 7-bit bytes, where the last byte has the top bit unset.
        // The first thing we need is to know how many bits we need to write
        let bitsToWrite = UInt.bitWidth - identifier.leadingZeroBitCount
        let bytesToWrite = (bitsToWrite + 6) / 7

        guard bytesToWrite > 0 else {
            // Just a zero.
            self.append(0)
            return
        }

        for byteNumber in (1..<bytesToWrite).reversed() {
            let shift = byteNumber * 7
            let byte = UInt8((identifier >> shift) & 0x7f) | 0x80
            self.append(byte)
        }

        // Last byte to append here, we must unset the top bit.
        let byte = UInt8((identifier & 0x7F))
        self.append(byte)
    }
}
