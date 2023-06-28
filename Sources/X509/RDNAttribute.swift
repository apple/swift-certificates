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

extension RelativeDistinguishedName {
    /// A single attribute of a ``RelativeDistinguishedName``.
    ///
    /// A ``RelativeDistinguishedName`` is made up of one or more attributes that represent the same
    /// node in the hierarchical ``DistinguishedName`` representation. In almost all cases there is
    /// only one ``Attribute`` in a given ``RelativeDistinguishedName``.
    ///
    /// These attributes are a key-value type, with the type of the node being identified by
    /// ``type`` and the value being stored in ``value``. In the vast majority of cases the ``value``
    /// of the node will be an `ASN1PrintableString` or `ASN1UTF8String`, but the value can only
    /// be derived by inspection.
    public struct Attribute {
        public struct Value: Hashable, Sendable {
            @usableFromInline
            enum Storage: Sendable {
                /// ``ASN1PrintableString``
                case printable(String)
                /// ``ASN1UTF8String``
                case utf8(String)
                /// `.any` can still contain bytes which are equal to the DER representation of `.printable` or `.utf8`
                /// the custom `Hashable` conformance takes care of this treats them as equal.
                case any(ASN1Any)
            }
            
            @usableFromInline
            var storage: Storage
            
            @inlinable
            init(storage: Storage) {
                self.storage = storage
            }
        }
        /// The type of this attribute.
        ///
        /// Common types can be found in `ASN1ObjectIdentifier.RDNAttributeType`.
        public var type: ASN1ObjectIdentifier

        /// The value of this attribute.
        public var value: Attribute.Value

        /// Create a new attribute from a given type and value.
        ///
        /// - Parameter type: The type of the attribute.
        /// - Parameter value: The value of the attribute.
        @inlinable
        public init(type: ASN1ObjectIdentifier, value: Attribute.Value) {
            self.type = type
            self.value = value
        }
    }
}

extension RelativeDistinguishedName.Attribute.Value.Storage: Hashable {
    @inlinable
    static func ==(lhs: Self, rhs: Self) -> Bool {
        switch (lhs, rhs) {
        case let (.printable(lhs), .printable(rhs)):
            return lhs == rhs
        case let (.utf8(lhs), .utf8(rhs)):
            return lhs == rhs
        case (.printable, .utf8), (.utf8, .printable):
            return false
        default:
            return ASN1Any(lhs) == ASN1Any(rhs)
        }
    }
    
    @inlinable
    func hash(into hasher: inout Hasher) {
        // TODO: implement a ASN1UTF8StringView over a String that conforms to RandomAccessCollection and can lazily bytes that are equal to ASN1Any(ASN1UTF8String(string:))
        // same for ASN1PrintableString. This would allow us to implement `hash(into:)` without allocating, same for default case in `==` above.
        ASN1Any(self).hash(into: &hasher)
    }
}

extension ASN1Any {
    @inlinable
    init(_ storage: RelativeDistinguishedName.Attribute.Value.Storage) {
        switch storage {
        case .printable(let printableString):
            // force try is safe because we verify in the initialiser that it is valid
            self = try! .init(erasing: ASN1PrintableString(printableString))
        case .utf8(let utf8String):
            // force try is safe because we verify in the initialiser that it is valid
            self = try! .init(erasing: ASN1UTF8String(utf8String))
        case .any(let any):
            self = any
        }
    }
}

extension ASN1Any {
    @inlinable
    init(_ value: RelativeDistinguishedName.Attribute.Value) {
        self = ASN1Any(value.storage)
    }
}

extension RelativeDistinguishedName.Attribute.Value {
    /// A helper constructor to construct a ``RelativeDistinguishedName/Attribute/Value`` with an `ASN1UTF8String`.
    /// - Parameter utf8String: The value of the attribute.
    @inlinable
    public init(utf8String: String) {
        self.storage = .utf8(utf8String)
    }

    /// A helper constructor to construct a ``RelativeDistinguishedName/Attribute/Value`` with an `ASN1PrintableString`.
    /// - Parameter printableString: The value of the attribute.
    @inlinable
    public init(printableString: String) throws {
        // verify that it is indeed a printable string
        _ = try ASN1PrintableString(printableString)
        self.storage = .printable(printableString)
    }
    
    @inlinable
    public init(asn1Any: ASN1Any) {
        self.storage = .any(asn1Any)
    }
}

extension RelativeDistinguishedName.Attribute.Value: CustomStringConvertible {
    @inlinable
    public var description: String {
        let text: String
        switch storage {
        case .printable(let string), .utf8(let string):
            text = string
        case .any(let any):
            do {
                text = try String(ASN1PrintableString(asn1Any: any))
            } catch {
                do {
                    text = try String(ASN1UTF8String(asn1Any: any))
                } catch {
                    text = String(describing: any)
                }
            }
        }
        
        // This is a very slow way to do this, but until we have any evidence that
        // this is hot code I'm happy to do it slowly.
        let unescapedBytes = Array(text.utf8)
        let charsToEscape: [UInt8] = [
            UInt8(ascii: ","), UInt8(ascii: "+"), UInt8(ascii: "\""), UInt8(ascii: "\\"),
            UInt8(ascii: "<"), UInt8(ascii: ">"), UInt8(ascii: ";")]

        let leadingBytesToEscape = unescapedBytes.prefix(while: {
            $0 == UInt8(ascii: " ") || $0 == UInt8(ascii: "#")
        })

        // We don't want these ranges to overlap.
        let trailingBytesToEscape = unescapedBytes.dropFirst(leadingBytesToEscape.count).suffix(while: {
            $0 == UInt8(ascii: " ")
        })
        let middleBytes = unescapedBytes[leadingBytesToEscape.endIndex..<trailingBytesToEscape.startIndex]

        var escapedBytes = leadingBytesToEscape.flatMap { [UInt8(ascii: "\\"), $0] }
        escapedBytes += middleBytes.flatMap {
            if charsToEscape.contains($0) {
                return [UInt8(ascii: "\\"), $0]
            } else {
                return [$0]
            }
        }
        escapedBytes += trailingBytesToEscape.flatMap { [UInt8(ascii: "\\"), $0] }

        let escapedString = String(decoding: escapedBytes, as: UTF8.self)
        return escapedString
    }
}


extension RelativeDistinguishedName.Attribute: Hashable { }

extension RelativeDistinguishedName.Attribute: Sendable { }

extension RelativeDistinguishedName.Attribute: CustomStringConvertible {
    @inlinable
    public var description: String {
        let attributeKey: String
        switch self.type {
        case .RDNAttributeType.commonName:
            attributeKey = "CN"
        case .RDNAttributeType.countryName:
            attributeKey = "C"
        case .RDNAttributeType.localityName:
            attributeKey = "L"
        case .RDNAttributeType.stateOrProvinceName:
            attributeKey = "ST"
        case .RDNAttributeType.organizationName:
            attributeKey = "O"
        case .RDNAttributeType.organizationalUnitName:
            attributeKey = "OU"
        case .RDNAttributeType.streetAddress:
            attributeKey = "STREET"
        case let type:
            attributeKey = String(describing: type)
        }

        return "\(attributeKey)=\(value.description)"
    }
}


extension RelativeDistinguishedName.Attribute: DERImplicitlyTaggable {
    @inlinable
    public static var defaultIdentifier: ASN1Identifier {
        .sequence
    }

    @inlinable
    public init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let type = try ASN1ObjectIdentifier(derEncoded: &nodes)
            let anyValue = try ASN1Any(derEncoded: &nodes)
            let value: Value
            switch type {
            /// ```
            /// id-at-commonName        AttributeType ::= { id-at 3 }
            ///
            /// -- Naming attributes of type X520CommonName:
            /// --   X520CommonName ::= DirectoryName (SIZE (1..ub-common-name))
            /// --
            /// -- Expanded to avoid parameterized type:
            /// X520CommonName ::= CHOICE {
            ///       teletexString     TeletexString   (SIZE (1..ub-common-name)),
            ///       printableString   PrintableString (SIZE (1..ub-common-name)),
            ///       universalString   UniversalString (SIZE (1..ub-common-name)),
            ///       utf8String        UTF8String      (SIZE (1..ub-common-name)),
            ///       bmpString         BMPString       (SIZE (1..ub-common-name)) }
            ///
            ///
            /// -- Naming attributes of type X520LocalityName
            ///
            /// id-at-localityName      AttributeType ::= { id-at 7 }
            ///
            /// -- Naming attributes of type X520LocalityName:
            /// --   X520LocalityName ::= DirectoryName (SIZE (1..ub-locality-name))
            /// --
            /// -- Expanded to avoid parameterized type:
            /// X520LocalityName ::= CHOICE {
            ///       teletexString     TeletexString   (SIZE (1..ub-locality-name)),
            ///       printableString   PrintableString (SIZE (1..ub-locality-name)),
            ///       universalString   UniversalString (SIZE (1..ub-locality-name)),
            ///       utf8String        UTF8String      (SIZE (1..ub-locality-name)),
            ///       bmpString         BMPString       (SIZE (1..ub-locality-
            ///
            /// id-at-stateOrProvinceName AttributeType ::= { id-at 8 }
            ///
            ///
            /// -- Naming attributes of type X520StateOrProvinceName:
            /// --   X520StateOrProvinceName ::= DirectoryName (SIZE (1..ub-state-name))
            /// --
            /// -- Expanded to avoid parameterized type:
            /// X520StateOrProvinceName ::= CHOICE {
            ///       teletexString     TeletexString   (SIZE (1..ub-state-name)),
            ///       printableString   PrintableString (SIZE (1..ub-state-name)),
            ///       universalString   UniversalString (SIZE (1..ub-state-name)),
            ///       utf8String        UTF8String      (SIZE (1..ub-state-name)),
            ///       bmpString         BMPString       (SIZE (1..ub-state-name)) }
            ///
            ///
            /// -- Naming attributes of type X520OrganizationName
            ///
            /// id-at-organizationName  AttributeType ::= { id-at 10 }
            ///
            /// -- Naming attributes of type X520OrganizationName:
            /// --   X520OrganizationName ::=
            /// --          DirectoryName (SIZE (1..ub-organization-name))
            /// --
            /// -- Expanded to avoid parameterized type:
            /// X520OrganizationName ::= CHOICE {
            ///       teletexString     TeletexString
            ///                           (SIZE (1..ub-organization-name)),
            ///       printableString   PrintableString
            ///                           (SIZE (1..ub-organization-name)),
            ///       universalString   UniversalString
            ///                           (SIZE (1..ub-organization-name)),
            ///       utf8String        UTF8String
            ///                           (SIZE (1..ub-organization-name)),
            ///       bmpString         BMPString
            ///                           (SIZE (1..ub-organization-name))  }
            ///
            ///
            /// id-at-organizationalUnitName AttributeType ::= { id-at 11 }
            ///
            /// -- Naming attributes of type X520OrganizationalUnitName:
            /// --   X520OrganizationalUnitName ::=
            /// --          DirectoryName (SIZE (1..ub-organizational-unit-name))
            /// --
            /// -- Expanded to avoid parameterized type:
            /// X520OrganizationalUnitName ::= CHOICE {
            ///       teletexString     TeletexString
            ///                           (SIZE (1..ub-organizational-unit-name)),
            ///       printableString   PrintableString
            ///                           (SIZE (1..ub-organizational-unit-name)),
            ///       universalString   UniversalString
            ///                           (SIZE (1..ub-organizational-unit-name)),
            ///       utf8String        UTF8String
            ///                           (SIZE (1..ub-organizational-unit-name)),
            ///       bmpString         BMPString
            ///                           (SIZE (1..ub-organizational-unit-name)) }
            /// ```
            case .RDNAttributeType.commonName,
                    .RDNAttributeType.localityName,
                    .RDNAttributeType.stateOrProvinceName,
                    .RDNAttributeType.organizationName,
                    .RDNAttributeType.organizationalUnitName:
                do {
                    value = try .init(utf8String: String(ASN1UTF8String(asn1Any: anyValue)))
                } catch {
                    do {
                        value = try .init(printableString: String(ASN1PrintableString(asn1Any: anyValue)))
                    } catch {
                        value = .init(asn1Any: anyValue)
                    }
                }
                
            /// ```
            /// -- Naming attributes of type X520countryName (digraph from IS 3166)
            ///
            /// id-at-countryName       AttributeType ::= { id-at 6 }
            ///
            /// X520countryName ::=     PrintableString (SIZE (2))
            /// ```
            case .RDNAttributeType.countryName:
                do {
                    value = try .init(printableString: String(ASN1PrintableString(asn1Any: anyValue)))
                } catch {
                    value = .init(asn1Any: anyValue)
                }
                
            default:
                value = .init(asn1Any: anyValue)
            }
            
            return .init(type: type, value: value)
        }
    }

    @inlinable
    public func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(self.type)
            try coder.serialize(ASN1Any(self.value))
        }
    }
}

extension RelativeDistinguishedName.Attribute {
    /// A helper constructor to construct a ``RelativeDistinguishedName/Attribute`` whose
    /// value is an `ASN1UTF8String`.
    ///
    /// - Parameter type: The type of the attribute.
    /// - Parameter utf8String: The value of the attribute.
    @inlinable
    public init(type: ASN1ObjectIdentifier, utf8String: String) {
        self.type = type
        self.value = .init(utf8String: utf8String)
    }

    /// A helper constructor to construct a ``RelativeDistinguishedName/Attribute`` whose
    /// value is an `ASN1PrintableString`.
    ///
    /// - Parameter type: The type of the attribute.
    /// - Parameter printableString: The value of the attribute.
    @inlinable
    public init(type: ASN1ObjectIdentifier, printableString: String) throws {
        self.type = type
        self.value = try .init(printableString: printableString)
    }
    
    /// Create a new attribute from a given type and value.
    ///
    /// - Parameter type: The type of the attribute.
    /// - Parameter value: The value of the attribute, wrapped in ``ASN1Any``.
    @inlinable
    public init(type: ASN1ObjectIdentifier, value: ASN1Any) {
        self.type = type
        self.value = .init(asn1Any: value)
    }
}

extension ASN1ObjectIdentifier {
    /// Common object identifiers used within ``RelativeDistinguishedName/Attribute``s.
    public enum RDNAttributeType {
        /// The 'countryName' attribute type contains a two-letter
        /// ISO 3166 country code.
        public static let countryName: ASN1ObjectIdentifier = [2, 5, 4, 6]

        /// The 'commonName' attribute type contains names of an
        /// object.
        public static let commonName: ASN1ObjectIdentifier = [2, 5, 4, 3]

        /// The 'localityName' attribute type contains names of a
        /// locality or place, such as a city, county, or other geographic
        /// region.
        public static let localityName: ASN1ObjectIdentifier = [2, 5, 4, 7]

        /// The 'stateOrProvinceName' attribute type contains the
        /// full names of states or provinces.
        public static let stateOrProvinceName: ASN1ObjectIdentifier = [2, 5, 4, 8]

        /// The 'organizationName' attribute type contains the
        /// names of an organization.
        public static let organizationName: ASN1ObjectIdentifier = [2, 5, 4, 10]

        /// The 'organizationalUnitName' attribute type contains
        /// the names of an organizational unit.
        public static let organizationalUnitName: ASN1ObjectIdentifier = [2, 5, 4, 11]

        /// The 'streetAddress' attribute type contains site
        /// information from a postal address (i.e., the street name, place,
        /// avenue, and the house number).
        public static let streetAddress: ASN1ObjectIdentifier = [2, 5, 4, 9]
    }
}

extension RandomAccessCollection {
    @inlinable
    func suffix(while predicate: (Element) -> Bool) -> SubSequence {
        var index = self.endIndex
        if index == self.startIndex {
            return self[...]
        }

        repeat {
            self.formIndex(before: &index)
            if !predicate(self[index]) {
                self.formIndex(after: &index)
                break
            }
        } while index != self.startIndex

        return self[index..<self.endIndex]
    }
}
