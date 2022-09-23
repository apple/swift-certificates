//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCertificate open source project
//
// Copyright (c) 2022 Apple Inc. and the SwiftCertificate project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.md for the list of SwiftCertificate project authors
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
        /// The type of this attribute.
        ///
        /// Common types can be found in `ASN1ObjectIdentifier.RDNAttributeType`.
        public var type: ASN1.ASN1ObjectIdentifier

        // TODO(cory): This feels gross, we should have a better representation that reduces the runtime type checking and recomputation.
        // These are all strings in other places, but we can't necessarily guarantee that. Probably want a computed property.
        /// The value of this attribute.
        public var value: ASN1.ASN1Any

        /// Create a new attribute from a given type and value.
        ///
        /// - Parameter type: The type of the attribute.
        /// - Parameter value: The value of the attribute, wrapped in an `ASN1Any`.
        @inlinable
        public init(type: ASN1.ASN1ObjectIdentifier, value: ASN1.ASN1Any) {
            self.type = type
            self.value = value
        }
    }
}


extension RelativeDistinguishedName.Attribute: Hashable { }

extension RelativeDistinguishedName.Attribute: Sendable { }

extension RelativeDistinguishedName.Attribute: CustomStringConvertible {
    @inlinable
    public var description: String {
        // TODO(cory): Relevant citation is probably https://www.rfc-editor.org/rfc/rfc4514
        return "TODO"
    }
}

extension RelativeDistinguishedName.Attribute: ASN1ImplicitlyTaggable {
    @inlinable
    public static var defaultIdentifier: ASN1.ASN1Identifier {
        .sequence
    }

    @inlinable
    public init(asn1Encoded rootNode: ASN1.ASN1Node, withIdentifier identifier: ASN1.ASN1Identifier) throws {
        self = try ASN1.sequence(rootNode, identifier: identifier) { nodes in
            let type = try ASN1.ASN1ObjectIdentifier(asn1Encoded: &nodes)
            let value = try ASN1.ASN1Any(asn1Encoded: &nodes)

            return .init(type: type, value: value)
        }
    }

    @inlinable
    public func serialize(into coder: inout ASN1.Serializer, withIdentifier identifier: ASN1.ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(self.type)
            try coder.serialize(self.value)
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
    public init(type: ASN1.ASN1ObjectIdentifier, utf8String: String) throws {
        self.type = type
        self.value = try ASN1.ASN1Any(erasing: ASN1.ASN1UTF8String(utf8String))
    }

    /// A helper constructor to construct a ``RelativeDistinguishedName/Attribute`` whose
    /// value is an `ASN1PrintableString`.
    ///
    /// - Parameter type: The type of the attribute.
    /// - Parameter printableString: The value of the attribute.
    @inlinable
    public init(type: ASN1.ASN1ObjectIdentifier, printableString: String) throws {
        self.type = type
        self.value = try ASN1.ASN1Any(erasing: ASN1.ASN1PrintableString(printableString))
    }
}

extension ASN1.ASN1ObjectIdentifier {
    /// Common object identifiers used within ``RelativeDistinguishedName/Attribute``s.
    public enum RDNAttributeType {
        /// The 'countryName' attribute type contains a two-letter
        /// ISO 3166 country code.
        public static let countryName: ASN1.ASN1ObjectIdentifier = [2, 5, 4, 6]

        /// The 'commonName' attribute type contains names of an
        /// object.
        public static let commonName: ASN1.ASN1ObjectIdentifier = [2, 5, 4, 3]

        /// The 'localityName' attribute type contains names of a
        /// locality or place, such as a city, county, or other geographic
        /// region.
        public static let localityName: ASN1.ASN1ObjectIdentifier = [2, 5, 4, 7]

        /// The 'stateOrProvinceName' attribute type contains the
        /// full names of states or provinces.
        public static let stateOrProvinceName: ASN1.ASN1ObjectIdentifier = [2, 5, 4, 8]

        /// The 'organizationName' attribute type contains the
        /// names of an organization.
        public static let organizationName: ASN1.ASN1ObjectIdentifier = [2, 5, 4, 10]

        /// The 'organizationalUnitName' attribute type contains
        /// the names of an organizational unit.
        public static let organizationalUnitName: ASN1.ASN1ObjectIdentifier = [2, 5, 4, 11]

        /// The 'streetAddress' attribute type contains site
        /// information from a postal address (i.e., the street name, place,
        /// avenue, and the house number).
        public static let streetAddress: ASN1.ASN1ObjectIdentifier = [2, 5, 4, 9]
    }
}
