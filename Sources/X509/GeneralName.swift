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

public enum GeneralName: Hashable, Sendable, ASN1Parseable, ASN1Serializable {
    case otherName(OtherName)
    case rfc822Name(String)
    case dNSName(String)
    case x400Address(ASN1.ASN1Any)
    case directoryName(DistinguishedName)
    case ediPartyName(ASN1.ASN1Any)
    case uniformResourceIdentifier(String)
    case iPAddress(ASN1.ASN1OctetString)
    case registeredID(ASN1.ASN1ObjectIdentifier)

    @usableFromInline
    static let otherNameTag = ASN1.ASN1Identifier(tagWithNumber: 0, tagClass: .contextSpecific, constructed: true)
    @usableFromInline
    static let rfc822NameTag = ASN1.ASN1Identifier(tagWithNumber: 1, tagClass: .contextSpecific, constructed: false)
    @usableFromInline
    static let dNSNameTag = ASN1.ASN1Identifier(tagWithNumber: 2, tagClass: .contextSpecific, constructed: false)
    @usableFromInline
    static let x400AddressTag = ASN1.ASN1Identifier(tagWithNumber: 3, tagClass: .contextSpecific, constructed: true)
    @usableFromInline
    static let directoryNameTag = ASN1.ASN1Identifier(tagWithNumber: 4, tagClass: .contextSpecific, constructed: true)
    @usableFromInline
    static let ediPartyNameTag = ASN1.ASN1Identifier(tagWithNumber: 5, tagClass: .contextSpecific, constructed: true)
    @usableFromInline
    static let uriTag = ASN1.ASN1Identifier(tagWithNumber: 6, tagClass: .contextSpecific, constructed: false)
    @usableFromInline
    static let iPAddressTag = ASN1.ASN1Identifier(tagWithNumber: 7, tagClass: .contextSpecific, constructed: false)
    @usableFromInline
    static let registeredIDTag = ASN1.ASN1Identifier(tagWithNumber: 8, tagClass: .contextSpecific, constructed: false)

    @inlinable
    public init(asn1Encoded rootNode: ASN1.ASN1Node) throws {
        switch rootNode.identifier {
        case Self.otherNameTag:
            self = try .otherName(OtherName(asn1Encoded: rootNode, withIdentifier: Self.otherNameTag))
        case Self.rfc822NameTag:
            let result = try ASN1.ASN1IA5String(asn1Encoded: rootNode, withIdentifier: Self.rfc822NameTag)
            self = .rfc822Name(String(result))
        case Self.dNSNameTag:
            let result = try ASN1.ASN1IA5String(asn1Encoded: rootNode, withIdentifier: Self.dNSNameTag)
            self = .dNSName(String(result))
        case Self.x400AddressTag:
            self = .x400Address(ASN1.ASN1Any(asn1Encoded: rootNode))
        case Self.directoryNameTag:
            self = try .directoryName(DistinguishedName(asn1Encoded: rootNode, withIdentifier: Self.directoryNameTag))
        case Self.ediPartyNameTag:
            self = .ediPartyName(ASN1.ASN1Any(asn1Encoded: rootNode))
        case Self.uriTag:
            let result = try ASN1.ASN1IA5String(asn1Encoded: rootNode, withIdentifier: Self.uriTag)
            self = .uniformResourceIdentifier(String(result))
        case Self.iPAddressTag:
            self = try .iPAddress(ASN1.ASN1OctetString(asn1Encoded: rootNode, withIdentifier: Self.iPAddressTag))
        case Self.registeredIDTag:
            self = try .registeredID(ASN1.ASN1ObjectIdentifier(asn1Encoded: rootNode, withIdentifier: Self.registeredIDTag))
        default:
            throw ASN1Error.invalidFieldIdentifier
        }
    }

    @inlinable
    public func serialize(into coder: inout ASN1.Serializer) throws {
        switch self {
        case .otherName(let otherName):
            try otherName.serialize(into: &coder, withIdentifier: Self.otherNameTag)
        case .rfc822Name(let name):
            let ia5String = try ASN1.ASN1IA5String(name)
            try ia5String.serialize(into: &coder, withIdentifier: Self.rfc822NameTag)
        case .dNSName(let name):
            let ia5String = try ASN1.ASN1IA5String(name)
            try ia5String.serialize(into: &coder, withIdentifier: Self.dNSNameTag)
        case .x400Address(let orAddress):
            try orAddress.serialize(into: &coder)
        case .directoryName(let name):
            try name.serialize(into: &coder, withIdentifier: Self.directoryNameTag)
        case .ediPartyName(let name):
            try name.serialize(into: &coder)
        case .uniformResourceIdentifier(let name):
            let ia5String = try ASN1.ASN1IA5String(name)
            try ia5String.serialize(into: &coder, withIdentifier: Self.uriTag)
        case .iPAddress(let ipAddress):
            try ipAddress.serialize(into: &coder, withIdentifier: Self.iPAddressTag)
        case .registeredID(let id):
            try id.serialize(into: &coder, withIdentifier: Self.registeredIDTag)
        }
    }
}

extension GeneralName: CustomStringConvertible {
    @inlinable
    public var description: String {
        switch self {
        case .dNSName(let name):
            return "dNSName: \(name)"
        case .directoryName(let directoryName):
            return "directoryName: \(directoryName)"
        case .ediPartyName(let name):
            return "ediPartyName: \(name)"
        case .iPAddress(let address):
            return "iPAddress: \(address.bytes)"
        case .otherName(let otherName):
            return "otherName: \(otherName)"
        case .registeredID(let id):
            return "registeredID: \(id)"
        case .rfc822Name(let name):
            return "rfc822Name: \(name)"
        case .uniformResourceIdentifier(let uri):
            return "uri: \(uri)"
        case .x400Address(let address):
            return "x400Address: \(address)"
        }
    }
}

//GeneralName ::= CHOICE {
//     otherName                       [0]     OtherName,
//     rfc822Name                      [1]     IA5String,
//     dNSName                         [2]     IA5String,
//     x400Address                     [3]     ORAddress,
//     directoryName                   [4]     Name,
//     ediPartyName                    [5]     EDIPartyName,
//     uniformResourceIdentifier       [6]     IA5String,
//     iPAddress                       [7]     OCTET STRING,
//     registeredID                    [8]     OBJECT IDENTIFIER }
//
//OtherName ::= SEQUENCE {
//     type-id    OBJECT IDENTIFIER,
//     value      [0] EXPLICIT ANY DEFINED BY type-id }
//
//EDIPartyName ::= SEQUENCE {
//     nameAssigner            [0]     DirectoryString OPTIONAL,
//     partyName               [1]     DirectoryString }

extension GeneralName {
    public struct OtherName: Hashable, Sendable, ASN1ImplicitlyTaggable {
        @inlinable
        public static var defaultIdentifier: ASN1.ASN1Identifier {
            .sequence
        }

        public var typeID: ASN1.ASN1ObjectIdentifier

        public var value: ASN1.ASN1Any?

        @inlinable
        public init(typeID: ASN1.ASN1ObjectIdentifier, value: ASN1.ASN1Any?) {
            self.typeID = typeID
            self.value = value
        }

        @inlinable
        public init(asn1Encoded rootNode: ASN1.ASN1Node, withIdentifier identifier: ASN1.ASN1Identifier) throws {
            self = try ASN1.sequence(rootNode, identifier: identifier) { nodes in
                let typeID = try ASN1.ASN1ObjectIdentifier(asn1Encoded: &nodes)
                let value = try ASN1.optionalExplicitlyTagged(&nodes, tagNumber: 0, tagClass: .contextSpecific) {
                    ASN1.ASN1Any(asn1Encoded: $0)
                }

                return OtherName(typeID: typeID, value: value)
            }
        }

        @inlinable
        public func serialize(into coder: inout ASN1.Serializer, withIdentifier identifier: ASN1.ASN1Identifier) throws {
            try coder.appendConstructedNode(identifier: identifier) { coder in
                try coder.serialize(self.typeID)
                if let value = self.value {
                    try coder.serialize(value, explicitlyTaggedWithIdentifier: .init(explicitTagWithNumber: 0, tagClass: .contextSpecific))
                }
            }
        }
    }
}

extension GeneralName.OtherName: CustomStringConvertible {
    @inlinable
    public var description: String {
        "\(self.typeID): \(String(describing: self.value))"
    }
}

@usableFromInline
struct GeneralNames: ASN1ImplicitlyTaggable {
    @inlinable
    static var defaultIdentifier: ASN1.ASN1Identifier {
        .sequence
    }

    @usableFromInline
    var names: [GeneralName]

    @inlinable
    init(_ names: [GeneralName]) {
        self.names = names
    }

    @inlinable
    init(asn1Encoded rootNode: ASN1.ASN1Node, withIdentifier identifier: ASN1.ASN1Identifier) throws {
        self.names = try ASN1.sequence(of: GeneralName.self, identifier: identifier, rootNode: rootNode)
    }

    @inlinable
    func serialize(into coder: inout ASN1.Serializer, withIdentifier identifier: ASN1.ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            for name in names {
                try coder.serialize(name)
            }
        }
    }
}
