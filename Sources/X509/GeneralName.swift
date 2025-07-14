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

public enum GeneralName: Hashable, Sendable, DERParseable, DERSerializable {
    case otherName(OtherName)
    case rfc822Name(String)
    case dnsName(String)
    case x400Address(ASN1Any)
    case directoryName(DistinguishedName)
    case ediPartyName(ASN1Any)
    case uniformResourceIdentifier(String)
    case ipAddress(ASN1OctetString)
    case registeredID(ASN1ObjectIdentifier)

    @usableFromInline
    static let otherNameTag = ASN1Identifier(tagWithNumber: 0, tagClass: .contextSpecific)
    @usableFromInline
    static let rfc822NameTag = ASN1Identifier(tagWithNumber: 1, tagClass: .contextSpecific)
    @usableFromInline
    static let dnsNameTag = ASN1Identifier(tagWithNumber: 2, tagClass: .contextSpecific)
    @usableFromInline
    static let x400AddressTag = ASN1Identifier(tagWithNumber: 3, tagClass: .contextSpecific)
    @usableFromInline
    static let directoryNameTag = ASN1Identifier(tagWithNumber: 4, tagClass: .contextSpecific)
    @usableFromInline
    static let ediPartyNameTag = ASN1Identifier(tagWithNumber: 5, tagClass: .contextSpecific)
    @usableFromInline
    static let uriTag = ASN1Identifier(tagWithNumber: 6, tagClass: .contextSpecific)
    @usableFromInline
    static let ipAddressTag = ASN1Identifier(tagWithNumber: 7, tagClass: .contextSpecific)
    @usableFromInline
    static let registeredIDTag = ASN1Identifier(tagWithNumber: 8, tagClass: .contextSpecific)

    @inlinable
    public init(derEncoded rootNode: ASN1Node) throws {
        switch rootNode.identifier {
        case Self.otherNameTag:
            self = try .otherName(OtherName(derEncoded: rootNode, withIdentifier: Self.otherNameTag))
        case Self.rfc822NameTag:
            let result = try ASN1IA5String(derEncoded: rootNode, withIdentifier: Self.rfc822NameTag)
            self = .rfc822Name(String(result))
        case Self.dnsNameTag:
            let result = try ASN1IA5String(derEncoded: rootNode, withIdentifier: Self.dnsNameTag)
            self = .dnsName(String(result))
        case Self.x400AddressTag:
            self = .x400Address(ASN1Any(derEncoded: rootNode))
        case Self.directoryNameTag:
            self = try DER.explicitlyTagged(
                rootNode,
                tagNumber: Self.directoryNameTag.tagNumber,
                tagClass: Self.directoryNameTag.tagClass
            ) { node in
                return try .directoryName(DistinguishedName(derEncoded: node))
            }
        case Self.ediPartyNameTag:
            self = .ediPartyName(ASN1Any(derEncoded: rootNode))
        case Self.uriTag:
            let result = try ASN1IA5String(derEncoded: rootNode, withIdentifier: Self.uriTag)
            self = .uniformResourceIdentifier(String(result))
        case Self.ipAddressTag:
            self = try .ipAddress(ASN1OctetString(derEncoded: rootNode, withIdentifier: Self.ipAddressTag))
        case Self.registeredIDTag:
            self = try .registeredID(ASN1ObjectIdentifier(derEncoded: rootNode, withIdentifier: Self.registeredIDTag))
        default:
            throw ASN1Error.unexpectedFieldType(rootNode.identifier)
        }
    }

    @inlinable
    public func serialize(into coder: inout DER.Serializer) throws {
        switch self {
        case .otherName(let otherName):
            try otherName.serialize(into: &coder, withIdentifier: Self.otherNameTag)
        case .rfc822Name(let name):
            let ia5String = try ASN1IA5String(name)
            try ia5String.serialize(into: &coder, withIdentifier: Self.rfc822NameTag)
        case .dnsName(let name):
            let ia5String = try ASN1IA5String(name)
            try ia5String.serialize(into: &coder, withIdentifier: Self.dnsNameTag)
        case .x400Address(let orAddress):
            try orAddress.serialize(into: &coder)
        case .directoryName(let name):
            try coder.serialize(name, explicitlyTaggedWithIdentifier: Self.directoryNameTag)
        case .ediPartyName(let name):
            try name.serialize(into: &coder)
        case .uniformResourceIdentifier(let name):
            let ia5String = try ASN1IA5String(name)
            try ia5String.serialize(into: &coder, withIdentifier: Self.uriTag)
        case .ipAddress(let ipAddress):
            try ipAddress.serialize(into: &coder, withIdentifier: Self.ipAddressTag)
        case .registeredID(let id):
            try id.serialize(into: &coder, withIdentifier: Self.registeredIDTag)
        }
    }
}

extension GeneralName: CustomStringConvertible {
    @inlinable
    public var description: String {
        switch self {
        case .dnsName(let name):
            return "DNSName(\(String(reflecting: name)))"
        case .directoryName(let directoryName):
            return "DirectoryName(\(String(reflecting: directoryName)))"
        case .ediPartyName(let name):
            return "EDIPartyName(\(String(reflecting: name)))"
        case .ipAddress(let address):
            return "IPAddress(\(String(reflecting: Array(address.bytes))))"
        case .otherName(let otherName):
            return "OtherName(\(String(reflecting: otherName)))"
        case .registeredID(let id):
            return "RegisteredID(\(String(reflecting: id)))"
        case .rfc822Name(let name):
            return "RFC822Name(\(String(reflecting: name)))"
        case .uniformResourceIdentifier(let uri):
            return "URI(\(String(reflecting: uri)))"
        case .x400Address(let address):
            return "X400Address(\(String(reflecting: address)))"
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
    public struct OtherName: Hashable, Sendable, DERImplicitlyTaggable {
        @inlinable
        public static var defaultIdentifier: ASN1Identifier {
            .sequence
        }

        public var typeID: ASN1ObjectIdentifier

        public var value: ASN1Any?

        @inlinable
        public init(typeID: ASN1ObjectIdentifier, value: ASN1Any?) {
            self.typeID = typeID
            self.value = value
        }

        @inlinable
        public init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
            self = try DER.sequence(rootNode, identifier: identifier) { nodes in
                let typeID = try ASN1ObjectIdentifier(derEncoded: &nodes)
                let value = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 0, tagClass: .contextSpecific) {
                    ASN1Any(derEncoded: $0)
                }

                return OtherName(typeID: typeID, value: value)
            }
        }

        @inlinable
        public func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
            try coder.appendConstructedNode(identifier: identifier) { coder in
                try coder.serialize(self.typeID)
                if let value = self.value {
                    try coder.serialize(
                        value,
                        explicitlyTaggedWithIdentifier: .init(tagWithNumber: 0, tagClass: .contextSpecific)
                    )
                }
            }
        }
    }
}

extension GeneralName.OtherName: CustomStringConvertible {
    @inlinable
    public var description: String {
        "\(self.typeID): \(String(reflecting: self.value))"
    }
}

@usableFromInline
struct GeneralNames: DERImplicitlyTaggable, Sendable {
    @inlinable
    static var defaultIdentifier: ASN1Identifier {
        .sequence
    }

    @usableFromInline
    var names: [GeneralName]

    @inlinable
    init(_ names: [GeneralName]) {
        self.names = names
    }

    @inlinable
    init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self.names = try DER.sequence(of: GeneralName.self, identifier: identifier, rootNode: rootNode)
    }

    @inlinable
    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            for name in names {
                try coder.serialize(name)
            }
        }
    }
}
