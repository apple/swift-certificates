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

extension Certificate.Extensions {
    /// Provides details on how to access information about the certificate issuer.
    ///
    /// This extension behaves as a collection of ``Certificate/Extensions-swift.struct/AuthorityInformationAccess-swift.struct/AccessDescription`` objects.
    ///
    /// In practice this most commonly contains OCSP servers and links to the issuing CA certificate.
    public struct AuthorityInformationAccess {
        @usableFromInline
        var descriptions: [AccessDescription]

        /// Create a new ``Certificate/Extensions-swift.struct/AuthorityInformationAccess-swift.struct/`` object
        /// containing specific access descriptions.
        ///
        /// - Parameter descriptions: The descriptions to include in the AIA extension.
        @inlinable
        public init<Descriptions: Sequence>(_ descriptions: Descriptions) where Descriptions.Element == AccessDescription {
            self.descriptions = Array(descriptions)
        }

        /// Create a new ``Certificate/Extensions-swift.struct/AuthorityInformationAccess-swift.struct`` object
        /// by unwrapping a ``Certificate/Extension``.
        ///
        /// - Parameter ext: The ``Certificate/Extension`` to unwrap
        /// - Throws: if the ``Certificate/Extension/oid`` is not equal to
        ///     `ASN1ObjectIdentifier.X509ExtensionID.authorityInformationAccess`.
        @inlinable
        public init(_ ext: Certificate.Extension) throws {
            guard ext.oid == .X509ExtensionID.authorityInformationAccess else {
                throw CertificateError.incorrectOIDForExtension(reason: "Expected \(ASN1.ASN1ObjectIdentifier.X509ExtensionID.authorityInformationAccess), got \(ext.oid)")
            }

            let aiaSyntax = try AuthorityInfoAccessSyntax(asn1Encoded: ext.value)
            self.descriptions = aiaSyntax.descriptions.map { AccessDescription($0) }
        }
    }
}

extension Certificate.Extensions.AuthorityInformationAccess: Hashable { }

extension Certificate.Extensions.AuthorityInformationAccess: Sendable { }

extension Certificate.Extensions.AuthorityInformationAccess: CustomStringConvertible {
    public var description: String {
        "TODO"
    }
}

// TODO(cory): Probably also RangeReplaceableCollection, even though it's kinda crap.
extension Certificate.Extensions.AuthorityInformationAccess: RandomAccessCollection {
    @inlinable
    public var startIndex: Int {
        self.descriptions.startIndex
    }

    @inlinable
    public var endIndex: Int {
        self.descriptions.endIndex
    }

    @inlinable
    public subscript(position: Int) -> AccessDescription {
        // TODO(cory): Maintain uniqueness
        get {
            self.descriptions[position]
        }
        set {
            self.descriptions[position] = newValue
        }
    }
}

extension Certificate.Extensions.AuthorityInformationAccess {
    /// Describes the location and format of additional information provided
    /// by the issuer of a given certificate.
    public struct AccessDescription {
        /// The format and meaning of the information at ``location``.
        public var method: AccessMethod

        /// The location where the information may be found.
        public var location: GeneralName

        /// Construct a new ``Certificate/Extensions-swift.struct/AuthorityInformationAccess-swift.struct/AccessDescription`` from constituent parts.
        @inlinable
        public init(method: AccessMethod, location: GeneralName) {
            self.method = method
            self.location = location
        }

        @inlinable
        init(_ asn1Form: AIAAccessDescription) {
            self.method = .init(asn1Form.accessMethod)
            self.location = asn1Form.accessLocation
        }
    }
}

extension Certificate.Extensions.AuthorityInformationAccess.AccessDescription: Hashable { }

extension Certificate.Extensions.AuthorityInformationAccess.AccessDescription: Sendable { }

extension Certificate.Extensions.AuthorityInformationAccess.AccessDescription: CustomStringConvertible {
    public var description: String {
        fatalError("TODO")
    }
}

extension Certificate.Extensions.AuthorityInformationAccess.AccessDescription {
    /// The format and meaning of the information included in a single
    /// ``Certificate/Extensions-swift.struct/AuthorityInformationAccess-swift.struct/AccessDescription``
    /// object.
    public struct AccessMethod {
        @usableFromInline
        var backing: Backing

        @usableFromInline
        enum Backing {
            case ocspServer
            case issuingCA
            case unknownType(ASN1.ASN1ObjectIdentifier)
        }

        @inlinable
        init(_ backing: Backing) {
            self.backing = backing
        }

        @inlinable
        init(_ oid: ASN1.ASN1ObjectIdentifier) {
            switch oid {
            case .AccessMethodIdentifiers.ocspServer:
                self.backing = .ocspServer
            case .AccessMethodIdentifiers.issuingCA:
                self.backing = .issuingCA
            default:
                self.backing = .unknownType(oid)
            }
        }

        /// Represents an OCSP server that can be queried for certificate revocation information.
        public static let ocspServer = Self(.ocspServer)

        /// A location from which a copy of the issuing CA certificate may be obtained.
        public static let issuingCA = Self(.issuingCA)
    }
}

extension Certificate.Extensions.AuthorityInformationAccess.AccessDescription.AccessMethod: Hashable { }

extension Certificate.Extensions.AuthorityInformationAccess.AccessDescription.AccessMethod: Sendable { }

extension Certificate.Extensions.AuthorityInformationAccess.AccessDescription.AccessMethod: CustomStringConvertible {
    public var description: String {
        fatalError("TODO")
    }
}

extension Certificate.Extensions.AuthorityInformationAccess.AccessDescription.AccessMethod.Backing: Hashable { }

extension Certificate.Extensions.AuthorityInformationAccess.AccessDescription.AccessMethod.Backing: Sendable { }

extension Certificate.Extensions.AuthorityInformationAccess.AccessDescription.AccessMethod.Backing: CustomStringConvertible {
    public var description: String {
        fatalError("TODO")
    }
}

extension Certificate.Extension {
    /// Construct an opaque ``Certificate/Extension`` from this AIA extension.
    ///
    /// - Parameters:
    ///   - aia: The extension to wrap
    ///   - critical: Whether this extension should have the critical bit set.
    @inlinable
    public init(_ aia: Certificate.Extensions.AuthorityInformationAccess, critical: Bool) throws {
        let asn1Representation = AuthorityInfoAccessSyntax(aia)
        var serializer = ASN1.Serializer()
        try serializer.serialize(asn1Representation)
        self.init(oid: .X509ExtensionID.authorityInformationAccess, critical: critical, value: serializer.serializedBytes[...])
    }
}

extension Certificate.Extensions.AuthorityInformationAccess: CertificateExtensionConvertible {
    public func makeCertificateExtension() throws -> Certificate.Extension {
        return try .init(self, critical: false)
    }
}

// MARK: ASN.1 Helpers

// AuthorityInfoAccessSyntax  ::=
//         SEQUENCE SIZE (1..MAX) OF AccessDescription
//
// AccessDescription  ::=  SEQUENCE {
//         accessMethod          OBJECT IDENTIFIER,
//         accessLocation        GeneralName  }
@usableFromInline
struct AuthorityInfoAccessSyntax: ASN1ImplicitlyTaggable {
    @inlinable
    static var defaultIdentifier: ASN1.ASN1Identifier {
        .sequence
    }

    @usableFromInline
    var descriptions: [AIAAccessDescription]

    @inlinable
    init(_ aia: Certificate.Extensions.AuthorityInformationAccess) {
        self.descriptions = aia.descriptions.map { .init($0) }
    }

    @inlinable
    init(asn1Encoded rootNode: ASN1.ASN1Node, withIdentifier identifier: ASN1.ASN1Identifier) throws {
        self.descriptions = try ASN1.sequence(of: AIAAccessDescription.self, identifier: identifier, rootNode: rootNode)
    }

    @inlinable
    func serialize(into coder: inout ASN1.Serializer, withIdentifier identifier: ASN1.ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            for description in descriptions {
                try coder.serialize(description)
            }
        }
    }
}

@usableFromInline
struct AIAAccessDescription: ASN1ImplicitlyTaggable {
    @inlinable
    static var defaultIdentifier: ASN1.ASN1Identifier {
        .sequence
    }

    @usableFromInline
    var accessMethod: ASN1.ASN1ObjectIdentifier

    @usableFromInline
    var accessLocation: GeneralName

    @inlinable
    init(accessMethod: ASN1.ASN1ObjectIdentifier, accessLocation: GeneralName) {
        self.accessMethod = accessMethod
        self.accessLocation = accessLocation
    }

    @inlinable
    init(_ description: Certificate.Extensions.AuthorityInformationAccess.AccessDescription) {
        self.accessMethod = ASN1.ASN1ObjectIdentifier(accessMethod: description.method)
        self.accessLocation = description.location
    }

    @inlinable
    init(asn1Encoded rootNode: ASN1.ASN1Node, withIdentifier identifier: ASN1.ASN1Identifier) throws {
        self = try ASN1.sequence(rootNode, identifier: identifier) { nodes in
            let accessMethod = try ASN1.ASN1ObjectIdentifier(asn1Encoded: &nodes)
            let accessLocation = try GeneralName(asn1Encoded: &nodes)
            return AIAAccessDescription(accessMethod: accessMethod, accessLocation: accessLocation)
        }
    }

    @inlinable
    func serialize(into coder: inout ASN1.Serializer, withIdentifier identifier: ASN1.ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(self.accessMethod)
            try coder.serialize(self.accessLocation)
        }
    }
}

extension ASN1.ASN1ObjectIdentifier {
    @usableFromInline
    enum AccessMethodIdentifiers {
        @usableFromInline
        static let ocspServer: ASN1.ASN1ObjectIdentifier = [1, 3, 6, 1, 5, 5, 7, 48, 1]

        @usableFromInline
        static let issuingCA: ASN1.ASN1ObjectIdentifier = [1, 3, 6, 1, 5, 5, 7, 48, 2]
    }

    @inlinable
    public init(accessMethod: Certificate.Extensions.AuthorityInformationAccess.AccessDescription.AccessMethod) {
        switch accessMethod.backing {
        case .ocspServer:
            self = .AccessMethodIdentifiers.ocspServer
        case .issuingCA:
            self = .AccessMethodIdentifiers.issuingCA
        case .unknownType(let oid):
            self = oid
        }
    }
}
