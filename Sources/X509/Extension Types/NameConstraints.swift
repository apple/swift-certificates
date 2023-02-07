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

/// Constraints the namespace within which all subject names issued by a given CA must reside.
///
/// These constraints apply both to the ``Certificate/subject`` and also to any
/// ``SubjectAlternativeNames`` that may be present. Restrictions are applied to
/// specific name _forms_, and when the form is not present then the restriction does not apply.
///
/// Restrictions are defined in terms of both permitted and forbidden subtrees. The forbidden trees
/// are consulted first, and if a name is matched in a forbidden tree then it does not matter whether
/// the same name is also matched in a permitted tree.
public struct NameConstraints {
    /// The DNS name trees that are permitted in certificates issued by this CA.
    ///
    /// These restrictions are expressed in forms like `host.example.com`. Any DNS name that can be
    /// constructed by adding zero or more labels to the left-hand side of the name satifies the constraint.
    public var permittedDNSDomains: [String] {
        // TODO(cory): We probably want a different collection type here that can lazily construct its contents, and
        // that will let us support people assigning into this collection.
        get {
            self.permittedSubtrees.compactMap {
                if case .dNSName(let name) = $0 {
                    return name
                } else {
                    return nil
                }
            }
        }
        set {
            fatalError("TODO")
        }
    }

    /// The DNS name trees that are forbidden in certificates issued by this CA.
    ///
    /// These restrictions are expressed in forms like `host.example.com`. Any DNS name that can be
    /// constructed by adding zero or more labels to the left-hand side of the name satifies the constraint.
    public var excludedDNSDomains: [String] {
        get {
            self.excludedSubtrees.compactMap {
                if case .dNSName(let name) = $0 {
                    return name
                } else {
                    return nil
                }
            }
        }
        set {
            fatalError("TODO")
        }
    }

    /// The IP ranges that are permitted in certificates issued by this CA.
    ///
    /// These restrictions are expressed as a subnet, represented in an ASN.1 octet string.
    /// Due to the absence of a currency subnet and IP address type in Swift, these are preserved
    /// as octet strings.
    ///
    /// As an example, the subnet 192.0.2.0/24 is encoded as the bytes `0xC0, 0x00, 0x02, 0x00, 0xFF, 0xFF, 0xFF, 0x00`.
    /// This represents a subnet root and its mask.
    ///
    /// Any IP address attested that falls within one of these subnets matches the constraint.
    public var permittedIPRanges: [ASN1OctetString] {
        get {
            self.permittedSubtrees.compactMap {
                if case .iPAddress(let address) = $0 {
                    return address
                } else {
                    return nil
                }
            }
        }
        set {
            fatalError("TODO")
        }
    }

    /// The IP ranges that are forbidden in certificates issued by this CA.
    ///
    /// These restrictions are expressed as a subnet, represented in an ASN.1 octet string.
    /// Due to the absence of a currency subnet and IP address type in Swift, these are preserved
    /// as octet strings.
    ///
    /// As an example, the subnet 192.0.2.0/24 is encoded as the bytes `0xC0, 0x00, 0x02, 0x00, 0xFF, 0xFF, 0xFF, 0x00`.
    /// This represents a subnet root and its mask.
    ///
    /// Any IP address attested that falls within one of these subnets matches the constraint.
    public var excludedIPRanges: [ASN1OctetString] {
        get {
            self.excludedSubtrees.compactMap {
                if case .iPAddress(let address) = $0 {
                    return address
                } else {
                    return nil
                }
            }
        }
        set {
            fatalError("TODO")
        }
    }

    /// The email addresses that are permitted in certificates issued by this CA.
    ///
    /// This form may contain a specific mailbox (e.g. `user@example.com`), all
    /// addresses on a given host (e.g. `example.com`), or all mailboxes within a
    /// given domain (e.g. `.example.com`).
    public var permittedEmailAddresses: [String] {
        get {
            self.permittedSubtrees.compactMap {
                if case .rfc822Name(let name) = $0 {
                    return name
                } else {
                    return nil
                }
            }
        }
        set {
            fatalError("TODO")
        }
    }

    /// The email addresses that are permitted in certificates issued by this CA.
    ///
    /// This form may contain a specific mailbox (e.g. `user@example.com`), all
    /// addresses on a given host (e.g. `example.com`), or all mailboxes within a
    /// given domain (e.g. `.example.com`).
    public var excludedEmailAddresses: [String] {
        get {
            self.excludedSubtrees.compactMap {
                if case .rfc822Name(let name) = $0 {
                    return name
                } else {
                    return nil
                }
            }
        }
        set {
            fatalError("TODO")
        }
    }

    /// The URI domains permitted in certificates issued by this CA.
    ///
    /// This contraint applies only to the host part of the URI. The constraint
    /// must be specified as a fully-qualified domain name and may specify either
    /// a host or a domain. When it specifies a domain the string will begin with a
    /// period, and matches any name that can be expanded with one or more labels to
    /// the left. Note that expanding with zero labels does not match: that is,
    /// `.example.com` matches `host.example.com`, but not `example.com`.
    public var permittedURIDomains: [String] {
        get {
            self.permittedSubtrees.compactMap {
                if case .uniformResourceIdentifier(let name) = $0 {
                    return name
                } else {
                    return nil
                }
            }
        }
        set {
            fatalError("TODO")
        }
    }

    /// The URI domains forbidden in certificates issued by this CA.
    ///
    /// This contraint applies only to the host part of the URI. The constraint
    /// must be specified as a fully-qualified domain name and may specify either
    /// a host or a domain. When it specifies a domain the string will begin with a
    /// period, and matches any name that can be expanded with one or more labels to
    /// the left. Note that expanding with zero labels does not match: that is,
    /// `.example.com` matches `host.example.com`, but not `example.com`.
    public var forbiddenURIDomains: [String] {
        get {
            self.excludedSubtrees.compactMap {
                if case .uniformResourceIdentifier(let name) = $0 {
                    return name
                } else {
                    return nil
                }
            }
        }
        set {
            fatalError("TODO")
        }
    }

    /// The complete set of permitted subtrees in ``GeneralName`` form.
    ///
    /// This contains the same data as the broken out forms (``permittedIPRanges``, ``permittedDNSDomains``,
    /// ``permittedURIDomains``, ``permittedEmailAddresses``), but may also include other cases
    /// that those helpers do not represent.
    public var permittedSubtrees: [GeneralName]

    /// The complete set of forbidden subtrees in ``GeneralName`` form.
    ///
    /// This contains the same data as the broken out forms (``excludedIPRanges``, ``excludedDNSDomains``,
    /// ``forbiddenURIDomains``, ``excludedEmailAddresses``), but may also include other cases
    /// that those helpers do not represent.
    public var excludedSubtrees: [GeneralName]

    /// Construct an extension constraining the names a CA may issue.
    ///
    /// - Parameters:
    ///   - permittedDNSDomains: The DNS name trees that are permitted in certificates issued by this CA.
    ///   - excludedDNSDomains: The DNS name trees that are forbidden in certificates issued by this CA.
    ///   - permittedIPRanges: The IP address ranges that are permitted in certificates issued by this CA.
    ///   - excludedIPRanges: The IP address ranges that are forbidden in certificates issued by this CA.
    ///   - permittedEmailAddresses: The email address trees that are permitted in certificates issued by this CA.
    ///   - excludedEmailAddress: The email address trees that are forbidden in certificates issued by this CA.
    ///   - permittedURIDomains: The URI domains that are permitted in certificates issued by this CA.
    ///   - excludedURIDomains: The URI domains that are forbidden in certificates issued by this CA.
    @inlinable
    public init(
        permittedDNSDomains: [String] = [],
        excludedDNSDomains: [String] = [],
        permittedIPRanges: [ASN1OctetString] = [],
        excludedIPRanges: [ASN1OctetString] = [],
        permittedEmailAddresses: [String] = [],
        excludedEmailAddresses: [String] = [],
        permittedURIDomains: [String] = [],
        forbiddenURIDomains: [String] = []
    ) {
        self.permittedSubtrees = []
        self.excludedSubtrees = []

        self.permittedDNSDomains = permittedDNSDomains
        self.excludedDNSDomains = excludedDNSDomains
        self.permittedIPRanges = permittedIPRanges
        self.excludedIPRanges = excludedIPRanges
        self.permittedEmailAddresses = permittedEmailAddresses
        self.excludedEmailAddresses = excludedEmailAddresses
        self.permittedURIDomains = permittedURIDomains
        self.forbiddenURIDomains = forbiddenURIDomains
    }

    /// Construct an extension constraining the names a CA may issue.
    ///
    /// - Parameters:
    ///   - permittedSubtrees: The complete set of permitted subtrees in ``GeneralName`` form.
    ///   - excludedSubtrees: The complete set of excluded subtrees in ``GeneralName`` form.
    @inlinable
    public init(
        permittedSubtrees: [GeneralName] = [],
        excludedSubtrees: [GeneralName] = []
    ) {
        self.permittedSubtrees = permittedSubtrees
        self.excludedSubtrees = excludedSubtrees
    }

    /// Create a new ``NameConstraints`` object
    /// by unwrapping a ``Certificate/Extension``.
    ///
    /// - Parameter ext: The ``Certificate/Extension`` to unwrap
    /// - Throws: if the ``Certificate/Extension/oid`` is not equal to
    ///     `ASN1ObjectIdentifier.X509ExtensionID.nameConstraints`.
    @inlinable
    public init(_ ext: Certificate.Extension) throws {
        guard ext.oid == .X509ExtensionID.nameConstraints else {
            throw CertificateError.incorrectOIDForExtension(reason: "Expected \(ASN1ObjectIdentifier.X509ExtensionID.nameConstraints), got \(ext.oid)")
        }

        let nameConstraintsValue = try NameConstraintsValue(derEncoded: ext.value)
        guard nameConstraintsValue.permittedSubtrees != nil || nameConstraintsValue.excludedSubtrees != nil else {
            throw ASN1Error.invalidASN1Object(reason: "Name Constraints has no permitted or excluded subtrees")
        }

        self.permittedSubtrees = nameConstraintsValue.permittedSubtrees ?? []
        self.excludedSubtrees = nameConstraintsValue.excludedSubtrees ?? []
    }
}

extension NameConstraints: Hashable { }

extension NameConstraints: Sendable { }

extension NameConstraints: CustomStringConvertible {
    public var description: String {
        var elements: [String] = []

        if self.permittedSubtrees.count > 0 {
            elements.append("permittedSubtrees: \(self.permittedSubtrees.map { String(describing: $0) }.joined(separator: ", "))")
        }
        if self.excludedSubtrees.count > 0 {
            elements.append("excludedSubtrees: \(self.excludedSubtrees.map { String(describing: $0) }.joined(separator: ", "))")
        }

        return elements.joined(separator: "; ")
    }
}

extension Certificate.Extension {
    /// Construct an opaque ``Certificate/Extension`` from this Name Constraints extension.
    ///
    /// - Parameters:
    ///   - nameConstraints: The extension to wrap
    ///   - critical: Whether this extension should have the critical bit set.
    @inlinable
    public init(_ nameConstraints: NameConstraints, critical: Bool) throws {
        let asn1Representation = NameConstraintsValue(nameConstraints)
        var serializer = DER.Serializer()
        try serializer.serialize(asn1Representation)
        self.init(oid: .X509ExtensionID.nameConstraints, critical: critical, value: serializer.serializedBytes[...])
    }
}

extension NameConstraints: CertificateExtensionConvertible {
    public func makeCertificateExtension() throws -> Certificate.Extension {
        return try .init(self, critical: false)
    }
}

// MARK: ASN1 Helpers
@usableFromInline
struct NameConstraintsValue: DERImplicitlyTaggable {
    @inlinable
    static var defaultIdentifier: ASN1Identifier {
        .sequence
    }

    @usableFromInline
    var permittedSubtrees: [GeneralName]?

    @usableFromInline
    var excludedSubtrees: [GeneralName]?

    @inlinable
    init(permittedSubtrees: [GeneralName]?, excludedSubtrees: [GeneralName]?) {
        self.permittedSubtrees = permittedSubtrees
        self.excludedSubtrees = excludedSubtrees
    }

    @inlinable
    init(_ ext: NameConstraints) {
        if !ext.permittedSubtrees.isEmpty {
            self.permittedSubtrees = ext.permittedSubtrees
        }
        if !ext.excludedSubtrees.isEmpty {
            self.excludedSubtrees = ext.excludedSubtrees
        }
    }

    @inlinable
    init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let permittedSubtrees: GeneralSubtrees? = try DER.optionalImplicitlyTagged(&nodes, tag: .init(tagWithNumber: 0, tagClass: .contextSpecific))
            let excludedSubtrees: GeneralSubtrees? = try DER.optionalImplicitlyTagged(&nodes, tag: .init(tagWithNumber: 1, tagClass: .contextSpecific))

            return NameConstraintsValue(permittedSubtrees: permittedSubtrees.map { $0.base }, excludedSubtrees: excludedSubtrees.map { $0.base })
        }
    }

    @inlinable
    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serializeOptionalImplicitlyTagged(
                self.permittedSubtrees.map { GeneralSubtrees($0) },
                withIdentifier: .init(tagWithNumber: 0, tagClass: .contextSpecific)
            )

            try coder.serializeOptionalImplicitlyTagged(
                self.excludedSubtrees.map { GeneralSubtrees($0) },
                withIdentifier: .init(tagWithNumber: 1, tagClass: .contextSpecific)
            )
        }
    }
}

@usableFromInline
struct GeneralSubtrees: DERImplicitlyTaggable {
    @inlinable
    static var defaultIdentifier: ASN1Identifier {
        .sequence
    }

    @usableFromInline
    var base: [GeneralName]

    @inlinable
    init(_ base: [GeneralName]) {
        self.base = base
    }

    @inlinable
    init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self.base = try DER.sequence(identifier: identifier, rootNode: rootNode)
    }

    @inlinable
    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.serializeSequenceOf(self.base, identifier: identifier)
    }
}

@usableFromInline
struct GeneralSubtree: DERImplicitlyTaggable {
    @inlinable
    static var defaultIdentifier: ASN1Identifier {
        .sequence
    }

    @usableFromInline
    var base: GeneralName

    @inlinable
    init(_ base: GeneralName) {
        self.base = base
    }

    @inlinable
    init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self.base = try DER.sequence(rootNode, identifier: identifier) { nodes in
            try GeneralName(derEncoded: &nodes)
        }
    }

    @inlinable
    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(self.base)
        }
    }
}
