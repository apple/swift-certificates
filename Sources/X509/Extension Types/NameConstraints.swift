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
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public struct NameConstraints {
    public struct DNSNames: Hashable, Sendable, Collection, ExpressibleByArrayLiteral, CustomStringConvertible {
        public typealias Element = String

        @inlinable
        public static func == (lhs: Self, rhs: Self) -> Bool {
            lhs.elementsEqual(rhs)
        }

        @usableFromInline
        var subtrees: [GeneralName]

        @inlinable
        public var description: String {
            "[\(self.joined(separator: ", "))]"
        }

        @inlinable
        init(subtrees: [GeneralName]) {
            self.subtrees = subtrees
        }

        @inlinable
        public init(_ elements: some Sequence<String>) {
            self.subtrees = elements.map { .dnsName($0) }
        }

        @inlinable
        public init(arrayLiteral elements: String...) {
            self.init(elements)
        }

        @inlinable
        public func hash(into hasher: inout Hasher) {
            hasher.combine(contentsOf: self)
        }

        public struct Index: Comparable, Sendable {
            @inlinable
            public static func < (lhs: Self, rhs: Self) -> Bool {
                lhs.wrapped < rhs.wrapped
            }
            @usableFromInline
            var wrapped: Int

            @inlinable
            init(_ wrapped: Int) {
                self.wrapped = wrapped
            }
        }

        @inlinable
        public var startIndex: Index {
            Index(
                self.subtrees.firstIndex(where: {
                    guard case .dnsName = $0 else {
                        return false
                    }
                    return true
                }) ?? self.subtrees.endIndex
            )
        }

        @inlinable
        public var endIndex: Index {
            Index(self.subtrees.endIndex)
        }

        @inlinable
        public func index(after i: Index) -> Index {
            Index(
                self.subtrees[i.wrapped...].dropFirst().firstIndex(where: {
                    guard case .dnsName = $0 else {
                        return false
                    }
                    return true
                }) ?? self.subtrees.endIndex
            )
        }

        @inlinable
        public subscript(position: Index) -> String {
            guard case .dnsName(let name) = self.subtrees[position.wrapped] else {
                fatalError("index \(position) is not a valid index for \(Self.self)")
            }
            return name
        }

        @inlinable
        var filtered: some Sequence<GeneralName> {
            self.subtrees.lazy.filter {
                guard case .dnsName = $0 else {
                    return false
                }
                return true
            }
        }
    }

    public struct IPRanges: Hashable, Sendable, Collection, ExpressibleByArrayLiteral, CustomStringConvertible {
        @inlinable
        public static func == (lhs: Self, rhs: Self) -> Bool {
            lhs.elementsEqual(rhs)
        }

        @usableFromInline
        var subtrees: [GeneralName]

        @inlinable
        public var description: String {
            "[\(self.lazy.map { String(describing: $0.bytes) }.joined(separator: ", "))]"
        }

        @inlinable
        init(subtrees: [GeneralName]) {
            self.subtrees = subtrees
        }

        @inlinable
        public init(_ elements: some Sequence<ASN1OctetString>) {
            self.subtrees = elements.map { .ipAddress($0) }
        }

        @inlinable
        public init(arrayLiteral elements: ASN1OctetString...) {
            self.init(elements)
        }

        @inlinable
        public func hash(into hasher: inout Hasher) {
            hasher.combine(contentsOf: self)
        }

        public struct Index: Comparable, Sendable {
            @inlinable
            public static func < (lhs: Self, rhs: Self) -> Bool {
                lhs.wrapped < rhs.wrapped
            }
            @usableFromInline
            var wrapped: Int

            @inlinable
            init(_ wrapped: Int) {
                self.wrapped = wrapped
            }
        }

        @inlinable
        public var startIndex: Index {
            Index(
                self.subtrees.firstIndex(where: {
                    guard case .ipAddress = $0 else {
                        return false
                    }
                    return true
                }) ?? self.subtrees.endIndex
            )
        }

        @inlinable
        public var endIndex: Index {
            Index(self.subtrees.endIndex)
        }

        @inlinable
        public func index(after i: Index) -> Index {
            Index(
                self.subtrees[i.wrapped...].dropFirst().firstIndex(where: {
                    guard case .ipAddress = $0 else {
                        return false
                    }
                    return true
                }) ?? self.subtrees.endIndex
            )
        }

        @inlinable
        public subscript(position: Index) -> ASN1OctetString {
            guard case .ipAddress(let ipAddress) = self.subtrees[position.wrapped] else {
                fatalError("index \(position) is not a valid index for \(Self.self)")
            }
            return ipAddress
        }

        @inlinable
        var filtered: some Sequence<GeneralName> {
            self.subtrees.lazy.filter {
                guard case .ipAddress = $0 else {
                    return false
                }
                return true
            }
        }
    }

    public struct EmailAddresses: Hashable, Sendable, Collection, ExpressibleByArrayLiteral, CustomStringConvertible {
        @inlinable
        public static func == (lhs: Self, rhs: Self) -> Bool {
            lhs.elementsEqual(rhs)
        }

        @usableFromInline
        var subtrees: [GeneralName]

        @inlinable
        public var description: String {
            "[\(self.joined(separator: ", "))]"
        }

        @inlinable
        init(subtrees: [GeneralName]) {
            self.subtrees = subtrees
        }

        @inlinable
        public init(_ elements: some Sequence<String>) {
            self.subtrees = elements.map { .rfc822Name($0) }
        }

        @inlinable
        public init(arrayLiteral elements: String...) {
            self.init(elements)
        }

        @inlinable
        public func hash(into hasher: inout Hasher) {
            hasher.combine(contentsOf: self)
        }

        public struct Index: Comparable, Sendable {
            @inlinable
            public static func < (lhs: Self, rhs: Self) -> Bool {
                lhs.wrapped < rhs.wrapped
            }
            @usableFromInline
            var wrapped: Int

            @inlinable
            init(_ wrapped: Int) {
                self.wrapped = wrapped
            }
        }

        @inlinable
        public var startIndex: Index {
            Index(
                self.subtrees.firstIndex(where: {
                    guard case .rfc822Name = $0 else {
                        return false
                    }
                    return true
                }) ?? self.subtrees.endIndex
            )
        }

        @inlinable
        public var endIndex: Index {
            Index(self.subtrees.endIndex)
        }

        @inlinable
        public func index(after i: Index) -> Index {
            Index(
                self.subtrees[i.wrapped...].dropFirst().firstIndex(where: {
                    guard case .rfc822Name = $0 else {
                        return false
                    }
                    return true
                }) ?? self.subtrees.endIndex
            )
        }

        @inlinable
        public subscript(position: Index) -> String {
            guard case .rfc822Name(let emailAddress) = self.subtrees[position.wrapped] else {
                fatalError("index \(position) is not a valid index for \(Self.self)")
            }
            return emailAddress
        }

        @inlinable
        var filtered: some Sequence<GeneralName> {
            self.subtrees.lazy.filter {
                guard case .rfc822Name = $0 else {
                    return false
                }
                return true
            }
        }
    }

    public struct URIDomains: Hashable, Sendable, Collection, ExpressibleByArrayLiteral, CustomStringConvertible {
        @inlinable
        public static func == (lhs: Self, rhs: Self) -> Bool {
            lhs.elementsEqual(rhs)
        }

        @usableFromInline
        var subtrees: [GeneralName]

        @inlinable
        public var description: String {
            "[\(self.joined(separator: ", "))]"
        }

        @inlinable
        init(subtrees: [GeneralName]) {
            self.subtrees = subtrees
        }

        @inlinable
        public init(_ elements: some Sequence<String>) {
            self.subtrees = elements.map { .uniformResourceIdentifier($0) }
        }

        @inlinable
        public init(arrayLiteral elements: String...) {
            self.init(elements)
        }

        @inlinable
        public func hash(into hasher: inout Hasher) {
            hasher.combine(contentsOf: self)
        }

        public struct Index: Comparable, Sendable {
            @inlinable
            public static func < (lhs: Self, rhs: Self) -> Bool {
                lhs.wrapped < rhs.wrapped
            }
            @usableFromInline
            var wrapped: Int

            @inlinable
            init(_ wrapped: Int) {
                self.wrapped = wrapped
            }
        }

        @inlinable
        public var startIndex: Index {
            Index(
                self.subtrees.firstIndex(where: {
                    guard case .uniformResourceIdentifier = $0 else {
                        return false
                    }
                    return true
                }) ?? self.subtrees.endIndex
            )
        }

        @inlinable
        public var endIndex: Index {
            Index(self.subtrees.endIndex)
        }

        @inlinable
        public func index(after i: Index) -> Index {
            Index(
                self.subtrees[i.wrapped...].dropFirst().firstIndex(where: {
                    guard case .uniformResourceIdentifier = $0 else {
                        return false
                    }
                    return true
                }) ?? self.subtrees.endIndex
            )
        }

        @inlinable
        public subscript(position: Index) -> String {
            guard case .uniformResourceIdentifier(let uri) = self.subtrees[position.wrapped] else {
                fatalError("index \(position) is not a valid index for \(Self.self)")
            }
            return uri
        }

        @inlinable
        var filtered: some Sequence<GeneralName> {
            self.subtrees.lazy.filter {
                guard case .uniformResourceIdentifier = $0 else {
                    return false
                }
                return true
            }
        }
    }

    /// The DNS name trees that are permitted in certificates issued by this CA.
    ///
    /// These restrictions are expressed in forms like `host.example.com`. Any DNS name that can be
    /// constructed by adding zero or more labels to the left-hand side of the name satisfies the constraint.
    public internal(set) var permittedDNSDomains: DNSNames {
        get {
            DNSNames(subtrees: permittedSubtrees)
        }
        set {
            permittedSubtrees.removeAll {
                guard case .dnsName = $0 else {
                    return false
                }
                return true
            }
            permittedSubtrees.append(contentsOf: newValue.filtered)
        }
    }

    /// The DNS name trees that are forbidden in certificates issued by this CA.
    ///
    /// These restrictions are expressed in forms like `host.example.com`. Any DNS name that can be
    /// constructed by adding zero or more labels to the left-hand side of the name satifies the constraint.
    public internal(set) var excludedDNSDomains: DNSNames {
        get {
            DNSNames(subtrees: excludedSubtrees)
        }
        set {
            excludedSubtrees.removeAll {
                guard case .dnsName = $0 else {
                    return false
                }
                return true
            }
            excludedSubtrees.append(contentsOf: newValue.filtered)
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
    public internal(set) var permittedIPRanges: IPRanges {
        get {
            IPRanges(subtrees: permittedSubtrees)
        }
        set {
            permittedSubtrees.removeAll {
                guard case .ipAddress = $0 else {
                    return false
                }
                return true
            }
            permittedSubtrees.append(contentsOf: newValue.filtered)
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
    public internal(set) var excludedIPRanges: IPRanges {
        get {
            IPRanges(subtrees: excludedSubtrees)
        }
        set {
            excludedSubtrees.removeAll {
                guard case .ipAddress = $0 else {
                    return false
                }
                return true
            }
            excludedSubtrees.append(contentsOf: newValue.filtered)
        }
    }

    /// The email addresses that are permitted in certificates issued by this CA.
    ///
    /// This form may contain a specific mailbox (e.g. `user@example.com`), all
    /// addresses on a given host (e.g. `example.com`), or all mailboxes within a
    /// given domain (e.g. `.example.com`).
    public internal(set) var permittedEmailAddresses: EmailAddresses {
        get {
            EmailAddresses(subtrees: permittedSubtrees)
        }
        set {
            permittedSubtrees.removeAll {
                guard case .rfc822Name = $0 else {
                    return false
                }
                return true
            }
            permittedSubtrees.append(contentsOf: newValue.filtered)
        }
    }

    /// The email addresses that are permitted in certificates issued by this CA.
    ///
    /// This form may contain a specific mailbox (e.g. `user@example.com`), all
    /// addresses on a given host (e.g. `example.com`), or all mailboxes within a
    /// given domain (e.g. `.example.com`).
    public internal(set) var excludedEmailAddresses: EmailAddresses {
        get {
            EmailAddresses(subtrees: excludedSubtrees)
        }
        set {
            excludedSubtrees.removeAll {
                guard case .rfc822Name = $0 else {
                    return false
                }
                return true
            }
            excludedSubtrees.append(contentsOf: newValue.filtered)
        }
    }

    /// The URI domains permitted in certificates issued by this CA.
    ///
    /// This constraint applies only to the host part of the URI. The constraint
    /// must be specified as a fully-qualified domain name and may specify either
    /// a host or a domain. When it specifies a domain the string will begin with a
    /// period, and matches any name that can be expanded with one or more labels to
    /// the left. Note that expanding with zero labels does not match: that is,
    /// `.example.com` matches `host.example.com`, but not `example.com`.
    public internal(set) var permittedURIDomains: URIDomains {
        get {
            URIDomains(subtrees: permittedSubtrees)
        }
        set {
            permittedSubtrees.removeAll {
                guard case .uniformResourceIdentifier = $0 else {
                    return false
                }
                return true
            }
            permittedSubtrees.append(contentsOf: newValue.filtered)
        }
    }

    /// The URI domains forbidden in certificates issued by this CA.
    ///
    /// This constraint applies only to the host part of the URI. The constraint
    /// must be specified as a fully-qualified domain name and may specify either
    /// a host or a domain. When it specifies a domain the string will begin with a
    /// period, and matches any name that can be expanded with one or more labels to
    /// the left. Note that expanding with zero labels does not match: that is,
    /// `.example.com` matches `host.example.com`, but not `example.com`.
    public internal(set) var forbiddenURIDomains: URIDomains {
        get {
            URIDomains(subtrees: excludedSubtrees)
        }
        set {
            excludedSubtrees.removeAll {
                guard case .uniformResourceIdentifier = $0 else {
                    return false
                }
                return true
            }
            excludedSubtrees.append(contentsOf: newValue.filtered)
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
    ///   - excludedEmailAddresses: The email address trees that are forbidden in certificates issued by this CA.
    ///   - permittedURIDomains: The URI domains that are permitted in certificates issued by this CA.
    ///   - forbiddenURIDomains: The URI domains that are forbidden in certificates issued by this CA.
    @inlinable
    public init(
        permittedDNSDomains: some Sequence<String> = [],
        excludedDNSDomains: some Sequence<String> = [],
        permittedIPRanges: some Sequence<ASN1OctetString> = [],
        excludedIPRanges: some Sequence<ASN1OctetString> = [],
        permittedEmailAddresses: some Sequence<String> = [],
        excludedEmailAddresses: some Sequence<String> = [],
        permittedURIDomains: some Sequence<String> = [],
        forbiddenURIDomains: some Sequence<String> = []
    ) {
        self.permittedSubtrees = []
        self.permittedSubtrees.reserveCapacity(
            permittedDNSDomains.underestimatedCount + permittedIPRanges.underestimatedCount
                + permittedEmailAddresses.underestimatedCount + permittedURIDomains.underestimatedCount
        )
        self.permittedSubtrees.append(contentsOf: permittedDNSDomains.lazy.map { .dnsName($0) })
        self.permittedSubtrees.append(contentsOf: permittedIPRanges.lazy.map { .ipAddress($0) })
        self.permittedSubtrees.append(contentsOf: permittedEmailAddresses.lazy.map { .rfc822Name($0) })
        self.permittedSubtrees.append(contentsOf: permittedURIDomains.lazy.map { .uniformResourceIdentifier($0) })

        self.excludedSubtrees = []
        self.excludedSubtrees.reserveCapacity(
            excludedDNSDomains.underestimatedCount + excludedIPRanges.underestimatedCount
                + excludedEmailAddresses.underestimatedCount + forbiddenURIDomains.underestimatedCount
        )
        self.excludedSubtrees.append(contentsOf: excludedDNSDomains.lazy.map { .dnsName($0) })
        self.excludedSubtrees.append(contentsOf: excludedIPRanges.lazy.map { .ipAddress($0) })
        self.excludedSubtrees.append(contentsOf: excludedEmailAddresses.lazy.map { .rfc822Name($0) })
        self.excludedSubtrees.append(contentsOf: forbiddenURIDomains.lazy.map { .uniformResourceIdentifier($0) })
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
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    public init(_ ext: Certificate.Extension) throws {
        guard ext.oid == .X509ExtensionID.nameConstraints else {
            throw CertificateError.incorrectOIDForExtension(
                reason: "Expected \(ASN1ObjectIdentifier.X509ExtensionID.nameConstraints), got \(ext.oid)"
            )
        }

        let nameConstraintsValue = try NameConstraintsValue(derEncoded: ext.value)
        guard nameConstraintsValue.permittedSubtrees != nil || nameConstraintsValue.excludedSubtrees != nil else {
            throw ASN1Error.invalidASN1Object(reason: "Name Constraints has no permitted or excluded subtrees")
        }

        self.permittedSubtrees = nameConstraintsValue.permittedSubtrees ?? []
        self.excludedSubtrees = nameConstraintsValue.excludedSubtrees ?? []
    }
}

extension Hasher {
    @inlinable
    mutating func combine(contentsOf elements: some Sequence<some Hashable>) {
        for element in elements {
            self.combine(element)
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension NameConstraints: Hashable {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension NameConstraints: Sendable {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension NameConstraints: CustomStringConvertible {
    public var description: String {
        var elements: [String] = []

        if self.permittedSubtrees.count > 0 {
            elements.append(
                "permittedSubtrees: [\(self.permittedSubtrees.map { String(reflecting: $0) }.joined(separator: ", "))]"
            )
        }
        if self.excludedSubtrees.count > 0 {
            elements.append(
                "excludedSubtrees: [\(self.excludedSubtrees.map { String(reflecting: $0) }.joined(separator: ", "))]"
            )
        }

        return elements.joined(separator: ", ")
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension NameConstraints: CustomDebugStringConvertible {
    public var debugDescription: String {
        return "NameConstraints(\(String(describing: self)))"
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
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

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension NameConstraints: CertificateExtensionConvertible {
    public func makeCertificateExtension() throws -> Certificate.Extension {
        return try .init(self, critical: false)
    }
}

// MARK: ASN1 Helpers
@usableFromInline
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
struct NameConstraintsValue: DERImplicitlyTaggable, Sendable {
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
            let permittedSubtrees: GeneralSubtrees? = try DER.optionalImplicitlyTagged(
                &nodes,
                tag: .init(tagWithNumber: 0, tagClass: .contextSpecific)
            )
            let excludedSubtrees: GeneralSubtrees? = try DER.optionalImplicitlyTagged(
                &nodes,
                tag: .init(tagWithNumber: 1, tagClass: .contextSpecific)
            )

            return NameConstraintsValue(
                permittedSubtrees: permittedSubtrees.map { $0.base },
                excludedSubtrees: excludedSubtrees.map { $0.base }
            )
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

// This type does a weird cheat.
//
// Technically, NameConstraints is defined like this:
//
//       NameConstraints ::= SEQUENCE {
//            permittedSubtrees       [0]     GeneralSubtrees OPTIONAL,
//            excludedSubtrees        [1]     GeneralSubtrees OPTIONAL }
//
//       GeneralSubtrees ::= SEQUENCE SIZE (1..MAX) OF GeneralSubtree
//
//       GeneralSubtree ::= SEQUENCE {
//            base                    GeneralName,
//            minimum         [0]     BaseDistance DEFAULT 0,
//            maximum         [1]     BaseDistance OPTIONAL }
//
//       BaseDistance ::= INTEGER (0..MAX)
//
// We can disregard `BaseDistance`, because as a practical matter it is never used, and so it's as though those
// two fields were never there.
//
// The result is that each of the subtrees encodes as a sequence of sequence of single general name. We could
// literally mirror that in Swift land, but at the top level we want to hold [GeneralName], so producing
// [GeneralSubtree] will force a heap allocation. Instead, we inline the definition of GeneralSubtree into
// GeneralSubtrees, to avoid the extra allocation.
@usableFromInline
struct GeneralSubtrees: DERImplicitlyTaggable, Sendable {
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
        self.base = try DER.sequence(rootNode, identifier: identifier) { nodes in
            var names: [GeneralName] = []
            while let node = nodes.next() {
                let name = try DER.sequence(node, identifier: .sequence) { nodes in
                    try GeneralName(derEncoded: &nodes)
                }
                names.append(name)
            }
            return names
        }
    }

    @inlinable
    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            for name in self.base {
                try coder.appendConstructedNode(identifier: .sequence) { coder in
                    try coder.serialize(name)
                }
            }
        }
    }
}
