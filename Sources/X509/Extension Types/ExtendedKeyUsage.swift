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

/// Indicates one or more purposes for which the certified public key
/// may be used, in addition to or instead of the the purposes indicated
/// in the ``KeyUsage`` extension.
public struct ExtendedKeyUsage {
    @usableFromInline
    var usages: [Usage]

    /// Construct an ``ExtendedKeyUsage`` extension containing the
    /// given usages.
    ///
    /// - Parameter usages: The purposes for which the certificate may be used.
    @inlinable
    public init<Usages: Sequence>(_ usages: Usages) throws where Usages.Element == Usage {
        self.usages = Array(usages)

        // This limit is somewhat arbitrary. Linear search for under 32 elements
        // is faster than hashing and fast enough to not be a significant performance bottleneck.
        // We have this limit because a bad actor could increase the number of elements to an arbitrary number which
        // will increase our decoding time exponentially.
        // This can be used for DoS attacks so we have added this limit.
        let maxUsages = 32
        guard self.usages.count <= maxUsages else {
            throw ASN1Error.invalidASN1Object(
                reason: "Too many extended key usages. Found \(self.usages.count) but only \(maxUsages) are allowed."
            )
        }

        if let (firstIndex, secondIndex) = self.usages.findDuplicates(by: ==) {
            let usage = self.usages[firstIndex]
            throw CertificateError.duplicateOID(
                reason: "duplicate \(usage) usage. First at \(firstIndex) and second at \(secondIndex)"
            )
        }
    }

    /// Create a new ``ExtendedKeyUsage`` object
    /// by unwrapping a ``Certificate/Extension``.
    ///
    /// - Parameter ext: The ``Certificate/Extension`` to unwrap
    /// - Throws: if the ``Certificate/Extension/oid`` is not equal to
    ///     `ASN1ObjectIdentifier.X509ExtensionID.extendedKeyUsage`.
    @inlinable
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    public init(_ ext: Certificate.Extension) throws {
        guard ext.oid == .X509ExtensionID.extendedKeyUsage else {
            throw CertificateError.incorrectOIDForExtension(
                reason: "Expected \(ASN1ObjectIdentifier.X509ExtensionID.extendedKeyUsage), got \(ext.oid)"
            )
        }

        let asn1EKU = try ASN1ExtendedKeyUsage(derEncoded: ext.value)
        try self.init(asn1EKU.usages.map { Usage(oid: $0) })
    }

    /// Create a new empty ``ExtendedKeyUsage`` object with no usages.
    @inlinable
    public init() {
        self.usages = []
    }
}

extension Array {
    @inlinable
    /// Searches for duplicates using a linear scan.
    /// This is more performant compared to hashing if we have less than ~64 usages
    /// - Parameter areEqual: a predicate that returns true if the first and second arguments are considered equal
    /// - Returns: a tuple of the first two indices duplicates found in `self`. `nil` is returned if no duplicates are found.
    func findDuplicates(
        by areEqual: (Element, Element) -> Bool
    ) -> (first: Index, second: Index)? {
        for index in self.indices {
            let usage = self[index]
            for currentIndex in self.indices[index...].dropFirst() {
                let currentUsage = self[currentIndex]
                if areEqual(usage, currentUsage) {
                    return (index, currentIndex)
                }
            }
        }
        return nil
    }
}

extension ExtendedKeyUsage: Hashable {}

extension ExtendedKeyUsage: Sendable {}

extension ExtendedKeyUsage: CustomStringConvertible {
    public var description: String {
        return self.map {
            String(reflecting: $0)
        }.joined(separator: ", ")
    }
}

extension ExtendedKeyUsage: CustomDebugStringConvertible {
    public var debugDescription: String {
        "ExtendedKeyUsage(\(String(describing: self)))"
    }
}

extension ExtendedKeyUsage: RandomAccessCollection {
    public var startIndex: Int {
        self.usages.startIndex
    }

    public var endIndex: Int {
        self.usages.endIndex
    }

    public subscript(position: Int) -> Usage {
        get {
            self.usages[position]
        }
    }
}

extension ExtendedKeyUsage {
    /// Append a new `usage` to the end of the ``ExtendedKeyUsage``, if it doesn't
    /// already contain it.
    ///
    /// - Parameter usage: The ``Usage`` to add to the set.
    ///
    /// - Returns: A pair `(inserted, index)`, where `inserted` is a Boolean value
    ///    indicating whether the operation added a new element, and `index` is
    ///    the index of `usage` in the resulting ``ExtendedKeyUsage``.
    @inlinable
    @discardableResult
    public mutating func append(_ usage: Element) -> (inserted: Bool, index: Int) {
        self.insert(usage, at: self.endIndex)
    }

    /// Insert a new `usage` to this set at the specified index, if `self` doesn't
    /// already contain it.
    ///
    /// - Parameters:
    ///     - usage: The ``Usage`` to insert if not already present.
    ///     - index: The index to insert `usage` if not already present.
    ///
    /// - Returns: A pair `(inserted, index)`, where `inserted` is a Boolean value
    ///    indicating whether the operation added a new element, and `index` is
    ///    the index of `item` in the resulting set. If `inserted` is false, then
    ///    the returned `index` may be different from the index requested.
    @inlinable
    @discardableResult
    public mutating func insert(
        _ usage: Element,
        at index: Int
    ) -> (inserted: Bool, index: Int) {
        guard let index = self.usages.firstIndex(of: usage) else {
            self.usages.insert(usage, at: index)
            return (true, index)
        }
        return (false, index)
    }

    /// Removes the given `usage` from `self`, if present.
    /// - Parameter usage: The  ``Usage`` to remove.
    /// - Returns: The ``Usage`` that was removed or `nil` if `usage` was not present.
    @inlinable
    @discardableResult
    public mutating func remove(_ usage: Element) -> Element? {
        guard let index = self.usages.firstIndex(where: { $0 == usage }) else {
            return nil
        }
        return self.usages.remove(at: index)
    }
}

extension ExtendedKeyUsage {
    /// An acceptable usage for a certificate as attested in an
    /// ``ExtendedKeyUsage``
    /// extension.
    public struct Usage {
        @usableFromInline
        enum Backing {
            case serverAuth
            case clientAuth
            case codeSigning
            case emailProtection
            case timeStamping
            case ocspSigning
            case any
            case certificateTransparency
            case unknown(ASN1ObjectIdentifier)
        }

        @usableFromInline
        var backing: Backing

        @inlinable
        init(_ backing: Backing) {
            self.backing = backing
        }

        /// Constructs a ``ExtendedKeyUsage/Usage`` from an opaque oid.
        ///
        /// - Parameter oid: The OID of the usage.
        @inlinable
        public init(oid: ASN1ObjectIdentifier) {
            switch oid {
            case .ExtendedKeyUsage.serverAuth:
                self = .serverAuth
            case .ExtendedKeyUsage.clientAuth:
                self = .clientAuth
            case .ExtendedKeyUsage.codeSigning:
                self = .codeSigning
            case .ExtendedKeyUsage.emailProtection:
                self = .emailProtection
            case .ExtendedKeyUsage.timeStamping:
                self = .timeStamping
            case .ExtendedKeyUsage.ocspSigning:
                self = .ocspSigning
            case .ExtendedKeyUsage.any:
                self = .any
            case .ExtendedKeyUsage.certificateTransparency:
                self = .certificateTransparency
            default:
                self.backing = .unknown(oid)
            }
        }

        /// The public key may be used for TLS web servers.
        public static let serverAuth = Self(.serverAuth)

        /// The public key may be used for TLS web client authentication.
        public static let clientAuth = Self(.clientAuth)

        /// The public key may be used for signing of downloadable executable code.
        public static let codeSigning = Self(.codeSigning)

        /// The public key may be used for email protection.
        public static let emailProtection = Self(.emailProtection)

        /// The public key may be used for binding the hash of an object to a time.
        public static let timeStamping = Self(.timeStamping)

        /// The public key may be used for signing OCSP responses.
        public static let ocspSigning = Self(.ocspSigning)

        /// The public key may be used for any purpose.
        public static let any = Self(.any)

        /// The public key may be used for signing certificate transparency precertificates.
        public static let certificateTransparency = Self(.certificateTransparency)
    }
}

extension ExtendedKeyUsage.Usage: Hashable {}

extension ExtendedKeyUsage.Usage: Sendable {}

extension ExtendedKeyUsage.Usage: CustomStringConvertible {
    public var description: String {
        switch self.backing {
        case .any:
            return "anyKeyUsage"
        case .serverAuth:
            return "serverAuth"
        case .clientAuth:
            return "clientAuth"
        case .codeSigning:
            return "codeSigning"
        case .emailProtection:
            return "emailProtection"
        case .timeStamping:
            return "timeStamping"
        case .ocspSigning:
            return "ocspSigning"
        case .certificateTransparency:
            return "certificateTransparency"
        case .unknown(let oid):
            return String(describing: oid)
        }
    }
}

extension ExtendedKeyUsage.Usage: CustomDebugStringConvertible {
    public var debugDescription: String {
        switch self.backing {
        case .any:
            return "anyKeyUsage"
        case .serverAuth:
            return "serverAuth"
        case .clientAuth:
            return "clientAuth"
        case .codeSigning:
            return "codeSigning"
        case .emailProtection:
            return "emailProtection"
        case .timeStamping:
            return "timeStamping"
        case .ocspSigning:
            return "ocspSigning"
        case .certificateTransparency:
            return "certificateTransparency"
        case .unknown(let oid):
            return String(reflecting: oid)
        }
    }
}

extension ExtendedKeyUsage.Usage.Backing: Hashable {}

extension ExtendedKeyUsage.Usage.Backing: Sendable {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.Extension {
    /// Construct an opaque ``Certificate/Extension`` from this Extended Key Usage extension.
    ///
    /// - Parameters:
    ///   - eku: The extension to wrap
    ///   - critical: Whether this extension should have the critical bit set.
    @inlinable
    public init(_ eku: ExtendedKeyUsage, critical: Bool) throws {
        let asn1Representation = ASN1ExtendedKeyUsage(eku)
        var serializer = DER.Serializer()
        try serializer.serialize(asn1Representation)
        self.init(oid: .X509ExtensionID.extendedKeyUsage, critical: critical, value: serializer.serializedBytes[...])
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension ExtendedKeyUsage: CertificateExtensionConvertible {
    public func makeCertificateExtension() throws -> Certificate.Extension {
        return try .init(self, critical: false)
    }
}

extension ASN1ObjectIdentifier {
    /// Construct the OID corresponding to a specific extended key usage.
    ///
    /// - Parameter usage: the EKU to use to construct the OID.
    @inlinable
    public init(_ usage: X509.ExtendedKeyUsage.Usage) {
        switch usage.backing {
        case .serverAuth:
            self = .ExtendedKeyUsage.serverAuth
        case .clientAuth:
            self = .ExtendedKeyUsage.clientAuth
        case .codeSigning:
            self = .ExtendedKeyUsage.codeSigning
        case .emailProtection:
            self = .ExtendedKeyUsage.emailProtection
        case .timeStamping:
            self = .ExtendedKeyUsage.timeStamping
        case .ocspSigning:
            self = .ExtendedKeyUsage.ocspSigning
        case .any:
            self = .ExtendedKeyUsage.any
        case .certificateTransparency:
            self = .ExtendedKeyUsage.certificateTransparency
        case .unknown(let oid):
            self = oid
        }
    }

    /// An acceptable usage for a certificate as attested in an
    /// ``ExtendedKeyUsage``
    /// extension.
    public enum ExtendedKeyUsage: Sendable {
        /// The public key may be used for any purpose.
        public static let any: ASN1ObjectIdentifier = [2, 5, 29, 37, 0]

        /// The public key may be used for TLS web servers.
        public static let serverAuth: ASN1ObjectIdentifier = [1, 3, 6, 1, 5, 5, 7, 3, 1]

        /// The public key may be used for TLS web client authentication.
        public static let clientAuth: ASN1ObjectIdentifier = [1, 3, 6, 1, 5, 5, 7, 3, 2]

        /// The public key may be used for signing of downloadable executable code.
        public static let codeSigning: ASN1ObjectIdentifier = [1, 3, 6, 1, 5, 5, 7, 3, 3]

        /// The public key may be used for email protection.
        public static let emailProtection: ASN1ObjectIdentifier = [1, 3, 6, 1, 5, 5, 7, 3, 4]

        /// The public key may be used for binding the hash of an object to a time.
        public static let timeStamping: ASN1ObjectIdentifier = [1, 3, 6, 1, 5, 5, 7, 3, 8]

        /// The public key may be used for signing OCSP responses.
        public static let ocspSigning: ASN1ObjectIdentifier = [1, 3, 6, 1, 5, 5, 7, 3, 9]

        /// The public key may be used for signing certificate transparency precertificates.
        public static let certificateTransparency: ASN1ObjectIdentifier = [1, 3, 6, 1, 4, 1, 11129, 2, 4, 4]
    }
}

@usableFromInline
struct ASN1ExtendedKeyUsage: DERImplicitlyTaggable, Sendable {
    @inlinable
    static var defaultIdentifier: ASN1Identifier {
        .sequence
    }

    @usableFromInline
    var usages: [ASN1ObjectIdentifier]

    @inlinable
    init(_ usages: [ASN1ObjectIdentifier]) {
        self.usages = usages
    }

    @inlinable
    init(_ eku: ExtendedKeyUsage) {
        self.usages = eku.usages.map { ASN1ObjectIdentifier($0) }
    }

    @inlinable
    init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self.usages = try DER.sequence(identifier: identifier, rootNode: rootNode)
    }

    @inlinable
    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.serializeSequenceOf(self.usages, identifier: identifier)
    }
}
