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
    /// Indicates one or more purposes for which the certified public key
    /// may be used, in addition to or instead of the the purposes indicated
    /// in the ``KeyUsage-swift.struct`` extension.
    public struct ExtendedKeyUsage {
        @usableFromInline
        var usages: [Usage]

        /// Construct an ``Certificate/Extensions-swift.struct/ExtendedKeyUsage-swift.struct`` extension containing the
        /// given usages.
        ///
        /// - Parameter usages: The purposes for which the certificate may be used.
        @inlinable
        public init<Usages: Sequence>(_ usages: Usages) where Usages.Element == Usage {
            self.usages = Array(usages)
        }

        /// Create a new ``Certificate/Extensions-swift.struct/ExtendedKeyUsage-swift.struct`` object
        /// by unwrapping a ``Certificate/Extension``.
        ///
        /// - Parameter ext: The ``Certificate/Extension`` to unwrap
        /// - Throws: if the ``Certificate/Extension/oid`` is not equal to
        ///     `ASN1ObjectIdentifier.X509ExtensionID.extendedKeyUsage`.
        @inlinable
        public init(_ ext: Certificate.Extension) throws {
            guard ext.oid == .X509ExtensionID.extendedKeyUsage else {
                throw CertificateError.incorrectOIDForExtension(reason: "Expected \(ASN1ObjectIdentifier.X509ExtensionID.extendedKeyUsage), got \(ext.oid)")
            }

            let asn1EKU = try ASN1ExtendedKeyUsage(derEncoded: ext.value)
            self.usages = asn1EKU.usages.map { Usage(oid: $0) }
        }
    }
}

extension Certificate.Extensions.ExtendedKeyUsage: Hashable { }

extension Certificate.Extensions.ExtendedKeyUsage: Sendable { }

extension Certificate.Extensions.ExtendedKeyUsage: CustomStringConvertible {
    public var description: String {
        return self.map {
            String(describing: $0)
        }.joined(separator: ", ")
    }
}

// TODO(cory): Probably also RangeReplaceableCollection, even though it's kinda crap.
extension Certificate.Extensions.ExtendedKeyUsage: RandomAccessCollection {
    public var startIndex: Int {
        self.usages.startIndex
    }

    public var endIndex: Int {
        self.usages.endIndex
    }

    public subscript(position: Int) -> Usage {
        // TODO(cory): Maintain uniqueness
        get {
            self.usages[position]
        }
        set {
            self.usages[position] = newValue
        }
    }
}

extension Certificate.Extensions.ExtendedKeyUsage {
    /// An acceptable usage for a certificate as attested in an
    /// ``Certificate/Extensions-swift.struct/ExtendedKeyUsage-swift.struct``
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

        /// Constructs a ``Certificate/Extensions-swift.struct/ExtendedKeyUsage-swift.struct/Usage`` from an opaque oid.
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

extension Certificate.Extensions.ExtendedKeyUsage.Usage: Hashable { }

extension Certificate.Extensions.ExtendedKeyUsage.Usage: Sendable { }

extension Certificate.Extensions.ExtendedKeyUsage.Usage: CustomStringConvertible {
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

extension Certificate.Extensions.ExtendedKeyUsage.Usage.Backing: Hashable { }

extension Certificate.Extensions.ExtendedKeyUsage.Usage.Backing: Sendable { }

extension Certificate.Extension {
    /// Construct an opaque ``Certificate/Extension`` from this Extended Key Usage extension.
    ///
    /// - Parameters:
    ///   - eku: The extension to wrap
    ///   - critical: Whether this extension should have the critical bit set.
    @inlinable
    public init(_ eku: Certificate.Extensions.ExtendedKeyUsage, critical: Bool) throws {
        let asn1Representation = ASN1ExtendedKeyUsage(eku)
        var serializer = DER.Serializer()
        try serializer.serialize(asn1Representation)
        self.init(oid: .X509ExtensionID.extendedKeyUsage, critical: critical, value: serializer.serializedBytes[...])
    }
}

extension Certificate.Extensions.ExtendedKeyUsage: CertificateExtensionConvertible {
    public func makeCertificateExtension() throws -> Certificate.Extension {
        return try .init(self, critical: false)
    }
}

extension ASN1ObjectIdentifier {
    /// Construct the OID corresponding to a specific extended key usage.
    ///
    /// - Parameter usage: the EKU to use to construct the OID.
    @inlinable
    public init(_ usage: Certificate.Extensions.ExtendedKeyUsage.Usage) {
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
    /// ``Certificate/Extensions-swift.struct/ExtendedKeyUsage-swift.struct``
    /// extension.
    public enum ExtendedKeyUsage {
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
struct ASN1ExtendedKeyUsage: DERImplicitlyTaggable {
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
    init(_ eku: Certificate.Extensions.ExtendedKeyUsage) {
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
