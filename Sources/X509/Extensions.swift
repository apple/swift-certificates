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

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate {
    /// A representation of a collection of X.509 extensions.
    ///
    /// The majority of semantic information in an X.509 certificate is contained within its
    /// collection of extensions. These extensions can add additional constraints or capabilities
    /// to a certificate, or provide additional information about either the subject or the issuer
    /// of the certificate.
    ///
    /// Each extension may appear only once in a given certificate. It may be marked as either critical
    /// or not. Critical extensions require that the user of a certificate understands the meaning of that
    /// extension (and can enforce it) in order to trust the certificate: if the user does not understand
    /// or cannot enforce that extension, it must reject the certificate outright.
    ///
    /// ### Sequence and Collection Helpers
    ///
    /// ``Certificate/Extensions-swift.struct`` is conceptually a collection of ``Certificate/Extension`` objects. The order
    /// is semantic and is preserved either in or from the serialized representation.
    ///
    /// However, ``Certificate/Extensions-swift.struct`` is also conceptually a dictionary keyed by ``Certificate/Extension/oid``.
    /// For that reason, in addition to the index-based subscript ``subscript(_:)-5rodj``, this type also offers
    /// ``subscript(oid:)`` to enable finding the extension with a specific OID. This API also lets users replace
    /// the value of a specific extension.
    ///
    /// ### Specific extension helpers
    ///
    /// To make it easier to decode specific extensions, this type provides a number of helpers for known extension types:
    ///
    /// - ``authorityInformationAccess``
    /// - ``subjectKeyIdentifier``
    /// - ``authorityKeyIdentifier``
    /// - ``extendedKeyUsage``
    /// - ``basicConstraints``
    /// - ``keyUsage``
    /// - ``nameConstraints``
    /// - ``subjectAlternativeNames``
    ///
    /// Users who add their own extension types (see ``Certificate/Extension`` for more) are encouraged to add their
    /// own helper getters for those types.
    ///
    /// ### Builder
    ///
    /// Constructing ``Certificate/Extensions-swift.struct`` can be somewhat awkward due to the opaque nature of ``Certificate/Extension``.
    /// To make this easier, ``Certificate/Extensions-swift.struct`` supports being constructed using a result builder DSL powered by ``ExtensionsBuilder``
    /// and ``CertificateExtensionConvertible``, using ``init(builder:)``. As an example, we can create a simple set of
    /// extensions like this:
    ///
    /// ```swift
    /// let extensions = Certificate.Extensions {
    ///     Critical(
    ///         KeyUsage(digitalSignature: true, keyCertSign: true, cRLSign: true)
    ///     )
    ///
    ///     ExtendedKeyUsage([.serverAuth, .clientAuth])
    ///
    ///     Critical(
    ///         BasicConstraints.isCertificateAuthority(maxPathLength: 0)
    ///     )
    ///
    ///     AuthorityInformationAccess([.init(method: .ocspServer, location: .uniformResourceIdentifier("http://ocsp.digicert.com"))])
    /// }
    /// ```
    ///
    /// This interface also makes it easy to mark specific extensions as critical.
    public struct Extensions {
        @usableFromInline
        var _extensions: [Certificate.Extension]

        /// Produce a new Extensions container from a collection of ``Certificate/Extension``.
        ///
        /// - Parameter extensions: The base extensions.
        /// - Throws: if multiple extensions have the same OID
        @inlinable
        public init<Elements>(_ extensions: Elements) throws where Elements: Sequence, Elements.Element == Extension {
            self._extensions = Array(extensions)

            // This limit is somewhat arbitrary. Linear search for under 32 elements
            // is faster than hashing and fast enough to not be a significant performance bottleneck.
            // We have this limit because a bad actor could increase the number of elements to an arbitrary number which
            // will increase our decoding time exponentially.
            // This can be used for DoS attacks so we have added this limit.
            let maxExtensions = 32
            guard self._extensions.count <= maxExtensions else {
                throw ASN1Error.invalidASN1Object(
                    reason:
                        "Too many extensions. Found \(self._extensions.count) but only \(maxExtensions) are allowed."
                )
            }

            if let (firstIndex, secondIndex) = self._extensions.findDuplicates(by: { $0.oid == $1.oid }) {
                let firstExt = self._extensions[firstIndex]
                let secondExt = self._extensions[secondIndex]
                throw CertificateError.duplicateOID(
                    reason:
                        "duplicate extension for OID \(firstExt.oid). First extension \(firstExt) at \(firstIndex) and second extension \(secondExt) at \(secondIndex)"
                )
            }
        }

        /// Construct a collection of extensions using the ``ExtensionsBuilder`` syntax.
        ///
        /// Constructing ``Certificate/Extensions-swift.struct`` can be somewhat awkward due to the opaque nature of ``Certificate/Extension``.
        /// To make this easier, ``Certificate/Extensions-swift.struct`` supports being constructed using a result builder DSL powered by ``ExtensionsBuilder``
        /// and ``CertificateExtensionConvertible``, using ``init(builder:)``. As an example, we can create a simple set of
        /// extensions like this:
        ///
        /// ```swift
        /// let extensions = Certificate.Extensions {
        ///     Critical(
        ///         KeyUsage(digitalSignature: true, keyCertSign: true, cRLSign: true)
        ///     )
        ///
        ///     ExtendedKeyUsage([.serverAuth, .clientAuth])
        ///
        ///     Critical(
        ///         BasicConstraints.isCertificateAuthority(maxPathLength: 0)
        ///     )
        ///
        ///     AuthorityInformationAccess([.init(method: .ocspServer, location: .uniformResourceIdentifier("http://ocsp.digicert.com"))])
        /// }
        /// ```
        ///
        /// - Parameter builder: The ``ExtensionsBuilder`` DSL.
        @inlinable
        public init(@ExtensionsBuilder builder: () throws -> Result<Certificate.Extensions, any Error>) throws {
            self = try builder().get()
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.Extensions: Hashable {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.Extensions: Sendable {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.Extensions: RandomAccessCollection {
    /// Produce a new empty Extensions container.
    @inlinable
    public init() {
        self._extensions = []
    }

    @inlinable
    public var startIndex: Int {
        self._extensions.startIndex
    }

    @inlinable
    public var endIndex: Int {
        self._extensions.endIndex
    }

    @inlinable
    public subscript(position: Int) -> Certificate.Extension {
        get {
            self._extensions[position]
        }
    }
}

// MARK: Modifying methods
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.Extensions {

    /// Append a new ``Certificate/Extension`` into this set of ``Certificate/Extensions-swift.struct``.
    ///
    /// - Parameter extension: The ``Certificate/Extension`` to insert.
    /// - Throws: If an ``Certificate/Extension`` with the same ``Certificate/Extension/oid`` is already present
    @inlinable
    public mutating func append(_ extension: Certificate.Extension) throws {
        if let oldExtension = self._extensions.first(where: { $0.oid == `extension`.oid }) {
            throw CertificateError.duplicateOID(
                reason:
                    "tried to append an extension for OID \(`extension`.oid) which is already present. Old extension: \(oldExtension) New extension: \(`extension`)"
            )
        } else {
            self._extensions.append(`extension`)
        }
    }

    /// Updates the ``Certificate/Extension`` stored in the dictionary for the ``Certificate/Extension/oid`` of the `extension`,
    /// or appends `extension` if an ``Certificate/Extension`` with same  ``Certificate/Extension/oid`` does not exist.
    ///
    /// - Parameter extension: The ``Certificate/Extension`` to update or append.
    /// - Returns: The old ``Certificate/Extension`` that was replaced or `nil` if no ``Certificate/Extension`` with same ``Certificate/Extension/oid`` was present
    @inlinable
    @discardableResult
    public mutating func update(_ extension: Certificate.Extension) -> Certificate.Extension? {
        guard let index = self._extensions.firstIndex(where: { $0.oid == `extension`.oid }) else {
            self._extensions.append(`extension`)
            return nil
        }
        let oldExtension = self._extensions[index]
        self._extensions[index] = `extension`
        return oldExtension
    }

    /// Removes the ``Certificate/Extension`` with the given `oid`.
    /// - Parameter oid: The  ``Certificate/Extension/oid`` of the``Certificate/Extension`` to remove.
    /// - Returns: The ``Certificate/Extension`` that was removed,
    ///     or `nil` if an ``Certificate/Extension`` was not present in with the given `oid`.
    @inlinable
    @discardableResult
    public mutating func remove(_ oid: ASN1ObjectIdentifier) -> Certificate.Extension? {
        guard let index = self._extensions.firstIndex(where: { $0.oid == oid }) else {
            return nil
        }
        return self._extensions.remove(at: index)
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.Extensions: CustomStringConvertible {
    @inlinable
    public var description: String {
        guard self.isEmpty else {
            return self._extensions.lazy.map { String(reflecting: $0) }.joined(separator: ", ")
        }
        return "(none)"
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.Extensions: CustomDebugStringConvertible {
    public var debugDescription: String {
        "[\(String(describing: self))]"
    }
}

// MARK: Helpers for specific extensions
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.Extensions {
    /// Look up a specific extension by its OID.
    ///
    /// - Parameter oid: The OID to search for.
    @inlinable
    public subscript(oid oid: ASN1ObjectIdentifier) -> Certificate.Extension? {
        get {
            self._extensions.first(where: { $0.oid == oid })
        }
        set {
            if let newValue = newValue {
                precondition(oid == newValue.oid)
                self.update(newValue)
            } else {
                self.remove(oid)
            }
        }
    }

    /// Loads the ``AuthorityInformationAccess``
    /// extension, if it is present.
    ///
    /// Throws if it is not possible to decode the AIA extension.
    @inlinable
    public var authorityInformationAccess: AuthorityInformationAccess? {
        get throws {
            try self[oid: .X509ExtensionID.authorityInformationAccess].map { try .init($0) }
        }
    }

    /// Loads the ``SubjectKeyIdentifier``
    /// extension, if it is present.
    ///
    /// Throws if it is not possible to decode the SKI extension.
    @inlinable
    public var subjectKeyIdentifier: SubjectKeyIdentifier? {
        get throws {
            try self[oid: .X509ExtensionID.subjectKeyIdentifier].map { try .init($0) }
        }
    }

    /// Loads the ``AuthorityKeyIdentifier``
    /// extension, if it is present.
    ///
    /// Throws if it is not possible to decode the AKI extension.
    @inlinable
    public var authorityKeyIdentifier: AuthorityKeyIdentifier? {
        get throws {
            try self[oid: .X509ExtensionID.authorityKeyIdentifier].map { try .init($0) }
        }
    }

    /// Loads the ``ExtendedKeyUsage``
    /// extension, if it is present.
    ///
    /// Throws if it is not possible to decode the EKU extension.
    @inlinable
    public var extendedKeyUsage: ExtendedKeyUsage? {
        get throws {
            try self[oid: .X509ExtensionID.extendedKeyUsage].map { try .init($0) }
        }
    }

    /// Loads the ``BasicConstraints``
    /// extension, if it is present.
    ///
    /// Throws if it is not possible to decode the basic constraints extension.
    @inlinable
    public var basicConstraints: BasicConstraints? {
        get throws {
            try self[oid: .X509ExtensionID.basicConstraints].map { try .init($0) }
        }
    }

    /// Loads the ``KeyUsage``
    /// extension, if it is present.
    ///
    /// Throws if it is not possible to decode the key usage extension.
    @inlinable
    public var keyUsage: KeyUsage? {
        get throws {
            try self[oid: .X509ExtensionID.keyUsage].map { try .init($0) }
        }
    }

    /// Loads the ``NameConstraints``
    /// extension, if it is present.
    ///
    /// Throws if it is not possible to decode the name constraints extension.
    @inlinable
    public var nameConstraints: NameConstraints? {
        get throws {
            try self[oid: .X509ExtensionID.nameConstraints].map { try .init($0) }
        }
    }

    /// Loads the ``SubjectAlternativeNames``
    /// extension, if it is present.
    ///
    /// Throws if it is not possible to decode the SAN extension.
    @inlinable
    public var subjectAlternativeNames: SubjectAlternativeNames? {
        get throws {
            try self[oid: .X509ExtensionID.subjectAlternativeName].map { try .init($0) }
        }
    }
}
