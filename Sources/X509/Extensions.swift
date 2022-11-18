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
    /// For that reason, in addition to the index-based subscript ``Certificate/Extensions-swift.struct/subscript(_:)-5rodj``, this type also offers
    /// ``subscript(oid:)`` to enable finding the extension with a specific OID. This API also lets users replace
    /// the value of a specific extension.
    ///
    /// ### Specific extension helpers
    ///
    /// To make it easier to decode specific extensions, this type provides a number of helpers for known extension types:
    ///
    /// - ``authorityInformationAccess-swift.property``
    /// - ``subjectKeyIdentifier-swift.property``
    /// - ``authorityKeyIdentifier-swift.property``
    /// - ``extendedKeyUsage-swift.property``
    /// - ``basicConstraints-swift.property``
    /// - ``keyUsage-swift.property``
    /// - ``nameConstraints-swift.property``
    /// - ``subjectAlternativeNames-swift.property``
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
    ///         Certificate.Extensions.KeyUsage(digitalSignature: true, keyCertSign: true, cRLSign: true)
    ///     )
    ///
    ///     Certificate.Extensions.ExtendedKeyUsage([.serverAuth, .clientAuth])
    ///
    ///     Critical(
    ///         Certificate.Extensions.BasicConstraints.isCertificateAuthority(maxPathLength: 0)
    ///     )
    ///
    ///     Certificate.Extensions.AuthorityInformationAccess([.init(method: .ocspServer, location: .uniformResourceIdentifier("http://ocsp.digicert.com"))])
    /// }
    /// ```
    ///
    /// This interface also makes it easy to mark specific extensions as critical.
    public struct Extensions {
        @usableFromInline
        var _extensions: [Extension]

        /// Produce a new Extensions container from an array of ``Certificate/Extension``.
        ///
        /// - Parameter extensions: The base extensions.
        @inlinable
        public init(extensions: [Extension]) {
            // TODO(cory): Police uniqueness
            self._extensions = extensions
        }

        /// Produce a new Extensions container from a collection of ``Certificate/Extension``.
        ///
        /// - Parameter extensions: The base extensions.
        @inlinable
        public init<Elements>(_ extensions: Elements) where Elements: Sequence, Elements.Element == Extension {
            self._extensions = Array(extensions)
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
        ///         Certificate.Extensions.KeyUsage(digitalSignature: true, keyCertSign: true, cRLSign: true)
        ///     )
        ///
        ///     Certificate.Extensions.ExtendedKeyUsage([.serverAuth, .clientAuth])
        ///
        ///     Critical(
        ///         Certificate.Extensions.BasicConstraints.isCertificateAuthority(maxPathLength: 0)
        ///     )
        ///
        ///     Certificate.Extensions.AuthorityInformationAccess([.init(method: .ocspServer, location: .uniformResourceIdentifier("http://ocsp.digicert.com"))])
        /// }
        /// ```
        ///
        /// - Parameter builder: The ``ExtensionsBuilder`` DSL.
        @inlinable
        public init(@ExtensionsBuilder builder: () throws -> Certificate.Extensions) throws {
            self = try builder()
        }
    }
}

extension Certificate.Extensions: Hashable { }

extension Certificate.Extensions: Sendable { }

// TODO: Tweak API surface here, this is more like a dictionary than an Array, and we
// need to forbid duplicate extensions. Consider backing this with OrderedDictionary.
extension Certificate.Extensions: RandomAccessCollection {
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
        // TODO(cory): enforce uniqueness
        get {
            self._extensions[position]
        }
    }

    /// Append a new ``Certificate/Extension`` into this set of ``Certificate/Extensions-swift.struct``.
    ///
    /// - Parameter ext: The ``Certificate/Extension`` to insert.
    @inlinable
    public mutating func append(_ ext: Certificate.Extension) {
        // TODO(cory): enforce uniqueness
        self._extensions.append(ext)
    }

    /// Append a sequence of new ``Certificate/Extension``s into this set of ``Certificate/Extensions-swift.struct``.
    ///
    /// - Parameter extensions: The sequence of new ``Certificate/Extension``s to insert.
    @inlinable
    public mutating func append<Extensions: Sequence>(contentsOf extensions: Extensions) where Extensions.Element == Certificate.Extension {
        // TODO(cory): enforce uniqueness
        self._extensions.append(contentsOf: extensions)
    }
}

extension Certificate.Extensions: CustomStringConvertible {
    @inlinable
    public var description: String {
        return "TODO"
    }
}

// MARK: Helpers for specific extensions
extension Certificate.Extensions {
    /// Look up a specific extension by its OID.
    ///
    /// - Parameter oid: The OID to search for.
    @inlinable
    public subscript(oid oid: ASN1ObjectIdentifier) -> Certificate.Extension? {
        get {
            return self.first(where: { $0.oid == oid })
        }
        set {
            if let newValue = newValue {
                precondition(oid == newValue.oid)
                if let currentExtensionIndex = self.firstIndex(where: { $0.oid == oid }) {
                    self._extensions[currentExtensionIndex] = newValue
                } else {
                    self._extensions.append(newValue)
                }
            } else if let currentExtensionIndex = self.firstIndex(where: { $0.oid == oid }) {
                self._extensions.remove(at: currentExtensionIndex)
            }
        }
    }

    /// Loads the ``Certificate/Extensions-swift.struct/AuthorityInformationAccess-swift.struct``
    /// extension, if it is present.
    ///
    /// Throws if it is not possible to decode the AIA extension.
    @inlinable
    public var authorityInformationAccess: Certificate.Extensions.AuthorityInformationAccess? {
        get throws {
            try self[oid: .X509ExtensionID.authorityInformationAccess].map { try .init($0) }
        }
    }

    /// Loads the ``Certificate/Extensions-swift.struct/SubjectKeyIdentifier-swift.struct``
    /// extension, if it is present.
    ///
    /// Throws if it is not possible to decode the SKI extension.
    @inlinable
    public var subjectKeyIdentifier: Certificate.Extensions.SubjectKeyIdentifier? {
        get throws {
            try self[oid: .X509ExtensionID.subjectKeyIdentifier].map { try .init($0) }
        }
    }

    /// Loads the ``Certificate/Extensions-swift.struct/AuthorityKeyIdentifier-swift.struct``
    /// extension, if it is present.
    ///
    /// Throws if it is not possible to decode the AKI extension.
    @inlinable
    public var authorityKeyIdentifier: Certificate.Extensions.AuthorityKeyIdentifier? {
        get throws {
            try self[oid: .X509ExtensionID.authorityKeyIdentifier].map { try .init($0) }
        }
    }

    /// Loads the ``Certificate/Extensions-swift.struct/ExtendedKeyUsage-swift.struct``
    /// extension, if it is present.
    ///
    /// Throws if it is not possible to decode the EKU extension.
    @inlinable
    public var extendedKeyUsage: Certificate.Extensions.ExtendedKeyUsage? {
        get throws {
            try self[oid: .X509ExtensionID.extendedKeyUsage].map { try .init($0) }
        }
    }

    /// Loads the ``Certificate/Extensions-swift.struct/BasicConstraints-swift.enum``
    /// extension, if it is present.
    ///
    /// Throws if it is not possible to decode the basic constraints extension.
    @inlinable
    public var basicConstraints: Certificate.Extensions.BasicConstraints? {
        get throws {
            try self[oid: .X509ExtensionID.basicConstraints].map { try .init($0) }
        }
    }

    /// Loads the ``Certificate/Extensions-swift.struct/KeyUsage-swift.struct``
    /// extension, if it is present.
    ///
    /// Throws if it is not possible to decode the key usage extension.
    @inlinable
    public var keyUsage: Certificate.Extensions.KeyUsage? {
        get throws {
            try self[oid: .X509ExtensionID.keyUsage].map { try .init($0) }
        }
    }

    /// Loads the ``Certificate/Extensions-swift.struct/NameConstraints-swift.struct``
    /// extension, if it is present.
    ///
    /// Throws if it is not possible to decode the name constraints extension.
    @inlinable
    public var nameConstraints: Certificate.Extensions.NameConstraints? {
        get throws {
            try self[oid: .X509ExtensionID.nameConstraints].map { try .init($0) }
        }
    }

    /// Loads the ``Certificate/Extensions-swift.struct/SubjectAlternativeNames-swift.struct``
    /// extension, if it is present.
    ///
    /// Throws if it is not possible to decode the SAN extension.
    @inlinable
    public var subjectAlternativeNames: Certificate.Extensions.SubjectAlternativeNames? {
        get throws {
            try self[oid: .X509ExtensionID.subjectAlternativeName].map { try .init($0) }
        }
    }
}
