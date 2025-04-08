//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCertificates open source project
//
// Copyright (c) 2023 Apple Inc. and the SwiftCertificates project authors
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
extension CertificateSigningRequest {
    /// A representation of the additional attributes on a certificate signing request.
    ///
    /// CSR attributes are represented as an ASN.1 SET of key-value pairs, where each key
    /// may have 1 or more values. Attributes are defined in a wide range of specifications.
    ///
    /// ### Sequence and Collection Helpers
    ///
    /// ``CertificateSigningRequest/Attributes-swift.struct`` is conceptually a collection of
    /// ``CertificateSigningRequest/Attribute`` objects. The collection is unordered, and order
    /// is not preserved across modification.
    ///
    /// However, ``CertificateSigningRequest/Attributes-swift.struct`` is also conceptually a dictionary
    /// keyed by ``CertificateSigningRequest/Attribute/oid``. For that reason, in addition to the index-based subscript
    /// this type also offers ``subscript(oid:)`` to enable finding the attribute with a specific OID. This API also
    /// lets users replace the value of a specific attribute.
    ///
    /// ### Specific attribute helpers
    ///
    /// To make it easier to decode specific attributes, this type provides a number of helpers for known extension types:
    ///
    /// - ``extensionRequest``
    ///
    /// Users who add their own attribute types (see ``CertificateSigningRequest/Attribute`` for more) are encouraged to add their
    /// own helper getters for those types.
    public struct Attributes {
        @usableFromInline
        var _attributes: [Attribute]

        /// Produce a new Attributes container from a collection of ``CertificateSigningRequest/Attribute``.
        ///
        /// - Parameter attributes: The base attributes.
        @inlinable
        public init<Elements>(_ attributes: Elements) where Elements: Sequence, Elements.Element == Attribute {
            self._attributes = []

            for element in attributes {
                self[oid: element.oid] = element
            }
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension CertificateSigningRequest.Attributes: Hashable {
    @inlinable
    public static func == (lhs: CertificateSigningRequest.Attributes, rhs: CertificateSigningRequest.Attributes) -> Bool
    {
        if lhs.count != rhs.count { return false }

        for element in lhs {
            if !rhs.contains(element) { return false }
        }

        return true
    }

    @inlinable
    public func hash(into hasher: inout Hasher) {
        // This achieves order-independent hashing without
        // having to sort anything.
        var hash = 0
        for element in self {
            var newHasher = Hasher()
            element.hash(into: &newHasher)
            hash ^= newHasher.finalize()
        }

        hasher.combine(hash)
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension CertificateSigningRequest.Attributes: Sendable {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension CertificateSigningRequest.Attributes: RandomAccessCollection {
    @inlinable
    public init() {
        self._attributes = []
    }

    @inlinable
    public var startIndex: Int {
        self._attributes.startIndex
    }

    @inlinable
    public var endIndex: Int {
        self._attributes.endIndex
    }

    @inlinable
    public subscript(position: Int) -> CertificateSigningRequest.Attribute {
        get {
            self._attributes[position]
        }
    }

    /// Insert a new ``CertificateSigningRequest/Attribute`` into this set of ``CertificateSigningRequest/Attributes-swift.struct``.
    ///
    /// If an attribute already exists with this OID, it will be replaced by the new value.
    ///
    /// - Parameter ext: The ``CertificateSigningRequest/Attribute`` to insert.
    @inlinable
    public mutating func insert(_ ext: CertificateSigningRequest.Attribute) {
        self[oid: ext.oid] = ext
    }

    /// Insert a sequence of new ``CertificateSigningRequest/Attribute``s into this set of ``CertificateSigningRequest/Attributes-swift.struct``.
    ///
    /// If a ``CertificateSigningRequest/Attribute`` with the same ``CertificateSigningRequest/Attribute/oid`` is already
    /// present in this element, the new value will replace it. If `extensions` contains multiple attributes with the same
    /// ``CertificateSigningRequest/Attribute/oid``, the last element will win.
    ///
    /// - Parameter extensions: The sequence of new ``CertificateSigningRequest/Attribute``s to insert.
    @inlinable
    public mutating func insert<Extensions: Sequence>(contentsOf extensions: Extensions)
    where Extensions.Element == CertificateSigningRequest.Attribute {
        for element in extensions {
            self[oid: element.oid] = element
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension CertificateSigningRequest.Attributes: CustomStringConvertible {
    @inlinable
    public var description: String {
        return "Attributes([\(self._attributes.map { String(reflecting: $0) }.joined(separator: ", "))])"
    }
}

// MARK: Helpers for specific extensions
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension CertificateSigningRequest.Attributes {
    /// Look up a specific attribute by its OID.
    ///
    /// - Parameter oid: The OID to search for.
    @inlinable
    public subscript(oid oid: ASN1ObjectIdentifier) -> CertificateSigningRequest.Attribute? {
        get {
            return self.first(where: { $0.oid == oid })
        }
        set {
            if let newValue = newValue {
                precondition(oid == newValue.oid)
                if let currentAttributeIndex = self.firstIndex(where: { $0.oid == oid }) {
                    self._attributes[currentAttributeIndex] = newValue
                } else {
                    self._attributes.append(newValue)
                }
            } else if let currentAttributeIndex = self.firstIndex(where: { $0.oid == oid }) {
                self._attributes.remove(at: currentAttributeIndex)
            }
        }
    }

    /// Loads the ``ExtensionRequest``
    /// attribute, if it is present.
    ///
    /// Throws if it is not possible to decode the Extension Request attribute.
    @inlinable
    public var extensionRequest: ExtensionRequest? {
        get throws {
            try self[oid: .CSRAttributes.extensionRequest].map { try .init($0) }
        }
    }
}
