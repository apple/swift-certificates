//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCertificates open source project
//
// Copyright (c) 2022 Apple Inc. and the SwiftCertificates project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.md for the list of SwiftCertificates project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import SwiftASN1

/// A ``RelativeDistinguishedName`` is a collection of elements at a single level of a hierarchical
/// ``DistinguishedName``.
///
/// Distinguished names are a remnant of the X.500 directory system. In that system,
/// distinguished names were the primary key, enabling the identification of a specific entity
/// within the directory.
///
/// ``RelativeDistinguishedName``s are the elements of a ``DistinguishedName``. Each ``RelativeDistinguishedName``
/// contains one or more ``RelativeDistinguishedName/Attribute`` which are considered equivalent: that is, they
/// are each a representation of the same piece of information.
///
/// ``RelativeDistinguishedName``s are organised into a hierarchy in a ``DistinguishedName``, in order from least
/// to most specific. In almost all current use-cases a ``RelativeDistinguishedName`` will contain only a single
/// ``Attribute``.
///
/// Note that ``RelativeDistinguishedName`` does not have a stable ordering of its elements. Inserting an element
/// at index `i` does not guarantee it will remain at that location. As a result, ``RelativeDistinguishedName`` is
/// not a `MutableCollection`.
public struct RelativeDistinguishedName {
    // TODO: Should we special-case this to the circumstance where we have only one attribute?
    @usableFromInline
    var attributes: [Attribute] {
        didSet {
            Self._sortElements(&self.attributes)
        }
    }

    /// Construct a ``RelativeDistinguishedName`` from a sequence of ``Attribute``.
    ///
    /// - Parameter attributes: The sequence of ``Attribute``s that make up the ``DistinguishedName``.
    @inlinable
    public init<AttributeSequence: Sequence>(_ attributes: AttributeSequence) throws where AttributeSequence.Element == RelativeDistinguishedName.Attribute {
        // TODO(cory:) We need to validate this, an attribute cannot be repeated.
        self.attributes = Array(attributes)
        Self._sortElements(&self.attributes)
    }

    /// Create an empty ``RelativeDistinguishedName``.
    @inlinable
    public init() {
        self.attributes = []
    }
}

extension RelativeDistinguishedName: Hashable { }

extension RelativeDistinguishedName: Sendable { }

extension RelativeDistinguishedName: RandomAccessCollection {
    @inlinable
    public var startIndex: Int {
        self.attributes.startIndex
    }

    @inlinable
    public var endIndex: Int {
        self.attributes.endIndex
    }

    @inlinable
    public subscript(position: Int) -> RelativeDistinguishedName.Attribute {
        get {
            self.attributes[position]
        }
    }

    /// Insert a new ``Attribute`` into this ``RelativeDistinguishedName``.
    ///
    /// - Parameter attribute: The ``Attribute`` to insert.
    @inlinable
    public mutating func insert(_ attribute: RelativeDistinguishedName.Attribute) {
        self.attributes.append(attribute)
    }

    /// Insert a `Collection` of ``Attribute``s into this ``RelativeDistinguishedName``.
    ///
    /// Note that the order of `attributes` will not be preserved.
    ///
    /// - Parameter attributes: The ``Attribute``s to be inserted.
    @inlinable
    public mutating func insert<Attributes: Collection>(contentsOf attributes: Attributes) where Attributes.Element == RelativeDistinguishedName.Attribute {
        self.attributes.append(contentsOf: attributes)
    }
}

extension RelativeDistinguishedName: CustomStringConvertible {
    @inlinable
    public var description: String {
        self.lazy.map {
            String(describing: $0)
        }.joined(separator: "+")
    }
}

extension RelativeDistinguishedName: DERImplicitlyTaggable {
    @inlinable
    public static var defaultIdentifier: ASN1Identifier {
        .set
    }

    @inlinable
    public init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.set(rootNode, identifier: identifier) { nodes in
            // TODO: We need to validate that these are lexicographically sorted. Perhaps ASN1.set should do it?
            var elements = Array<RelativeDistinguishedName.Attribute>()

            while let node = nodes.next() {
                try elements.append(.init(derEncoded: node))
            }

            return try RelativeDistinguishedName(elements)
        }
    }

    @inlinable
    public func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { rootCoder in
            for element in self.attributes {
                try element.serialize(into: &rootCoder)
            }
        }
    }

    @inlinable
    static func _sortElements(_ elements: inout [RelativeDistinguishedName.Attribute]) {
        // We keep the elements sorted at all times. This is dumb, but we assume that these objects get
        // mutated infrequently.
        // This is weird. We need to individually serialize each element, then lexicographically compare
        // them and then write them out. We could do this in place but for now let's not worry about it.
        try! elements.sort { lhs, rhs in
            var serializer = DER.Serializer()
            try serializer.serialize(lhs)
            let lhsBytes = serializer.serializedBytes

            serializer = DER.Serializer()
            try serializer.serialize(rhs)
            let rhsBytes = serializer.serializedBytes

            // Compare up to the common length lexicographically.
            for (leftByte, rightByte) in zip(lhsBytes, rhsBytes) {
                if leftByte < rightByte {
                    // true means left comes before right
                    return true
                } else if rightByte < leftByte {
                    // Right comes after left
                    return false
                }
            }

            // We got to the end of the shorter element, so all current elements are equal.
            // If lhs is shorter, it comes earlier, _unless_ all of rhs's trailing elements are zero.
            let trailing = rhsBytes.dropFirst(lhsBytes.count)
            if trailing.count == 0 || trailing.allSatisfy({ $0 == 0}) {
                // Must return false when the two elements are equal.
                return false
            }
            return true
        }
    }
}
