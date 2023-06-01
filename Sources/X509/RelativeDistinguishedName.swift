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
    var attributes: [Attribute]

    /// Construct a ``RelativeDistinguishedName`` from a sequence of ``Attribute``.
    ///
    /// - Parameter attributes: The sequence of ``Attribute``s that make up the ``DistinguishedName``.
    @inlinable
    public init<AttributeSequence: Sequence>(_ attributes: AttributeSequence) throws where AttributeSequence.Element == RelativeDistinguishedName.Attribute {
        self.attributes = Array(attributes)
        Self._sortElements(&self.attributes)
        
        // police uniqueness. `attributes` are sorted so we just need to
        // check that adjacent elements are not equal
        let adjacentPairs = zip(self.attributes.dropLast(), self.attributes.dropFirst())
        for (lhs, rhs) in adjacentPairs {
            if lhs == rhs {
                throw CertificateError.duplicateElement(
                    reason: "RelativeDistinguishedName contains \(lhs) at least twice but duplicates are not allowed."
                )
            }
        }
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
    /// - Returns: `true` if the `attribute` was inserted or `false` if it was already present.
    @inlinable
    @discardableResult
    public mutating func insert(_ attribute: RelativeDistinguishedName.Attribute) -> Bool {
        if self.attributes.contains(attribute) {
            return false
        }
        self.attributes.append(attribute)
        Self._sortElements(&self.attributes)
        return true
    }

    /// Insert a `Collection` of ``Attribute``s into this ``RelativeDistinguishedName``.
    ///
    /// Note that the order of `attributes` will not be preserved and duplicates will be deduplicated .
    ///
    /// - Parameter attributes: The ``Attribute``s to be inserted.
    @inlinable
    public mutating func insert<Attributes: Collection>(contentsOf attributes: Attributes) where Attributes.Element == RelativeDistinguishedName.Attribute {
        
        for attribute in attributes {
            if self.attributes.contains(attribute) {
                continue
            }
            self.attributes.append(attribute)
        }
        
        Self._sortElements(&self.attributes)
    }
    
    /// Removes the given `attribute` from `self` if present.
    /// - Parameter attribute: The ``Attribute`` to remove.
    /// - Returns: `true` if `attribute` was present in `self` or `false` if it was not present.
    @inlinable
    @discardableResult
    public mutating func remove(_ attribute: Attribute) -> Bool {
        guard let index = self.attributes.firstIndex(of: attribute) else {
            return false
        }
        self.attributes.remove(at: index)
        // removing an element preserves the order and therefore we don't need to sort it afterwards
        return true
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
        try self.init(DER.set(identifier: identifier, rootNode: rootNode))
    }

    @inlinable
    public func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        // TODO: performance improvement: `attributes` is already guaranteed to be sorted but `serializeSetOf` will still sort it again.
        // we need special support in ASN.1 for that operation which should still assert the order in debug builds
        try coder.serializeSetOf(self.attributes, identifier: identifier)
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
