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

/// ``_TinyArray2`` is a ``RandomAccessCollection`` optimised to store zero, one or two ``Element``s.
/// It supports arbitrary many elements but if only up to two ``Element``s are stored it does **not** allocate separate storage on the heap
/// and instead stores the ``Element``s inline.
public struct _TinyArray2<Element> {
    @usableFromInline
    enum Storage {
        case one(Element)
        case two(Element, Element)
        case arbitrary([Element])
    }

    @usableFromInline
    var storage: Storage
}

// MARK: - TinyArray "public" interface

extension _TinyArray2: Equatable where Element: Equatable {}
extension _TinyArray2: Hashable where Element: Hashable {}
extension _TinyArray2: Sendable where Element: Sendable {}

extension _TinyArray2: RandomAccessCollection {
    public typealias Element = Element

    public typealias Index = Int

    @inlinable
    public subscript(position: Int) -> Element {
        get {
            self.storage[position]
        }
        set {
            self.storage[position] = newValue
        }
    }

    @inlinable
    public var startIndex: Int {
        self.storage.startIndex
    }

    @inlinable
    public var endIndex: Int {
        self.storage.endIndex
    }
}

extension _TinyArray2 {
    @inlinable
    public init(_ elements: some Sequence<Element>) {
        self.storage = .init(elements)
    }

    @inlinable
    public init(_ elements: some Sequence<Result<Element, some Error>>) throws {
        self.storage = try .init(elements)
    }

    @inlinable
    public init() {
        self.storage = .init()
    }

    @inlinable
    public mutating func append(_ newElement: Element) {
        self.storage.append(newElement)
    }

    @inlinable
    public mutating func append(contentsOf newElements: some Sequence<Element>) {
        self.storage.append(contentsOf: newElements)
    }

    @discardableResult
    @inlinable
    public mutating func remove(at index: Int) -> Element {
        self.storage.remove(at: index)
    }

    @inlinable
    public mutating func removeAll(where shouldBeRemoved: (Element) throws -> Bool) rethrows {
        try self.storage.removeAll(where: shouldBeRemoved)
    }

    @inlinable
    public mutating func sort(by areInIncreasingOrder: (Element, Element) throws -> Bool) rethrows {
        try self.storage.sort(by: areInIncreasingOrder)
    }
}

// MARK: - TinyArray.Storage "private" implementation

extension _TinyArray2.Storage: Equatable where Element: Equatable {
    @inlinable
    static func == (lhs: Self, rhs: Self) -> Bool {
        switch (lhs, rhs) {
        case (.one(let lhs), .one(let rhs)):
            return lhs == rhs
        case (.two(let lhs0, let lhs1), .two(let rhs0, let rhs1)):
            return lhs0 == rhs0 && lhs1 == rhs1
        case (.arbitrary(let lhs), .arbitrary(let rhs)):
            // we don't use lhs.elementsEqual(rhs) so we can hit the fast path from Array
            // if both arrays share the same underlying storage: https://github.com/apple/swift/blob/b42019005988b2d13398025883e285a81d323efa/stdlib/public/core/Array.swift#L1775
            return lhs == rhs

        case (.one(let element), .arbitrary(let array)),
            (.arbitrary(let array), .one(let element)):
            guard array.count == 1 else {
                return false
            }
            return element == array[0]

        case (.two(let element0, let element1), .arbitrary(let array)),
            (.arbitrary(let array), .two(let element0, let element1)):
            guard array.count == 2 else {
                return false
            }
            return element0 == array[0] && element1 == array[1]

        case (.one, .two), (.two, .one):
            return false
        }
    }
}
extension _TinyArray2.Storage: Hashable where Element: Hashable {
    @inlinable
    func hash(into hasher: inout Hasher) {
        // same strategy as Array: https://github.com/apple/swift/blob/b42019005988b2d13398025883e285a81d323efa/stdlib/public/core/Array.swift#L1801
        hasher.combine(count)
        for element in self {
            hasher.combine(element)
        }
    }
}
extension _TinyArray2.Storage: Sendable where Element: Sendable {}

extension _TinyArray2.Storage: RandomAccessCollection {
    @inlinable
    subscript(position: Int) -> Element {
        get {
            switch self {
            case .one(let element):
                guard position == 0 else {
                    fatalError("index \(position) out of bounds")
                }
                return element

            case .two(let element0, let element1):
                switch position {
                case 0:
                    return element0
                case 1:
                    return element1
                default:
                    fatalError("index \(position) out of bounds")
                }

            case .arbitrary(let elements):
                return elements[position]
            }
        }
        set {
            switch self {
            case .one:
                guard position == 0 else {
                    fatalError("index \(position) out of bounds")
                }
                self = .one(newValue)

            case .two(let element0, let element1):
                switch position {
                case 0:
                    self = .two(newValue, element1)
                case 1:
                    self = .two(element0, newValue)
                default:
                    fatalError("index \(position) out of bounds")
                }

            case .arbitrary(var elements):
                elements[position] = newValue
                self = .arbitrary(elements)
            }
        }
    }

    @inlinable
    var startIndex: Int {
        0
    }

    @inlinable
    var endIndex: Int {
        switch self {
        case .one: return 1
        case .two: return 2
        case .arbitrary(let elements): return elements.endIndex
        }
    }
}

extension _TinyArray2.Storage {
    @inlinable
    init(_ elements: some Sequence<Element>) {
        self = .arbitrary([])
        self.append(contentsOf: elements)
    }

    @inlinable
    init(_ newElements: some Sequence<Result<Element, some Error>>) throws {
        var iterator = newElements.makeIterator()
        guard let firstElement = try iterator.next()?.get() else {
            self = .arbitrary([])
            return
        }
        guard let secondElement = try iterator.next()?.get() else {
            // newElements just contains a single element
            // and we hit the fast path
            self = .one(firstElement)
            return
        }

        guard let thirdElement = try iterator.next()?.get() else {
            // newElements just contains two elements
            // and we hit the fast path
            self = .two(firstElement, secondElement)
            return
        }

        var elements: [Element] = []
        elements.reserveCapacity(newElements.underestimatedCount)
        elements.append(firstElement)
        elements.append(secondElement)
        elements.append(thirdElement)
        while let nextElement = try iterator.next()?.get() {
            elements.append(nextElement)
        }
        self = .arbitrary(elements)
    }

    @inlinable
    init() {
        self = .arbitrary([])
    }

    @inlinable
    mutating func append(_ newElement: Element) {
        self.append(contentsOf: CollectionOfOne(newElement))
    }

    @inlinable
    mutating func append(contentsOf newElements: some Sequence<Element>) {
        switch self {
        case .one(let firstElement):
            var iterator = newElements.makeIterator()
            guard let secondElement = iterator.next() else {
                // newElements is empty, nothing to do
                return
            }
            guard let thirdElements = iterator.next() else {
                // newElements just contains a single element
                self = .two(firstElement, secondElement)
                return
            }
            var elements: [Element] = []
            elements.reserveCapacity(1 + newElements.underestimatedCount)
            elements.append(firstElement)
            elements.append(secondElement)
            elements.append(thirdElements)
            elements.appendRemainingElements(from: &iterator)
            self = .arbitrary(elements)

        case .two(let firstElement, let secondElement):
            var iterator = newElements.makeIterator()
            guard let thirdElement = iterator.next() else {
                // newElements is empty, nothing to do
                return
            }
            var elements: [Element] = []
            elements.reserveCapacity(2 + newElements.underestimatedCount)
            elements.append(firstElement)
            elements.append(secondElement)
            elements.append(thirdElement)
            elements.appendRemainingElements(from: &iterator)
            self = .arbitrary(elements)

        case .arbitrary(var elements):
            if elements.isEmpty {
                // if `self` is currently empty and `newElements` just contains a single
                // element, we skip allocating an array and set `self` to `.one(firstElement)`
                var iterator = newElements.makeIterator()
                guard let firstElement = iterator.next() else {
                    // newElements is empty, nothing to do
                    return
                }
                guard let secondElement = iterator.next() else {
                    // newElements just contains a single element
                    // and we hit the fast path
                    self = .one(firstElement)
                    return
                }
                elements.reserveCapacity(elements.count + newElements.underestimatedCount)
                elements.append(firstElement)
                elements.append(secondElement)
                elements.appendRemainingElements(from: &iterator)
                self = .arbitrary(elements)

            } else {
                elements.append(contentsOf: newElements)
                self = .arbitrary(elements)
            }

        }
    }

    @discardableResult
    @inlinable
    mutating func remove(at index: Int) -> Element {
        switch self {
        case .one(let oldElement):
            guard index == 0 else {
                fatalError("index \(index) out of bounds")
            }
            self = .arbitrary([])
            return oldElement
        case .two(let oldElement0, let oldElement1):
            switch index {
            case 0:
                self = .one(oldElement1)
                return oldElement0
            case 1:
                self = .one(oldElement0)
                return oldElement1
            default:
                fatalError("index \(index) out of bounds")
            }

        case .arbitrary(var elements):
            defer {
                self = .arbitrary(elements)
            }
            return elements.remove(at: index)

        }
    }

    @inlinable
    mutating func removeAll(where shouldBeRemoved: (Element) throws -> Bool) rethrows {
        switch self {
        case .one(let oldElement):
            if try shouldBeRemoved(oldElement) {
                self = .arbitrary([])
            }
        case .two(let oldElement0, let oldElement1):
            let shouldRemoveElement0 = try shouldBeRemoved(oldElement0)
            let shouldRemoveElement1 = try shouldBeRemoved(oldElement1)
            switch (shouldRemoveElement0, shouldRemoveElement1) {
            case (true, true):
                self = .arbitrary([])
            case (true, false):
                self = .one(oldElement1)
            case (false, true):
                self = .one(oldElement0)
            case (false, false):
                break
            }

        case .arbitrary(var elements):
            defer {
                self = .arbitrary(elements)
            }
            return try elements.removeAll(where: shouldBeRemoved)

        }
    }

    @inlinable
    mutating func sort(by areInIncreasingOrder: (Element, Element) throws -> Bool) rethrows {
        switch self {
        case .one:
            // a collection of just one element is always sorted, nothing to do
            break

        case .two(let element0, let element1):
            if try areInIncreasingOrder(element0, element1) {
                break
            } else {
                self = .two(element1, element0)
            }

        case .arbitrary(var elements):
            defer {
                self = .arbitrary(elements)
            }

            try elements.sort(by: areInIncreasingOrder)
        }
    }
}
