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

import Foundation

/// ``TinyArray`` is optimizer to store zero or one ``Element``.
/// It supports arbitary many elements but if only up to one ``Element`` is stored it does **not** allocate seperate storage on the heap and
/// instead stores the ``Element`` inline.
@usableFromInline
enum TinyArray<Element>: RandomAccessCollection {
    @usableFromInline
    typealias Element = Element
    
    @usableFromInline
    typealias Index = Int
    
    case one(Element)
    case arbitary([Element])
    
    @inlinable
    subscript(position: Int) -> Element {
        get {
            switch self {
            case .one(let element):
                guard position == 0 else {
                    fatalError("index \(position) out of bounds")
                }
                return element
            case .arbitary(let elements):
                return elements[position]
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
        case .arbitary(let elements): return elements.endIndex
        }
    }
    
    @inlinable
    init(_ elements: some Sequence<Element>) {
        self = .arbitary([])
        self.append(contentsOf: elements)
    }
    
    @inlinable
    init() {
        self = .arbitary([])
    }
    
    @inlinable
    mutating func append(_ newElement: Element) {
        self.append(contentsOf: CollectionOfOne(newElement))
    }
    
    @inlinable
    mutating func append(contentsOf newElements: some Sequence<Element>){
        switch self {
        case .one(let firstElement):
            var iterator = newElements.makeIterator()
            guard let secondElement = iterator.next() else {
                // newElements is empty, nothing to do
                return
            }
            var elements: [Element] = []
            elements.reserveCapacity(newElements.underestimatedCount)
            elements.append(firstElement)
            elements.append(secondElement)
            elements.appendRemainingElements(from: &iterator)
            
        case .arbitary(var elements):
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
            } else {
                elements.append(contentsOf: newElements)
                self = .arbitary(elements)
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
            self = .arbitary([])
            return oldElement
            
        case .arbitary(var elements):
            defer {
                if elements.count == 1 {
                    self = .one(elements[0])
                } else {
                    self = .arbitary(elements)
                }
            }

            return elements.remove(at: index)
        }
    }
    
    @inlinable
    mutating func removeAll(where shouldBeRemoved: (Element) throws -> Bool) rethrows {
        switch self {
        case .one(let oldElement):
            if try shouldBeRemoved(oldElement) {
                self = .arbitary([])
            }
            
        case .arbitary(var elements):
            defer {
                if elements.count == 1 {
                    self = .one(elements[0])
                } else {
                    self = .arbitary(elements)
                }
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
        case .arbitary(var elements):
            defer {
                // sorting doesn't change the number of elements
                // so we don't need to check the size
                self = .arbitary(elements)
            }
            
            try elements.sort(by: areInIncreasingOrder)
        }
    }
}

extension TinyArray: Equatable where Element: Equatable {}
extension TinyArray: Hashable where Element: Hashable {}
extension TinyArray: Sendable where Element: Sendable {}


extension Array {
    @inlinable
    mutating func appendRemainingElements(from iterator: inout some IteratorProtocol<Element>) {
        while let nextElement = iterator.next() {
            append(nextElement)
        }
    }
}
