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

import Benchmark
import _CertificateInternals

public func tinyArray1NonAllocationFunctions() {
    var counts = 0
    counts += _TinyArray1(CollectionOfOne(1)).count

    var array = _TinyArray1<Int>()
    array.append(contentsOf: CollectionOfOne(1))
    counts += array.count

    blackHole(counts)
}

struct CollectionOfTwo<Element>: Collection {
    var elements: (Element, Element)
    init(_ element0: Element, _ element1: Element) {
        self.elements = (element0, element1)
    }

    var startIndex: Int { 0 }
    var endIndex: Int { 2 }
    func index(after i: Int) -> Int {
        i + 1
    }

    subscript(position: Int) -> Element {
        switch position {
        case 0: return elements.0
        case 1: return elements.1
        default: fatalError("index \(position) out of bounds")
        }
    }
}

public func tinyArray2NonAllocationFunctions() {
    blackHole(_TinyArray2(CollectionOfOne(1)))
    blackHole(_TinyArray2(CollectionOfTwo(1, 2)))

    do {
        var array = _TinyArray2<Int>()
        array.append(contentsOf: CollectionOfOne(1))
        blackHole(array)
    }
    do {
        var array = _TinyArray2<Int>()
        array.append(contentsOf: CollectionOfOne(1))
        array.append(contentsOf: CollectionOfOne(2))
        blackHole(array)
    }
    do {
        var array = _TinyArray2<Int>()
        array.append(contentsOf: CollectionOfTwo(1, 2))
        blackHole(array)
    }
}
