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

import XCTest
@_spi(IntegrationTests) import X509

final class TinyArrayTests: XCTestCase {
    private func _assertEqual(
        _ expected: @autoclosure () -> some Sequence<Int>,
        initial: @autoclosure () -> TinyArray<Int>,
        _ mutate: (inout TinyArray<Int>) -> (),
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        var actual = initial()
        mutate(&actual)
        XCTAssertEqual(Array(actual), Array(expected()), file: file, line: line)
        let expected = TinyArray(expected())
        XCTAssertEqual(actual, expected, file: file, line: line)
        var acutalHasher = Hasher()
        acutalHasher.combine(actual)
        var expectedHasher = Hasher()
        expectedHasher.combine(expected)
        XCTAssertEqual(acutalHasher.finalize(), expectedHasher.finalize(), "\(actual) does not have the same hash as \(expected)", file: file, line: line)
    }
    
    private func assertEqual(
        _ expected: [Int],
        initial: @autoclosure () -> TinyArray<Int> = TinyArray(),
        _ mutate: (inout TinyArray<Int>) -> (),
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        _assertEqual(expected, initial: initial(), mutate, file: file, line: line)
        // get a sequence that is not an `Array` to hit the slow path as well
        _assertEqual(expected.lazy.map { $0 }, initial: initial(), mutate, file: file, line: line)
    }
    
    func testInit() {
        XCTAssertEqual(Array(TinyArray([Int]())), [])
        XCTAssertEqual(Array(TinyArray<Int>()), [])
        XCTAssertEqual(TinyArray<Int>(), TinyArray<Int>([]))
        
        XCTAssertEqual(Array(TinyArray<Int>(CollectionOfOne(1))), [1])
        XCTAssertEqual(Array(TinyArray<Int>([1])), [1])
        XCTAssertEqual(Array(TinyArray<Int>([1, 2])), [1, 2])
        
        XCTAssertEqual(Array(TinyArray<Int>([1, 2, 3])), [1, 2, 3])
        XCTAssertEqual(Array(TinyArray<Int>([1, 2, 3, 4])), [1, 2, 3, 4])
        XCTAssertEqual(Array(TinyArray<Int>([1, 2, 3, 4, 5])), [1, 2, 3, 4, 5])
    }
    
    func testAppend() {
        assertEqual([1]) { array in
            array.append(1)
        }
        assertEqual([1, 2]) { array in
            array.append(1)
            array.append(2)
        }
        assertEqual([1, 2, 3]) { array in
            array.append(1)
            array.append(2)
            array.append(3)
        }
        assertEqual([1, 2, 3, 4]) { array in
            array.append(1)
            array.append(2)
            array.append(3)
            array.append(4)
        }
    }
    
    func testAppendContentsOf() {
        assertEqual([]) { array in
            array.append(contentsOf: [])
        }
        assertEqual([]) { array in
            array.append(contentsOf: [])
            array.append(contentsOf: [])
        }
        assertEqual([1]) { array in
            array.append(contentsOf: [1])
        }
        assertEqual([1]) { array in
            array.append(contentsOf: [1])
            array.append(contentsOf: [])
        }
        assertEqual([1, 2]) { array in
            array.append(contentsOf: [1, 2])
        }
        assertEqual([1, 2]) { array in
            array.append(contentsOf: [1, 2])
            array.append(contentsOf: [])
        }
        assertEqual([1, 2, 3]) { array in
            array.append(contentsOf: [1, 2, 3])
        }
        assertEqual([1, 2, 3, 4]) { array in
            array.append(contentsOf: [1, 2, 3, 4])
        }
        assertEqual([1, 2, 3, 4, 5]) { array in
            array.append(contentsOf: [1, 2, 3, 4, 5])
        }
        
        assertEqual([1, 2]) { array in
            array.append(contentsOf: [1])
            array.append(contentsOf: [2])
        }
        assertEqual([1, 2, 3]) { array in
            array.append(contentsOf: [1])
            array.append(contentsOf: [2, 3])
        }
        assertEqual([1, 2, 3]) { array in
            array.append(contentsOf: [1, 2])
            array.append(contentsOf: [3])
        }
        assertEqual([1, 2, 3, 4]) { array in
            array.append(contentsOf: [1, 2])
            array.append(contentsOf: [3, 4])
        }
        assertEqual([1, 2, 3, 4]) { array in
            array.append(contentsOf: [1])
            array.append(contentsOf: [2, 3, 4])
        }
        assertEqual([1, 2, 3, 4]) { array in
            array.append(contentsOf: [1, 2, 3])
            array.append(contentsOf: [4])
        }
        assertEqual([1, 2, 3, 4, 5]) { array in
            array.append(contentsOf: [1, 2, 3, 4])
            array.append(contentsOf: [5])
        }
        assertEqual([1, 2, 3, 4, 5]) { array in
            array.append(contentsOf: [1, 2, 3])
            array.append(contentsOf: [4, 5])
        }
        assertEqual([1, 2, 3, 4, 5]) { array in
            array.append(contentsOf: [1, 2])
            array.append(contentsOf: [3, 4, 5])
        }
        assertEqual([1, 2, 3, 4, 5]) { array in
            array.append(contentsOf: [1])
            array.append(contentsOf: [2, 3, 4, 5])
        }
    }
    
    func testRemoveAt() {
        assertEqual([], initial: [1]) { array in
            array.remove(at: 0)
        }
        assertEqual([1], initial: [1, 2]) { array in
            array.remove(at: 1)
        }
        assertEqual([2], initial: [1, 2]) { array in
            array.remove(at: 0)
        }
        assertEqual([], initial: [1, 2]) { array in
            array.remove(at: 1)
            array.remove(at: 0)
        }
        assertEqual([], initial: [1, 2]) { array in
            array.remove(at: 0)
            array.remove(at: 0)
        }
        assertEqual([1, 2], initial: [1, 2, 3]) { array in
            array.remove(at: 2)
        }
        assertEqual([1, 3], initial: [1, 2, 3]) { array in
            array.remove(at: 1)
        }
        assertEqual([2, 3], initial: [1, 2, 3]) { array in
            array.remove(at: 0)
        }
        assertEqual([1], initial: [1, 2, 3]) { array in
            array.remove(at: 1)
            array.remove(at: 1)
        }
        assertEqual([2], initial: [1, 2, 3]) { array in
            array.remove(at: 0)
            array.remove(at: 1)
        }
        assertEqual([3], initial: [1, 2, 3]) { array in
            array.remove(at: 1)
            array.remove(at: 0)
        }
        assertEqual([], initial: [1, 2, 3]) { array in
            array.remove(at: 2)
            array.remove(at: 1)
            array.remove(at: 0)
        }
        assertEqual([], initial: [1, 2, 3]) { array in
            array.remove(at: 0)
            array.remove(at: 0)
            array.remove(at: 0)
        }
    }
    
    func testRemoveAll() {
        assertEqual([], initial: []) { array in
            array.removeAll(where: { _ in true })
        }
        assertEqual([], initial: [1]) { array in
            array.removeAll(where: { _ in true })
        }
        assertEqual([], initial: [1, 2]) { array in
            array.removeAll(where: { _ in true })
        }
        assertEqual([], initial: [1, 2, 3]) { array in
            array.removeAll(where: { _ in true })
        }
        assertEqual([], initial: [1, 2, 3, 4]) { array in
            array.removeAll(where: { _ in true })
        }
        assertEqual([], initial: [1, 2, 3, 4, 5]) { array in
            array.removeAll(where: { _ in true })
        }
        
        assertEqual([1], initial: [1]) { array in
            array.removeAll(where: { _ in false })
        }
        assertEqual([1, 2], initial: [1, 2]) { array in
            array.removeAll(where: { _ in false })
        }
        assertEqual([1, 2, 3], initial: [1, 2, 3]) { array in
            array.removeAll(where: { _ in false })
        }
        assertEqual([1, 2, 3, 4], initial: [1, 2, 3, 4]) { array in
            array.removeAll(where: { _ in false })
        }
        assertEqual([1, 2, 3, 4, 5], initial: [1, 2, 3, 4, 5]) { array in
            array.removeAll(where: { _ in false })
        }
        
        assertEqual([], initial: [1]) { array in
            array.removeAll(where: { Set([1]).contains($0) })
        }
        assertEqual([2], initial: [1, 2]) { array in
            array.removeAll(where: { Set([1]).contains($0) })
        }
        assertEqual([2, 3], initial: [1, 2, 3]) { array in
            array.removeAll(where: { Set([1]).contains($0) })
        }
        assertEqual([2], initial: [1, 2, 3]) { array in
            array.removeAll(where: { Set([1, 3]).contains($0) })
        }
    }
    
    func testSort() {
        assertEqual([], initial: []) { array in
            array.sort(by: { lhs, rhs in
                XCTFail("should never be called")
                return lhs < rhs
            })
        }
        assertEqual([1], initial: [1]) { array in
            array.sort(by: { lhs, rhs in
                XCTFail("should never be called")
                return lhs < rhs
            })
        }
        assertEqual([2, 1], initial: [1, 2]) { array in
            array.sort(by: >)
        }
        assertEqual([3, 2, 1], initial: [1, 2, 3]) { array in
            array.sort(by: >)
        }
    }
    
    func testThrowingInitFromResult() {
        XCTAssertEqual(Array(try TinyArray<Int>(CollectionOfOne(Result<_, Error>.success(1)))), [1])
        XCTAssertEqual(Array(try TinyArray([Result<_, Error>.success(1)])), [1])
        XCTAssertEqual(Array(try TinyArray([Result<_, Error>.success(1), .success(2)])), [1, 2])
        XCTAssertEqual(Array(try TinyArray([Result<_, Error>.success(1), .success(2), .success(3)])), [1, 2, 3])
        XCTAssertEqual(Array(try TinyArray([Result<_, Error>.success(1), .success(2), .success(3), .success(4)])), [1, 2, 3, 4])
        XCTAssertEqual(Array(try TinyArray([Result<_, Error>.success(1), .success(2), .success(3), .success(4), .success(5)])), [1, 2, 3, 4, 5])
        
        struct MyError: Error {}
        
        XCTAssertThrowsError(Array(try TinyArray<Int>([Result.failure(MyError())])))
        XCTAssertThrowsError(Array(try TinyArray<Int>([Result.failure(MyError()), Result.failure(MyError())])))
        XCTAssertThrowsError(Array(try TinyArray<Int>([.success(1), Result.failure(MyError())])))
        XCTAssertThrowsError(Array(try TinyArray<Int>([.success(1), Result.failure(MyError()), .success(2)])))
        XCTAssertThrowsError(Array(try TinyArray<Int>([.success(1), .success(2), Result.failure(MyError())])))
        XCTAssertThrowsError(Array(try TinyArray<Int>([.success(1), .success(2), Result.failure(MyError()), .success(4)])))
        XCTAssertThrowsError(Array(try TinyArray<Int>([.success(1), .success(2), .success(3), Result.failure(MyError())])))
        XCTAssertThrowsError(Array(try TinyArray<Int>([.success(1), .success(2), .success(3), .success(4), Result.failure(MyError())])))
    }
}

extension TinyArray: ExpressibleByArrayLiteral {
    public typealias ArrayLiteralElement = Element
    
    public init(arrayLiteral elements: Element...) {
        self.init(elements)
    }
}
