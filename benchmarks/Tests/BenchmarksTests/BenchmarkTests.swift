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

import Benchmarks
import XCTest

final class TestRunner: XCTestCase {
    override func setUpWithError() throws {
        #if DEBUG
        throw XCTSkip("performance tests only run in release mode")
        #endif
    }
    func testVerifier() async {
        for _ in 0..<100 {
            await verifier()
        }
    }

    func testPraseWebPKIRoots() {
        let runParseWebPKIRoots = parseWebPKIRoots()
        for _ in 0..<1000 {
            runParseWebPKIRoots()
        }
    }

    func testTinyArrayNonAllocationFunctions() {
        for _ in 0..<1000 {
            tinyArrayNonAllocationFunctions()
        }
    }

    func testTinyArrayAppend() {
        for _ in 0..<1000 {
            tinyArrayAppend()
        }
    }
}
