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

import X509
import Foundation
import XCTest
@_spi(IntegrationTests) import _WebPKI

final class TestRoots: XCTestCase {
    func testLoadRoots() throws {
        let caPaths = WebPKI.roots
        let derEncodedCAs = try caPaths.map { Array(try Data(contentsOf: $0)) }
        
        for derEncodedCA in derEncodedCAs {
            XCTAssertNoThrow(try Certificate(derEncoded: derEncodedCA))
        }
    }
}


    
        
    
