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
import SwiftASN1

func run(identifier: String) {
    let derEncodedCAs = try WebPKI.all.map { try! PEMDocument(pemString: $0).derBytes }
    measure(identifier: identifier) {
        var totalExtensionCount = 0
        for _ in 0..<1000 {
            for derEncodedCA in derEncodedCAs {
                totalExtensionCount += try! Certificate(derEncoded: derEncodedCA).extensions.count
            }
        }
        return totalExtensionCount
    }
}
