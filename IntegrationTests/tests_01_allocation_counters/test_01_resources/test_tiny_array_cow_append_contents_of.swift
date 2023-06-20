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

import _CertificateInternals

func run(identifier: String) {
    measure(identifier: identifier) {
        var count = 0
        for _ in 0..<1000 {
            var tinyArray = _TinyArray<Int>()
            for i in 0..<1000 {
                tinyArray.append(i)
            }
            count += tinyArray.count
        }
        
        return count
    }
}
