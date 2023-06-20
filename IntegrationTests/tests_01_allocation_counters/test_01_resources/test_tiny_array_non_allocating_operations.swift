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
        var counts = 0
        for _ in 0..<1000 {
            counts += _TinyArray(CollectionOfOne(1)).count
            
            do {
                var array = _TinyArray<Int>()
                array.append(contentsOf: CollectionOfOne(1))
                counts += array.count
            }
        }
        
        return counts
    }
}
