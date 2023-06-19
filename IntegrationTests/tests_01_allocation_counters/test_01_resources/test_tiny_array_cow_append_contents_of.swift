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

@_spi(IntegrationTests) import X509

func run(identifier: String) {
    measure(identifier: identifier) {
        var array = Array<Int>()
        array.reserveCapacity(4)
        array.append(1)
        array.append(2)
        var tinyArray = TinyArray(array)
        // drop the ref to array so TinyArray is now the single owner
        array = []
        
        tinyArray.append(3)
        tinyArray.append(4)
        return tinyArray.count
    }
}
