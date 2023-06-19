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
    let preallocatedArray1 = [1]
    let preallocatedArray2 = [1, 2]
    let preallocatedArray3 = [1, 2, 3]
    let preallocatedArray4 = [1, 2, 3, 4]

    measure(identifier: identifier) {
        var counts = 0
        counts += TinyArray(CollectionOfOne(1)).count
        counts += TinyArray(preallocatedArray1).count
        counts += TinyArray(preallocatedArray2).count
        counts += TinyArray(preallocatedArray3).count
        counts += TinyArray(preallocatedArray4).count
        
        do {
            var array = TinyArray<Int>()
            array.append(contentsOf: CollectionOfOne(1))
            counts += array.count
        }
        
        do {
            var array = TinyArray<Int>()
            array.append(contentsOf: preallocatedArray1)
            counts += array.count
        }
        
        do {
            var array = TinyArray<Int>()
            array.append(contentsOf: preallocatedArray2)
            counts += array.count
        }
        
        do {
            var array = TinyArray<Int>()
            array.append(contentsOf: preallocatedArray3)
            counts += array.count
        }
        
        do {
            var array = TinyArray<Int>()
            array.append(contentsOf: preallocatedArray4)
            counts += array.count
        }
        
        return counts
    }
}
