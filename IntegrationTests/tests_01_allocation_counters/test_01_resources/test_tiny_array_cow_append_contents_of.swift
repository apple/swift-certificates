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
        var tinyArray = TinyArray<Int>()
        tinyArray.append(1)
        tinyArray.append(2)
        tinyArray.append(3)
        tinyArray.append(4)
        tinyArray.append(5)
        tinyArray.append(6)
        tinyArray.append(7)
        tinyArray.append(8)
        return tinyArray.count
    }
}
