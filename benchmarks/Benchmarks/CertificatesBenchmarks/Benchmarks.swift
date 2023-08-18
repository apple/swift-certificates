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
import Sources

let benchmarks = {
    Benchmark("Verifier", configuration: .init(warmupIterations: 1)) { benchmark in
        await verifier()
    }
    
    let runParseWebPKIRoots = parseWebPKIRoots()
    Benchmark("Parse WebPKI Roots") { benchmark in
        runParseWebPKIRoots()
    }
    
    Benchmark("TinyArray non-allocating functions") { benchmark in
        tinyArrayNonAllocationFunctions()
    }
    
    Benchmark("TinyArray.append(_:)") { benchmark in
        tinyArrayAppend()
    }
}
