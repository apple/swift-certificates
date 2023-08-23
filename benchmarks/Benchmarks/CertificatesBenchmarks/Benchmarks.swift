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
import Foundation


let benchmarks = {
    Benchmark.defaultConfiguration = .init(
        metrics: [.mallocCountTotal, .syscalls, .retainCount],
        warmupIterations: 1
    )

    Benchmark("Verifier", configuration: .init(metrics: [.mallocCountTotal, .syscalls])) { benchmark in
        for _ in benchmark.scaledIterations {
            await verifier()
        }
    }
    
    let runParseWebPKIRoots = parseWebPKIRoots()
    Benchmark("Parse WebPKI Roots") { benchmark in
        for _ in benchmark.scaledIterations {
            runParseWebPKIRoots()
        }
    }
    
    Benchmark("TinyArray non-allocating functions") { benchmark in
        for _ in benchmark.scaledIterations {
            tinyArrayNonAllocationFunctions()
        }
    }
    
    Benchmark("TinyArray.append(_:)") { benchmark in
        for _ in benchmark.scaledIterations {
            tinyArrayAppend()
        }
    }
}
