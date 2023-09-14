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
import Foundation

let benchmarks = {
    Benchmark.defaultConfiguration = .init(
        metrics: [
            .mallocCountTotal,
            .syscalls,
            .readSyscalls,
            .writeSyscalls,
            .memoryLeaked,
            .retainCount,
            .retainCount,
        ]
    )
    
    var configWithoutRetainRelease = Benchmark.defaultConfiguration
    configWithoutRetainRelease.metrics.removeAll(where: { $0 == .retainCount || $0 == .releaseCount })

    Benchmark("Verifier", configuration: ) { benchmark in
        for _ in benchmark.scaledIterations {
            await verifier()
        }
    }

    Benchmark("Parse WebPKI Roots") { benchmark, run in
        for _ in benchmark.scaledIterations {
            run()
        }
    } setup: {
        parseWebPKIRootsSetup()
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
