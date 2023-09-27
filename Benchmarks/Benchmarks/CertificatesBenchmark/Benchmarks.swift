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
            .releaseCount,
        ]
    )

    var configWithoutRetainRelease = Benchmark.defaultConfiguration
    configWithoutRetainRelease.metrics.removeAll(where: { $0 == .retainCount || $0 == .releaseCount })

    // async code is currently still quite flaky in the number of retain/release it does so we don't measure them today
    Benchmark("Verifier", configuration: configWithoutRetainRelease) { benchmark in
        for _ in benchmark.scaledIterations {
            await verifier()
        }
    }

    Benchmark("Parse WebPKI Roots from DER") { benchmark, run in
        for _ in benchmark.scaledIterations {
            run()
        }
    } setup: {
        parseWebPKIRootsFromDER()
    }

    Benchmark("Parse WebPKI Roots from PEM files") { benchmark, run in
        for _ in benchmark.scaledIterations {
            run()
        }
    } setup: {
        parseWebPKIRootsFromPEMFiles()
    }

    Benchmark("Parse WebPKI Roots from multi PEM file") { benchmark, run in
        for _ in benchmark.scaledIterations {
            run()
        }
    } setup: {
        parseWebPKIRootsFromMultiPEMFile()
    }

    Benchmark("TinyArray non-allocating functions") { benchmark in
        for _ in benchmark.scaledIterations {
            tinyArrayNonAllocationFunctions()
        }
    }

    Benchmark("TinyArray.append") { benchmark in
        for _ in benchmark.scaledIterations {
            tinyArrayAppend()
        }
    }
}
