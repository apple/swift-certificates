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

func thresholds(for benchmarkName: String) -> [BenchmarkMetric : BenchmarkThresholds]? {
    // https://forums.swift.org/t/pitch-introduce-module-to-get-the-current-module-name/45806/8
    let moduleName = String("\(#fileID)".prefix(while: { $0 != "/" }))
    
    return BenchmarkThresholds.makeBenchmarkThresholds(
        path: FileManager.default.currentDirectoryPath,
        moduleName: moduleName,
        benchmarkName: benchmarkName
    )
}



let benchmarks = {
    Benchmark.defaultConfiguration = .init(
        metrics: [.mallocCountTotal, .syscalls, .retainCount],
        warmupIterations: 1
    )
    
    do {
        let testName = "Verifier"
        Benchmark(testName, configuration: .init(
            metrics: [.mallocCountTotal, .syscalls],
            thresholds: thresholds(for: testName))
        ) { benchmark in
            for _ in benchmark.scaledIterations {
                await verifier()
            }
        }
    }

    do {
        let runParseWebPKIRoots = parseWebPKIRoots()
        let testName = "Parse WebPKI Roots"
        Benchmark(testName, configuration: .init(thresholds: thresholds(for: testName))) { benchmark in
            for _ in benchmark.scaledIterations {
                runParseWebPKIRoots()
            }
        }
    }
    do {
        let testName = "TinyArray non-allocating functions"
        Benchmark(testName, configuration: .init(thresholds: thresholds(for: testName))) { benchmark in
            for _ in benchmark.scaledIterations {
                tinyArrayNonAllocationFunctions()
            }
        }
    }
    
    do {
        let testName = "TinyArray.append(_:)"
        Benchmark(testName, configuration: .init(thresholds: thresholds(for: testName))) { benchmark in
            for _ in benchmark.scaledIterations {
                tinyArrayAppend()
            }
        }
    }
}
