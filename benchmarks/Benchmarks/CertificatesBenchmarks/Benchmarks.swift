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

func makeConfigurationFor(_ name: String) -> Benchmark.Configuration {
    // https://forums.swift.org/t/pitch-introduce-module-to-get-the-current-module-name/45806/8
    let moduleName = String("\(#fileID)".prefix(while: { $0 != "/" }))

    var configuration: Benchmark.Configuration = .init(metrics: [.mallocCountTotal, .syscalls] + .arc,
                                                       warmupIterations: 1,
                                                       scalingFactor: .kilo,
                                                       maxDuration: .seconds(2),
                                                       maxIterations: .kilo(100))

    configuration.thresholds = BenchmarkThresholds.makeBenchmarkThresholds(path: FileManager.default.currentDirectoryPath,
                                                                           moduleName: moduleName,
                                                                           benchmarkName: name)
    // if thresholds are nil here, we failed to read anything from the file and might want to warn or set up
    // other thresholds
    return configuration
}



let benchmarks = {
    Benchmark.defaultConfiguration = .init(
        metrics: .all,
        warmupIterations: 1
    )
    
    do {
        let testName = "Verifier"
        Benchmark("Verifier", configuration: makeConfigurationFor(testName)) { benchmark in
            for _ in benchmark.scaledIterations {
                await verifier()
            }
        }
    }

    do {
        let runParseWebPKIRoots = parseWebPKIRoots()
        let testName = "Parse WebPKI Roots"
        Benchmark(testName, configuration: makeConfigurationFor(testName)) { benchmark in
            for _ in benchmark.scaledIterations {
                runParseWebPKIRoots()
            }
        }
    }
    do {
        let testName = "TinyArray non-allocating functions"
        Benchmark(testName, configuration: makeConfigurationFor(testName)) { benchmark in
            for _ in benchmark.scaledIterations {
                tinyArrayNonAllocationFunctions()
            }
        }
    }
    
    do {
        let testName = "TinyArray.append(_:)"
        Benchmark(testName, configuration: makeConfigurationFor(testName)) { benchmark in
            for _ in benchmark.scaledIterations {
                tinyArrayAppend()
            }
        }
    }
}
