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

import XCTest
import SwiftASN1
@_spi(Testing) @testable import X509

final class CertificateStoreTests: XCTestCase {
    #if os(Linux)
    func testLoadingDefaultTrustRoots() async throws {
        let log = DiagnosticsLog()
        let store = await CertificateStore.systemTrustRoots.resolve(diagnosticsCallback: log.append(_:))
        XCTAssertGreaterThanOrEqual(store.totalCertificateCount, 100, "expected to find at least 100 certificates")
        XCTAssertEqual(log, [])
    }
    #else
    func testLoadingDefaultTrustRoots() async throws {
        let log = DiagnosticsLog()

        let store = await CertificateStore.systemTrustRoots.resolve(diagnosticsCallback: log.append(_:))
        XCTAssertEqual(store.totalCertificateCount, 0)

        XCTAssertEqual(log.count, 1)
    }

    #endif

    func testLoadingFailsGracefullyIfFilesDoNotExist() {
        let searchPaths = [
            "/some/path/that/does/not/exist/1",
            "/some/path/that/does/not/exist/2",
        ]
        XCTAssertThrowsError(try CertificateStore.loadTrustRoots(at: searchPaths)) { error in
            guard let error = error as? CertificateError else {
                return XCTFail("could not cast \(error) to \(CertificateError.self)")
            }
            XCTAssertEqual(error.code, .failedToLoadSystemTrustStore)
        }
    }

    func testLoadingFailsGracefullyIfFirstFileDoesNotExist() throws {
        let caCertificatesURL = try XCTUnwrap(Bundle.module.url(forResource: "ca-certificates", withExtension: "crt"))
        let searchPaths = [
            "/some/path/that/does/not/exist/1",
            caCertificatesURL.path,
        ]
        let log = DiagnosticsLog()
        let store = try CertificateStore.loadTrustRoots(at: searchPaths)
        XCTAssertEqual(log, [])
        XCTAssertEqual(store.values.lazy.map(\.count).reduce(0, +), 137)
    }
}

extension CertificateStore.Resolved {
    var totalCertificateCount: Int {
        self.systemTrustRoots.values.lazy.map(\.count).reduce(0, +)
            + self.additionTrustRoots.values.lazy.map(\.count).reduce(0, +)
    }
}
