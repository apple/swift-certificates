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
    func testLoadingDefaultTrustRootsOnLinux() async throws {
        let log = DiagnosticsLog()
        let store = await CertificateStore.systemTrustRoots.resolve(diagnosticsCallback: log.append(_:))
        XCTAssertGreaterThanOrEqual(store.totalCertificateCount, 100, "expected to find at least 100 certificates")
        XCTAssertEqual(log, [])
    }
    #endif
    
    func testLoadingFailsGracefullyIfFilesDoNotExist() {
        let searchPaths = [
            "/some/path/that/does/not/exist/1",
            "/some/path/that/does/not/exist/2",
        ]
        XCTAssertThrowsError(try CertificateStore.loadTrustRoot(at: searchPaths)) { error in
            guard let error = error as? TrustRootsLoadingError else {
                return XCTFail("could not cast \(error) to \(TrustRootsLoadingError.self)")
            }
            XCTAssertEqual(error.errors.map(\.path), searchPaths)
        }
    }
    
    func testLoadingFailsGracefullyIfFirstFileDoesNotExist() async throws {
        let caCertificatesURL = try XCTUnwrap(Bundle.module.url(forResource: "ca-certificates", withExtension: "crt"))
        let searchPaths = [
            "/some/path/that/does/not/exist/1",
            caCertificatesURL.path,
        ]
        let log = DiagnosticsLog()
        let store = try await CertificateStore.loadTrustRoot(at: searchPaths).resolve(diagnosticsCallback: log.append(_:))
        XCTAssertEqual(log, [])
        XCTAssertEqual(store.totalCertificateCount, 136)
    }
}

extension CertificateStore.Resolved {
    var totalCertificateCount: Int {
        self._certificates.lazy.map(\.count).reduce(0, +)
    }
}
