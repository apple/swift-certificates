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
import X509

final class ExtendedKeyUsageTests: XCTestCase {
    func testInit() {
        XCTAssertThrowsError(
            try ExtendedKeyUsage([
                .serverAuth,
                .serverAuth,
            ])
        ) { error in
            XCTAssertEqual((error as? CertificateError)?.code, .duplicateOID, "wrong error \(error)")
        }

        XCTAssertThrowsError(
            try ExtendedKeyUsage([
                .clientAuth,
                .serverAuth,
                .clientAuth,
            ])
        ) { error in
            XCTAssertEqual((error as? CertificateError)?.code, .duplicateOID, "wrong error \(error)")
        }
    }

    func testInsert() throws {
        var usages = try ExtendedKeyUsage([
            .serverAuth
        ])
        XCTAssertTrue(usages.insert(.clientAuth, at: 1) == (true, 1))
        XCTAssertEqual(
            usages,
            try ExtendedKeyUsage([
                .serverAuth,
                .clientAuth,
            ])
        )
        XCTAssertTrue(usages.insert(.clientAuth, at: 1) == (false, 1))
        XCTAssertEqual(
            usages,
            try ExtendedKeyUsage([
                .serverAuth,
                .clientAuth,
            ])
        )
        XCTAssertTrue(usages.insert(.ocspSigning, at: 1) == (true, 1))
        XCTAssertEqual(
            usages,
            try ExtendedKeyUsage([
                .serverAuth,
                .ocspSigning,
                .clientAuth,
            ])
        )
        XCTAssertTrue(usages.insert(.codeSigning, at: 0) == (true, 0))
        XCTAssertEqual(
            usages,
            try ExtendedKeyUsage([
                .codeSigning,
                .serverAuth,
                .ocspSigning,
                .clientAuth,
            ])
        )
    }

    func testAppend() throws {
        var usages = ExtendedKeyUsage()

        usages.append(.clientAuth)
        XCTAssertEqual(
            usages,
            try ExtendedKeyUsage([
                .clientAuth
            ])
        )

        usages.append(.clientAuth)
        XCTAssertEqual(
            usages,
            try ExtendedKeyUsage([
                .clientAuth
            ])
        )

        usages.append(.ocspSigning)
        XCTAssertEqual(
            usages,
            try ExtendedKeyUsage([
                .clientAuth,
                .ocspSigning,
            ])
        )
    }

    func testRemove() throws {
        var usages = try ExtendedKeyUsage([
            .clientAuth,
            .serverAuth,
            .ocspSigning,
        ])

        XCTAssertNil(usages.remove(.emailProtection))
        XCTAssertEqual(
            usages,
            try ExtendedKeyUsage([
                .clientAuth,
                .serverAuth,
                .ocspSigning,
            ])
        )

        XCTAssertEqual(usages.remove(.clientAuth), .clientAuth)
        XCTAssertEqual(
            usages,
            try ExtendedKeyUsage([
                .serverAuth,
                .ocspSigning,
            ])
        )

        XCTAssertNil(usages.remove(.clientAuth))
        XCTAssertEqual(
            usages,
            try ExtendedKeyUsage([
                .serverAuth,
                .ocspSigning,
            ])
        )

        XCTAssertEqual(usages.remove(.ocspSigning), .ocspSigning)
        XCTAssertEqual(
            usages,
            try ExtendedKeyUsage([
                .serverAuth
            ])
        )

        XCTAssertEqual(usages.remove(.serverAuth), .serverAuth)
        XCTAssertEqual(usages, ExtendedKeyUsage())

        XCTAssertNil(usages.remove(.serverAuth))
        XCTAssertEqual(usages, ExtendedKeyUsage())
    }

    func testLargeNumberOfExtensions() throws {
        let usages = try ExtendedKeyUsage(
            (0..<32).map {
                ExtendedKeyUsage.Usage(oid: [1, $0])
            }
        )
        XCTAssertEqual(usages.count, 32)
    }

    func testUnreasonableLargeNumberOfExtensionsAreRejected() {
        XCTAssertThrowsError(
            try ExtendedKeyUsage(
                (0..<33).map {
                    ExtendedKeyUsage.Usage(oid: [1, $0])
                }
            )
        )

        XCTAssertThrowsError(
            try ExtendedKeyUsage(
                (0..<10_000).map {
                    ExtendedKeyUsage.Usage(oid: [1, $0])
                }
            )
        )
    }
}
