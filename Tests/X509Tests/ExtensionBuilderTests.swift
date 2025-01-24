//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCertificates open source project
//
// Copyright (c) 2022 Apple Inc. and the SwiftCertificates project authors
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

final class ExtensionBuilderTests: XCTestCase {
    func testSimpleBuilder() throws {
        let x = 1
        let extensions = try Certificate.Extensions {
            Certificate.Extension(oid: .X509ExtensionID.authorityInformationAccess, critical: true, value: [1, 2, 3])

            Certificate.Extension(oid: .X509ExtensionID.authorityKeyIdentifier, critical: true, value: [4, 5, 6])

            if x == 1 {
                Certificate.Extension(oid: .X509ExtensionID.basicConstraints, critical: true, value: [7, 8, 9])
            }

            if x == 2 {
                Certificate.Extension(oid: .X509ExtensionID.extendedKeyUsage, critical: true, value: [10, 11, 12])
            } else {
                Certificate.Extension(oid: .X509ExtensionID.nameConstraints, critical: false, value: [13, 14, 15])
            }

            if x == 3 {
                Certificate.Extension(oid: .X509ExtensionID.nameConstraints, critical: false, value: [16, 17, 18])
            }

            for i in 19..<22 {
                Certificate.Extension(oid: [1, UInt(i)], critical: false, value: [22])
            }
        }

        let expectedExtensions = try Certificate.Extensions([
            Certificate.Extension(oid: .X509ExtensionID.authorityInformationAccess, critical: true, value: [1, 2, 3]),
            Certificate.Extension(oid: .X509ExtensionID.authorityKeyIdentifier, critical: true, value: [4, 5, 6]),
            Certificate.Extension(oid: .X509ExtensionID.basicConstraints, critical: true, value: [7, 8, 9]),
            Certificate.Extension(oid: .X509ExtensionID.nameConstraints, critical: false, value: [13, 14, 15]),
            Certificate.Extension(oid: [1, 19], critical: false, value: [22]),
            Certificate.Extension(oid: [1, 20], critical: false, value: [22]),
            Certificate.Extension(oid: [1, 21], critical: false, value: [22]),
        ])

        XCTAssertEqual(extensions, expectedExtensions)
    }

    func testMakingThingsCritical() throws {
        let extensions = try Certificate.Extensions {
            Critical(
                Certificate.Extension(
                    oid: .X509ExtensionID.authorityInformationAccess,
                    critical: false,
                    value: [1, 2, 3]
                )
            )
        }

        let expectedExtensions = try Certificate.Extensions([
            Certificate.Extension(oid: .X509ExtensionID.authorityInformationAccess, critical: true, value: [1, 2, 3])
        ])

        XCTAssertEqual(extensions, expectedExtensions)
    }

    func testThrowingExtension() throws {
        struct MyError: Error {}
        struct MyThrowingExtension: CertificateExtensionConvertible {
            func makeCertificateExtension() throws -> Certificate.Extension {
                throw MyError()
            }
        }

        let `true` = true
        let `false` = false

        XCTAssertThrowsError(
            try Certificate.Extensions {
                MyThrowingExtension()
            }
        ) { error in
            XCTAssertTrue(error is MyError, "wrong error \(error)")
        }

        XCTAssertThrowsError(
            try Certificate.Extensions {
                MyThrowingExtension()
                MyThrowingExtension()
            }
        ) { error in
            XCTAssertTrue(error is MyError, "wrong error \(error)")
        }

        XCTAssertThrowsError(
            try Certificate.Extensions {
                for _ in 0..<3 {
                    MyThrowingExtension()
                }
            }
        ) { error in
            XCTAssertTrue(error is MyError, "wrong error \(error)")
        }

        XCTAssertThrowsError(
            try Certificate.Extensions {
                Certificate.Extension(oid: [1, 1], critical: false, value: [1])
                MyThrowingExtension()
            }
        ) { error in
            XCTAssertTrue(error is MyError, "wrong error \(error)")
        }

        XCTAssertThrowsError(
            try Certificate.Extensions {
                MyThrowingExtension()
                Certificate.Extension(oid: [1, 1], critical: false, value: [1])
            }
        ) { error in
            XCTAssertTrue(error is MyError, "wrong error \(error)")
        }

        XCTAssertThrowsError(
            try Certificate.Extensions {
                if `true` {
                    MyThrowingExtension()
                }
            }
        ) { error in
            XCTAssertTrue(error is MyError, "wrong error \(error)")
        }

        XCTAssertNoThrow(
            try Certificate.Extensions {
                if `false` {
                    MyThrowingExtension()
                }
            }
        )

        XCTAssertThrowsError(
            try Certificate.Extensions {
                if `true` {
                    MyThrowingExtension()
                } else {
                    Certificate.Extension(oid: [1, 1], critical: false, value: [1])
                }
            }
        ) { error in
            XCTAssertTrue(error is MyError, "wrong error \(error)")
        }

        XCTAssertNoThrow(
            try Certificate.Extensions {
                if `false` {
                    MyThrowingExtension()
                } else {
                    Certificate.Extension(oid: [1, 1], critical: false, value: [1])
                }
            }
        )

        XCTAssertNoThrow(
            try Certificate.Extensions {
                if `true` {
                    Certificate.Extension(oid: [1, 1], critical: false, value: [1])
                } else {
                    MyThrowingExtension()
                }
            }
        )

        XCTAssertThrowsError(
            try Certificate.Extensions {
                if `false` {
                    Certificate.Extension(oid: [1, 1], critical: false, value: [1])
                } else {
                    MyThrowingExtension()
                }
            }
        ) { error in
            XCTAssertTrue(error is MyError, "wrong error \(error)")
        }
    }

    func testInitDuplicateHandling() {
        XCTAssertThrowsError(
            try Certificate.Extensions([
                .init(oid: [1, 1], critical: false, value: [1]),
                .init(oid: [1, 1], critical: false, value: [2]),
            ])
        ) { error in
            XCTAssertEqual((error as? CertificateError)?.code, .duplicateOID, "wrong error \(error)")
        }

        XCTAssertThrowsError(
            try Certificate.Extensions([
                .init(oid: [1, 1], critical: false, value: [1]),
                .init(oid: [1, 2], critical: false, value: [1]),
                .init(oid: [1, 1], critical: false, value: [2]),
            ])
        ) { error in
            XCTAssertEqual((error as? CertificateError)?.code, .duplicateOID, "wrong error \(error)")
        }

        XCTAssertThrowsError(
            try Certificate.Extensions {
                try ExtendedKeyUsage([.serverAuth])
                try ExtendedKeyUsage([.clientAuth])
            }
        ) { error in
            XCTAssertEqual((error as? CertificateError)?.code, .duplicateOID, "wrong error \(error)")
        }
    }

    func testAppend() {
        var extensions = Certificate.Extensions()
        XCTAssertNoThrow(try extensions.append(.init(oid: [1, 1], critical: false, value: [1])))
        XCTAssertNoThrow(try extensions.append(.init(oid: [1, 2], critical: true, value: [1])))
        XCTAssertEqual(
            extensions,
            try Certificate.Extensions([
                .init(oid: [1, 1], critical: false, value: [1]),
                .init(oid: [1, 2], critical: true, value: [1]),
            ])
        )
        XCTAssertThrowsError(try extensions.append(.init(oid: [1, 2], critical: false, value: [1]))) { error in
            XCTAssertEqual((error as? CertificateError)?.code, .duplicateOID, "wrong error \(error)")
        }
        XCTAssertEqual(
            extensions,
            try Certificate.Extensions([
                .init(oid: [1, 1], critical: false, value: [1]),
                .init(oid: [1, 2], critical: true, value: [1]),
            ])
        )
    }

    func testUpdate() {
        var extensions = Certificate.Extensions()
        extensions.update(.init(oid: [1, 1], critical: false, value: [1]))
        XCTAssertEqual(
            extensions.update(.init(oid: [1, 1], critical: false, value: [2])),
            .init(oid: [1, 1], critical: false, value: [1])
        )
        XCTAssertEqual(
            extensions,
            try Certificate.Extensions([
                .init(oid: [1, 1], critical: false, value: [2])
            ])
        )
    }

    func testRemove() {
        var extensions = Certificate.Extensions()
        extensions.remove([1, 1])
        XCTAssertEqual(extensions, Certificate.Extensions())
        XCTAssertNoThrow(try extensions.append(.init(oid: [1, 1], critical: false, value: [1])))
        XCTAssertNoThrow(try extensions.append(.init(oid: [1, 2], critical: true, value: [1])))
        extensions.remove([1, 2])
        XCTAssertEqual(
            extensions,
            try Certificate.Extensions {
                Certificate.Extension(oid: [1, 1], critical: false, value: [1])
            }
        )
        extensions.remove([1, 2])
        XCTAssertEqual(
            extensions,
            try Certificate.Extensions {
                Certificate.Extension(oid: [1, 1], critical: false, value: [1])
            }
        )
        extensions.remove([1, 1])
        XCTAssertEqual(extensions, Certificate.Extensions())
    }

    func testLargeNumberOfExtensions() throws {
        let ext = try Certificate.Extensions(
            (0..<32).map {
                Certificate.Extension(oid: [1, $0], critical: false, value: [1, 2, 3, 4])
            }
        )
        XCTAssertEqual(ext.count, 32)
    }

    func testUnreasonableLargeNumberOfExtensionsAreRejected() {
        XCTAssertThrowsError(
            try Certificate.Extensions(
                (0..<33).map {
                    Certificate.Extension(oid: [1, $0], critical: false, value: [1, 2, 3, 4])
                }
            )
        )

        XCTAssertThrowsError(
            try Certificate.Extensions(
                (0..<10_000).map {
                    Certificate.Extension(oid: [1, $0], critical: false, value: [1, 2, 3, 4])
                }
            )
        )
    }
}
