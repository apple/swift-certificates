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
                Certificate.Extension(oid: [UInt(i)], critical: false, value: [22])
            }
        }

        let expectedExtensions = Certificate.Extensions([
            Certificate.Extension(oid: .X509ExtensionID.authorityInformationAccess, critical: true, value: [1, 2, 3]),
            Certificate.Extension(oid: .X509ExtensionID.authorityKeyIdentifier, critical: true, value: [4, 5, 6]),
            Certificate.Extension(oid: .X509ExtensionID.basicConstraints, critical: true, value: [7, 8, 9]),
            Certificate.Extension(oid: .X509ExtensionID.nameConstraints, critical: false, value: [13, 14, 15]),
            Certificate.Extension(oid: [19], critical: false, value: [22]),
            Certificate.Extension(oid: [20], critical: false, value: [22]),
            Certificate.Extension(oid: [21], critical: false, value: [22]),
        ])

        XCTAssertEqual(extensions, expectedExtensions)
    }

    func testMakingThingsCritical() throws {
        let extensions = try Certificate.Extensions {
            Critical(
                Certificate.Extension(oid: .X509ExtensionID.authorityInformationAccess, critical: false, value: [1, 2, 3])
            )
        }

        let expectedExtensions = Certificate.Extensions([
            Certificate.Extension(oid: .X509ExtensionID.authorityInformationAccess, critical: true, value: [1, 2, 3]),
        ])

        XCTAssertEqual(extensions, expectedExtensions)
    }
}
