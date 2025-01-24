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
import X509

final class DistinguishedNameBuilderTests: XCTestCase {
    func testSimpleBuilder() throws {
        let x = 1
        let extensions = try DistinguishedName {
            CommonName("1")

            CountryName("2")

            if x == 1 {
                LocalityName("3")
            }

            if x == 2 {
                CommonName("4")
            } else {
                OrganizationName("5")
            }

            if x == 3 {
                CommonName("6")
            }

            for i in 7..<10 {
                StreetAddress("\(i)")
            }
        }

        let expectedExtensions = DistinguishedName([
            RelativeDistinguishedName(.init(type: .RDNAttributeType.commonName, utf8String: "1")),
            try RelativeDistinguishedName(.init(type: .RDNAttributeType.countryName, printableString: "2")),
            RelativeDistinguishedName(.init(type: .RDNAttributeType.localityName, utf8String: "3")),
            RelativeDistinguishedName(.init(type: .RDNAttributeType.organizationName, utf8String: "5")),
            RelativeDistinguishedName(.init(type: .RDNAttributeType.streetAddress, utf8String: "7")),
            RelativeDistinguishedName(.init(type: .RDNAttributeType.streetAddress, utf8String: "8")),
            RelativeDistinguishedName(.init(type: .RDNAttributeType.streetAddress, utf8String: "9")),
        ])

        XCTAssertEqual(extensions, expectedExtensions)
    }
    func testThrowing() throws {
        struct MyError: Error {}
        struct MyThrowingName: RelativeDistinguishedNameConvertible {
            func makeRDN() throws -> RelativeDistinguishedName {
                throw MyError()
            }
        }

        let `true` = true
        let `false` = false

        XCTAssertThrowsError(
            try DistinguishedName {
                MyThrowingName()
            }
        ) { error in
            XCTAssertTrue(error is MyError, "wrong error \(error)")
        }

        XCTAssertThrowsError(
            try DistinguishedName {
                MyThrowingName()
                MyThrowingName()
            }
        ) { error in
            XCTAssertTrue(error is MyError, "wrong error \(error)")
        }

        XCTAssertThrowsError(
            try DistinguishedName {
                for _ in 0..<3 {
                    MyThrowingName()
                }
            }
        ) { error in
            XCTAssertTrue(error is MyError, "wrong error \(error)")
        }

        XCTAssertThrowsError(
            try DistinguishedName {
                CommonName("test")
                MyThrowingName()
            }
        ) { error in
            XCTAssertTrue(error is MyError, "wrong error \(error)")
        }

        XCTAssertThrowsError(
            try DistinguishedName {
                MyThrowingName()
                CommonName("test")
            }
        ) { error in
            XCTAssertTrue(error is MyError, "wrong error \(error)")
        }

        XCTAssertThrowsError(
            try DistinguishedName {
                if `true` {
                    MyThrowingName()
                }
            }
        ) { error in
            XCTAssertTrue(error is MyError, "wrong error \(error)")
        }

        XCTAssertNoThrow(
            try DistinguishedName {
                if `false` {
                    MyThrowingName()
                }
            }
        )

        XCTAssertThrowsError(
            try DistinguishedName {
                if `true` {
                    MyThrowingName()
                } else {
                    CommonName("test")
                }
            }
        ) { error in
            XCTAssertTrue(error is MyError, "wrong error \(error)")
        }

        XCTAssertNoThrow(
            try DistinguishedName {
                if `false` {
                    MyThrowingName()
                } else {
                    CommonName("test")
                }
            }
        )

        XCTAssertNoThrow(
            try DistinguishedName {
                if `true` {
                    CommonName("test")
                } else {
                    MyThrowingName()
                }
            }
        )

        XCTAssertThrowsError(
            try DistinguishedName {
                if `false` {
                    CommonName("test")
                } else {
                    MyThrowingName()
                }
            }
        ) { error in
            XCTAssertTrue(error is MyError, "wrong error \(error)")
        }
    }
}
