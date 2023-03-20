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
@testable import X509

final class NameConstraintsTests: XCTestCase {
    static let names: [DistinguishedName] = [
        try! DistinguishedName {
            CountryName("US")
            StateOrProvinceName("CA")
            OrganizationName("Apple")
        },
        try! DistinguishedName {
            CountryName("US")
            StateOrProvinceName("CA")
            OrganizationName("Apple")
            CommonName("Test")
        },
        try! DistinguishedName {
            CountryName("GB")
            OrganizationName("Apple")
            CommonName("Test")
        },
    ]

    func testDirectoryNameMatches() throws {
        // The key here is that a distinguished name only matches a constraint if they're equal.
        for firstName in NameConstraintsTests.names {
            for secondName in NameConstraintsTests.names {
                XCTAssertEqual(
                    NameConstraintsPolicy.directoryNameMatchesConstraint(directoryName: firstName, constraint: secondName),
                    firstName == secondName,
                    "Expected directory name match to be \(firstName == secondName) for \(firstName) and \(secondName)"
                )
            }
        }
    }
}
