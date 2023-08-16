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
                    NameConstraintsPolicy.directoryNameMatchesConstraint(
                        directoryName: firstName,
                        constraint: secondName
                    ),
                    firstName == secondName,
                    "Expected directory name match to be \(firstName == secondName) for \(firstName) and \(secondName)"
                )
            }
        }
    }

    func testLazyProperties() {
        struct NameConstraintsPropertyValue {
            var property: PartialKeyPath<NameConstraints>
            var setValue: (inout NameConstraints) -> Void
            var assertValueIsSet: (NameConstraints) -> Void
            init<Property: Hashable>(
                _ keyPath: WritableKeyPath<NameConstraints, Property>,
                value: Property,
                file: StaticString = #filePath,
                line: UInt = #line
            ) {
                self.property = keyPath
                self.setValue = { constraints in
                    constraints[keyPath: keyPath] = value
                }

                self.assertValueIsSet = { constraints in
                    // check Equatable conformance
                    XCTAssertEqual(constraints[keyPath: keyPath], value, file: file, line: line)

                    // check Hashable conformance
                    var lhsHasher = Hasher()
                    lhsHasher.combine(constraints[keyPath: keyPath])
                    var rhsHasher = Hasher()
                    rhsHasher.combine(value)
                    XCTAssertEqual(
                        lhsHasher.finalize(),
                        rhsHasher.finalize(),
                        "hashes do not match for \(constraints[keyPath: keyPath]) and \(value)",
                        file: file,
                        line: line
                    )
                }
            }
        }

        let tests: [NameConstraintsPropertyValue] = [
            NameConstraintsPropertyValue(\.excludedDNSDomains, value: []),
            NameConstraintsPropertyValue(\.excludedDNSDomains, value: ["apple.com"]),
            NameConstraintsPropertyValue(\.excludedDNSDomains, value: ["example.com"]),
            NameConstraintsPropertyValue(\.excludedDNSDomains, value: ["apple.com", "example.com"]),
            NameConstraintsPropertyValue(\.permittedDNSDomains, value: []),
            NameConstraintsPropertyValue(\.permittedDNSDomains, value: ["apple.com"]),
            NameConstraintsPropertyValue(\.permittedDNSDomains, value: ["example.com"]),
            NameConstraintsPropertyValue(\.permittedDNSDomains, value: ["apple.com", "example.com"]),

            NameConstraintsPropertyValue(\.excludedEmailAddresses, value: []),
            NameConstraintsPropertyValue(\.excludedEmailAddresses, value: ["foo@example.com"]),
            NameConstraintsPropertyValue(\.excludedEmailAddresses, value: ["bar@example.com"]),
            NameConstraintsPropertyValue(\.excludedEmailAddresses, value: ["foo@example.com", "bar@example.com"]),
            NameConstraintsPropertyValue(\.permittedEmailAddresses, value: []),
            NameConstraintsPropertyValue(\.permittedEmailAddresses, value: ["foo@example.com"]),
            NameConstraintsPropertyValue(\.permittedEmailAddresses, value: ["bar@example.com"]),
            NameConstraintsPropertyValue(\.permittedEmailAddresses, value: ["foo@example.com", "bar@example.com"]),

            NameConstraintsPropertyValue(\.excludedIPRanges, value: []),
            NameConstraintsPropertyValue(\.excludedIPRanges, value: [.v4("127.0.0.1")]),
            NameConstraintsPropertyValue(\.excludedIPRanges, value: [.v4("192.168.0.1")]),
            NameConstraintsPropertyValue(\.excludedIPRanges, value: [.v4("127.0.0.1"), .v4("192.168.0.1")]),
            NameConstraintsPropertyValue(\.permittedIPRanges, value: []),
            NameConstraintsPropertyValue(\.permittedIPRanges, value: [.v4("127.0.0.1")]),
            NameConstraintsPropertyValue(\.permittedIPRanges, value: [.v4("192.168.0.1")]),
            NameConstraintsPropertyValue(\.permittedIPRanges, value: [.v4("127.0.0.1"), .v4("192.168.0.1")]),

            NameConstraintsPropertyValue(\.forbiddenURIDomains, value: []),
            NameConstraintsPropertyValue(\.forbiddenURIDomains, value: [".example.com"]),
            NameConstraintsPropertyValue(\.forbiddenURIDomains, value: [".apple.com"]),
            NameConstraintsPropertyValue(\.forbiddenURIDomains, value: [".example.com", ".apple.com"]),
            NameConstraintsPropertyValue(\.permittedURIDomains, value: []),
            NameConstraintsPropertyValue(\.permittedURIDomains, value: [".example.com"]),
            NameConstraintsPropertyValue(\.permittedURIDomains, value: [".apple.com"]),
            NameConstraintsPropertyValue(\.permittedURIDomains, value: [".example.com", ".apple.com"]),
        ]

        // This will set the properties to the above values in order (and in reversed order).
        // After it sets each property it asserts that the previous latest value of other properties are still set
        // to their previous latest values and are not modified.

        var nameConstraints = NameConstraints()
        var latestValueForProperty: [PartialKeyPath<NameConstraints>: NameConstraintsPropertyValue] = [:]

        for test in tests + tests.reversed() {
            test.setValue(&nameConstraints)
            latestValueForProperty[test.property] = test

            let newNameConstraints = NameConstraints(
                permittedDNSDomains: nameConstraints.permittedDNSDomains,
                excludedDNSDomains: nameConstraints.excludedDNSDomains,
                permittedIPRanges: nameConstraints.permittedIPRanges,
                excludedIPRanges: nameConstraints.excludedIPRanges,
                permittedEmailAddresses: nameConstraints.permittedEmailAddresses,
                excludedEmailAddresses: nameConstraints.excludedEmailAddresses,
                permittedURIDomains: nameConstraints.permittedURIDomains,
                forbiddenURIDomains: nameConstraints.forbiddenURIDomains
            )

            for latestValue in latestValueForProperty.values {
                latestValue.assertValueIsSet(nameConstraints)
                latestValue.assertValueIsSet(newNameConstraints)
            }
        }
    }
}
