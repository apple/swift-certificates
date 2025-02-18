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
#if canImport(Android)
import Android
#endif

final class IPAddressNameTests: XCTestCase {
    static let fixtures: [(ASN1OctetString, ASN1OctetString, Bool)] = [
        // Confirm a few CIDR masks
        (.v4("17.250.78.1"), .v4(subnet: "17.0.0.0", mask: "255.0.0.0"), true),
        (.v4("17.250.78.1"), .v4(subnet: "17.250.0.66", mask: "255.255.0.0"), true),
        (.v4("17.250.78.1"), .v4(subnet: "17.250.78.0", mask: "255.255.255.0"), true),
        (.v4("17.250.78.1"), .v4(subnet: "17.250.78.1", mask: "255.255.255.255"), true),
        (.v4("18.250.78.1"), .v4(subnet: "17.0.0.0", mask: "255.0.0.0"), false),
        (.v4("17.250.78.1"), .v4(subnet: "17.250.78.2", mask: "255.255.255.255"), false),

        // CIDR mask with zero bytes in weird places.
        (.v4("17.250.78.1"), .v4(subnet: "17.250.78.1", mask: "0.0.0.255"), false),
        (.v4("17.250.78.1"), .v4(subnet: "17.250.78.1", mask: "0.0.255.255"), false),
        (.v4("17.250.78.1"), .v4(subnet: "17.250.78.1", mask: "0.255.255.255"), false),
        (.v4("17.250.78.1"), .v4(subnet: "17.250.78.1", mask: "255.0.255.0"), false),
        (.v4("17.250.78.1"), .v4(subnet: "17.250.78.1", mask: "255.255.0.255"), false),

        // CIDR masks that aren't all zeros
        (.v4("17.250.78.1"), .v4(subnet: "17.0.0.0", mask: "128.0.0.0"), true),
        (.v4("17.255.78.1"), .v4(subnet: "17.254.0.0", mask: "255.254.0.0"), true),
        (.v4("17.255.78.1"), .v4(subnet: "17.254.0.0", mask: "255.255.0.0"), false),

        // CIDR masks with weird bit patterns
        (.v4("17.250.78.1"), .v4(subnet: "17.250.78.1", mask: "255.255.62.0"), false),
        (.v4("17.250.78.1"), .v4(subnet: "17.250.78.1", mask: "255.239.255.255"), false),

        // All zero mask matches nothing
        (.v4("17.250.78.1"), .v4(subnet: "0.0.0.0", mask: "0.0.0.0"), false),

        // v4 address with v6 mask and vice-versa
        (.v4("17.250.78.1"), .v6(subnet: "8000::", mask: "8000::"), false),
        (.v6("fe80::"), .v4(subnet: "254.128.0.0", mask: "255.128.0.0"), false),

        // Confirm a few CIDR masks
        (.v6("fe80::8d:f7d:79c5:5719"), .v6(subnet: "fe80::", mask: "ffff:ffff:ffff:ffff::"), true),
        (.v6("fe80::8d:f7d:79c5:5719"), .v6(subnet: "fe80::8d:0:0:0", mask: "ffff:ffff:ffff:ffff:ffff::"), true),
        (.v6("fe80::8d:f7d:79c5:5719"), .v6(subnet: "fe80::8d:f7d:0:0", mask: "ffff:ffff:ffff:ffff:ffff:ffff::"), true),
        (
            .v6("fe80::8d:f7d:79c5:5719"),
            .v6(subnet: "fe80::8d:f7d:79c5:0", mask: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:0"), true
        ),
        (
            .v6("fe80::8d:f7d:79c5:5719"),
            .v6(subnet: "fe80::8d:f7d:79c5:5719", mask: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), true
        ),
        (.v6("fe80::8d:f7d:79c5:5719"), .v6(subnet: "fe81::", mask: "ffff:ffff:ffff:ffff::"), false),
        (
            .v6("fe80::8d:f7d:79d5:5719"),
            .v6(subnet: "fe80::8d:f7d:79c5:5719", mask: "ffff:ffff:ffff:ffff:ffff:ffff:ffff:ffff"), false
        ),

        // CIDR mask with zero bytes in weird places.
        (.v6("fe80::8d:f7d:79c5:5719"), .v6(subnet: "fe80::8d:f7d:79c5:5719", mask: "::ffff"), false),
        (.v6("fe80::8d:f7d:79c5:5719"), .v6(subnet: "fe80::8d:f7d:79c5:5719", mask: "::ffff:ffff"), false),
        (.v6("fe80::8d:f7d:79c5:5719"), .v6(subnet: "fe80::8d:f7d:79c5:5719", mask: "ffff::ffff"), false),
        (.v6("fe80::8d:f7d:79c5:5719"), .v6(subnet: "fe80::8d:f7d:79c5:5719", mask: "ffff:0:0:ffff::ffff"), false),

        // CIDR masks that aren't all zeros
        (.v6("fe80::8d:f7d:79c5:5719"), .v6(subnet: "fe80::8d:f7d:79c5:5719", mask: "8000::"), true),
        (.v6("fe80::8d:f7d:79c5:5719"), .v6(subnet: "fe80::8d:f7d:79c5:5719", mask: "fffe::"), true),
        (.v6("fe80::8d:f7d:79c5:5719"), .v6(subnet: "fe81::8d:f7d:79c5:5719", mask: "ffff:ffff::"), false),

        // CIDR masks with weird bit patterns
        (.v6("fe80::8d:f7d:79c5:5719"), .v6(subnet: "fe81::8d:f7d:79c5:5719", mask: "ffff:ffff:c9c9::"), false),
        (
            .v6("fe80::8d:f7d:79c5:5719"),
            .v6(subnet: "fe81::8d:f7d:79c5:5719", mask: "ffff:ffff:feff:ffff:ffff:ffff:ffff:ffff"), false
        ),

        // All zero mask matches nothing
        (.v6("fe80::8d:f7d:79c5:5719"), .v6(subnet: "::", mask: "::"), false),

        // Require exactly double the bytes for the subnet.
        (.v4("17.250.78.1"), ASN1OctetString(contentBytes: .init(repeating: 0xff, count: 1)), false),
        (.v4("17.250.78.1"), ASN1OctetString(contentBytes: .init(repeating: 0xff, count: 7)), false),
        (.v4("17.250.78.1"), ASN1OctetString(contentBytes: .init(repeating: 0xff, count: 9)), false),
        (.v6("fe80::8d:f7d:79c5:5719"), ASN1OctetString(contentBytes: .init(repeating: 0xff, count: 1)), false),
        (.v6("fe80::8d:f7d:79c5:5719"), ASN1OctetString(contentBytes: .init(repeating: 0xff, count: 31)), false),
        (.v6("fe80::8d:f7d:79c5:5719"), ASN1OctetString(contentBytes: .init(repeating: 0xff, count: 33)), false),
    ]

    func testConstraints() throws {
        // (presented name, constraint, match)
        for (presentedName, constraint, match) in IPAddressNameTests.fixtures {
            XCTAssertEqual(
                NameConstraintsPolicy.ipAddressMatchesConstraint(ipAddress: presentedName, constraint: constraint),
                match,
                "Expected address \(presentedName) matching \(constraint) to be \(match), but it wasn't"
            )
        }
    }
}

extension ASN1OctetString {
    static func v4(_ ipv4Address: String) -> ASN1OctetString {
        var addr = in_addr()
        let rc = inet_pton(AF_INET, ipv4Address, &addr)
        precondition(rc == 1)

        let bytes = Swift.withUnsafeBytes(of: &addr) {
            ArraySlice($0)
        }

        return .init(contentBytes: bytes)
    }

    static func v6(_ ipv6Address: String) -> ASN1OctetString {
        var addr = in6_addr()
        let rc = inet_pton(AF_INET6, ipv6Address, &addr)
        precondition(rc == 1)

        let bytes = Swift.withUnsafeBytes(of: &addr) {
            ArraySlice($0)
        }

        return .init(contentBytes: bytes)
    }

    static func v4(subnet: String, mask: String) -> ASN1OctetString {
        let subnet = ASN1OctetString.v4(subnet)
        let mask = ASN1OctetString.v4(mask)
        return ASN1OctetString(contentBytes: subnet.bytes + mask.bytes)
    }

    static func v6(subnet: String, mask: String) -> ASN1OctetString {
        let subnet = ASN1OctetString.v6(subnet)
        let mask = ASN1OctetString.v6(mask)
        return ASN1OctetString(contentBytes: subnet.bytes + mask.bytes)
    }
}
