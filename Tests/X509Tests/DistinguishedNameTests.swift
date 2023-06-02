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
@testable import X509

final class DistinguishedNameTests: XCTestCase {
    private func assertRoundTrips<ASN1Object: DERParseable & DERSerializable & Equatable>(_ value: ASN1Object) throws {
        var serializer = DER.Serializer()
        try serializer.serialize(value)
        let parsed = try ASN1Object(derEncoded: serializer.serializedBytes)
        XCTAssertEqual(parsed, value)
    }

    func testSimpleRelativeDistinguishedNameSortsItsElements() throws {
        let expected = [
            try RelativeDistinguishedName.Attribute(type: .NameAttributes.commonName, printableString: "efgh"),
            try RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcd"),
        ]
        let nameA = try RelativeDistinguishedName(expected)
        let nameB = try RelativeDistinguishedName(expected.reversed())
        XCTAssertEqual(Array(nameA), expected)
        XCTAssertEqual(Array(nameB), expected)
    }

    func testSimpleRelativeDistinguishedNameSortsItsElementsWhenAssignedAfterTheFact() throws {
        let expected = [
            try RelativeDistinguishedName.Attribute(type: .NameAttributes.commonName, printableString: "efgh"),
            try RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcd"),
        ]
        var nameA = RelativeDistinguishedName()
        var nameB = RelativeDistinguishedName()
        nameA.insert(contentsOf: expected)
        nameB.insert(contentsOf: expected.reversed())
        XCTAssertEqual(Array(nameA), expected)
        XCTAssertEqual(Array(nameB), expected)
    }

    func testSimpleRelativeDistinguishedNameSortsItsElementsIncludingByLength() throws {
        let expected = [
            try RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcd"),
            try RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcde"),
            try RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcdef"),
        ]
        let nameA = try RelativeDistinguishedName(expected)
        let nameB = try RelativeDistinguishedName(expected.reversed())
        XCTAssertEqual(Array(nameA), expected)
        XCTAssertEqual(Array(nameB), expected)
    }
    
    func testSimpleRelativeDistinguishedNameRemoveAt() throws {
        var rdn = try RelativeDistinguishedName([
            try RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcd"),
            try RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcde"),
            try RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcdef"),
        ])
        
        XCTAssertEqual(
            rdn.remove(at: 1),
            try RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcde")
        )
        XCTAssertEqual(rdn, try RelativeDistinguishedName([
            try RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcd"),
            try RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcdef"),
        ]))
        
        XCTAssertEqual(
            rdn.remove(at: 0),
            try RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcd")
        )
        XCTAssertEqual(rdn, try RelativeDistinguishedName([
            try RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcdef"),
        ]))
        
        XCTAssertEqual(
            rdn.remove(at: 0),
            try RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcdef")
        )
        XCTAssertEqual(rdn, RelativeDistinguishedName())
    }
    
    func testSimpleRelativeDistinguishedNameRemoveAll() throws {
        var rdn = try RelativeDistinguishedName([
            try RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcd"),
            try RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcde"),
            try RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcdef"),
        ])
        
        try rdn.removeAll(where: {
            try $0 == RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcde")
        })
        
        XCTAssertEqual(rdn, try RelativeDistinguishedName([
            try RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcd"),
            try RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcdef"),
        ]))
        
        try rdn.removeAll(where: {
            try $0 == RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcd")
        })
        XCTAssertEqual(rdn, try RelativeDistinguishedName([
            try RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcdef"),
        ]))
        
        try rdn.removeAll(where: {
            try $0 == RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcdef")
        })
        XCTAssertEqual(rdn, RelativeDistinguishedName())
    }
    
    func testSimpleRelativeDistinguishedNameRemoveAllInOneGo() throws {
        var rdn = try RelativeDistinguishedName([
            try RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcd"),
            try RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcde"),
            try RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcdef"),
        ])
        
        rdn.removeAll(where: { _ in true })
        
        XCTAssertEqual(rdn, RelativeDistinguishedName())
    }

    func testSimpleRelativeDistinguishedNameRoundTrips() throws {
        let name = try RelativeDistinguishedName([
            try RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcd"),
            try RelativeDistinguishedName.Attribute(type: .NameAttributes.commonName, printableString: "efgh"),
        ])
        try self.assertRoundTrips(name)
    }

    func testSimpleRelativeDistinguishedNameSerializesAsExpected() throws {
        let name = try RelativeDistinguishedName([
            try RelativeDistinguishedName.Attribute(type: .NameAttributes.commonName, printableString: "efgh"),
            try RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcd"),
        ])

        var serializer = DER.Serializer()
        try serializer.serialize(name)

        let expectedBytes: [UInt8] = [
            49, 26, 48, 11, 6, 3, 85, 4, 3, 19, 4, 0x65, 0x66, 0x67, 0x68, 48, 11, 6, 3, 85, 4, 41, 12, 4, 0x61, 0x62, 0x63, 0x64
        ]

        XCTAssertEqual(serializer.serializedBytes, expectedBytes)
    }

    func testSimpleDistinguishedNameRoundTrips() throws {
        let firstName = try RelativeDistinguishedName([
            try RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcd"),
            try RelativeDistinguishedName.Attribute(type: .NameAttributes.commonName, printableString: "efgh"),
        ])
        let secondName = try RelativeDistinguishedName([
            try RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "ijkl"),
            try RelativeDistinguishedName.Attribute(type: .NameAttributes.commonName, printableString: "mnop"),
        ])
        let name = DistinguishedName([firstName, secondName])
        try self.assertRoundTrips(name)
    }

    func testSimpleDistinguishedNameSerializesAsExpected() throws {
        let firstName = try RelativeDistinguishedName([
            try RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcd"),
            try RelativeDistinguishedName.Attribute(type: .NameAttributes.commonName, printableString: "efgh"),
        ])
        let secondName = try RelativeDistinguishedName([
            try RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "ijkl"),
            try RelativeDistinguishedName.Attribute(type: .NameAttributes.commonName, printableString: "mnop"),
        ])
        let name = DistinguishedName([firstName, secondName])

        var serializer = DER.Serializer()
        try serializer.serialize(name)

        let expectedBytes: [UInt8] = [
            48, 56, 49, 26, 48, 11, 6, 3, 85, 4, 3, 19, 4, 0x65, 0x66, 0x67, 0x68, 48, 11, 6, 3, 85,
            4, 41, 12, 4, 0x61, 0x62, 0x63, 0x64, 49, 26, 48, 11, 6, 3, 85, 4, 3, 19, 4, 0x6d, 0x6e, 0x6f,
            0x70, 48, 11, 6, 3, 85, 4, 41, 12, 4, 0x69, 0x6a, 0x6b, 0x6c
        ]

        XCTAssertEqual(serializer.serializedBytes, expectedBytes)
    }

    func testDistinguishedNameBuilder() throws {
        let name = try DistinguishedName {
            CountryName("US")
            OrganizationName("DigiCert Inc")
            OrganizationalUnitName("www.digicert.com")
            CommonName("DigiCert Global Root G3")
        }
        XCTAssertEqual(
            name,
            try DistinguishedName([
                RelativeDistinguishedName.Attribute(type: .RDNAttributeType.countryName, utf8String: "US"),
                RelativeDistinguishedName.Attribute(type: .RDNAttributeType.organizationName, utf8String: "DigiCert Inc"),
                RelativeDistinguishedName.Attribute(type: .RDNAttributeType.organizationalUnitName, utf8String: "www.digicert.com"),
                RelativeDistinguishedName.Attribute(type: .RDNAttributeType.commonName, utf8String: "DigiCert Global Root G3"),
            ])
        )
    }

    func testDistinguishedNameBuilderFlow() throws {
        let x = 1
        let name = try DistinguishedName {
            CountryName("US")
            OrganizationName("DigiCert Inc")

            if x == 1 {
                OrganizationalUnitName("www.digicert.com")
            }

            if x == 2 {
                StreetAddress("123 Fake Street")
            } else {
                StreetAddress("123 Real Street")
            }

            if x == 3 {
                StateOrProvinceName("DigiLand")
            }

            for name in ["foo", "bar", "baz"].filter({ $0 == "baz" }) {
                CommonName(name)
            }
        }

        XCTAssertEqual(
            name,
            try DistinguishedName([
                RelativeDistinguishedName.Attribute(type: .RDNAttributeType.countryName, utf8String: "US"),
                RelativeDistinguishedName.Attribute(type: .RDNAttributeType.organizationName, utf8String: "DigiCert Inc"),
                RelativeDistinguishedName.Attribute(type: .RDNAttributeType.organizationalUnitName, utf8String: "www.digicert.com"),
                RelativeDistinguishedName.Attribute(type: .RDNAttributeType.streetAddress, utf8String: "123 Real Street"),
                RelativeDistinguishedName.Attribute(type: .RDNAttributeType.commonName, utf8String: "baz"),
            ])
        )
    }

    func testDistinguishedNameRepresentation() throws {
        let name = try DistinguishedName([
            RelativeDistinguishedName.Attribute(type: .RDNAttributeType.countryName, utf8String: "US"),
            RelativeDistinguishedName.Attribute(type: .RDNAttributeType.organizationName, utf8String: "DigiCert Inc"),
            RelativeDistinguishedName.Attribute(type: .RDNAttributeType.organizationalUnitName, utf8String: "www.digicert.com"),
            RelativeDistinguishedName.Attribute(type: .RDNAttributeType.commonName, utf8String: "DigiCert Global Root G3"),
        ])

        let s = String(describing: name)
        XCTAssertEqual(s, "CN=DigiCert Global Root G3,OU=www.digicert.com,O=DigiCert Inc,C=US")
    }

    func testDistinguishedNameRepresentationWithNestedAttributes() throws {
        let name = try DistinguishedName([
            RelativeDistinguishedName([
                RelativeDistinguishedName.Attribute(type: .RDNAttributeType.countryName, utf8String: "US"),
            ]),
            RelativeDistinguishedName([
                RelativeDistinguishedName.Attribute(type: .RDNAttributeType.stateOrProvinceName, printableString: "CA"),
                RelativeDistinguishedName.Attribute(type: .RDNAttributeType.stateOrProvinceName, utf8String: "California")
            ]),
            RelativeDistinguishedName([
                RelativeDistinguishedName.Attribute(type: .RDNAttributeType.organizationName, utf8String: "DigiCert Inc"),
            ]),
            RelativeDistinguishedName([
                RelativeDistinguishedName.Attribute(type: .RDNAttributeType.organizationalUnitName, utf8String: "www.digicert.com"),
            ]),
            RelativeDistinguishedName([
                RelativeDistinguishedName.Attribute(type: .RDNAttributeType.commonName, utf8String: "DigiCert Global Root G3"),
            ])
        ])

        let s = String(describing: name)
        XCTAssertEqual(s, "CN=DigiCert Global Root G3,OU=www.digicert.com,O=DigiCert Inc,ST=CA+ST=California,C=US")
    }

    func testDistinguishedNameRepresentationWithCommasAndNewlines() throws {
        let name = try DistinguishedName([
            RelativeDistinguishedName.Attribute(type: .RDNAttributeType.countryName, utf8String: "US "),
            RelativeDistinguishedName.Attribute(type: .RDNAttributeType.organizationName, utf8String: " DigiCert Inc"),
            RelativeDistinguishedName.Attribute(type: .RDNAttributeType.organizationalUnitName, utf8String: "#www.digicert.com"),
            RelativeDistinguishedName.Attribute(type: .RDNAttributeType.commonName, utf8String: ",+\"\\<>;"),
        ])

        let s = String(describing: name)
        XCTAssertEqual(s, "CN=\\,\\+\\\"\\\\\\<\\>\\;,OU=\\#www.digicert.com,O=\\ DigiCert Inc,C=US\\ ")
    }
}
