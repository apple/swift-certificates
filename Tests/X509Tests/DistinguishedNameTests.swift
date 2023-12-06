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
            RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcd"),
        ]
        let nameA = RelativeDistinguishedName(expected)
        let nameB = RelativeDistinguishedName(expected.reversed())
        XCTAssertEqual(Array(nameA), expected)
        XCTAssertEqual(Array(nameB), expected)
    }

    func testSimpleRelativeDistinguishedNameSortsItsElementsWhenAssignedAfterTheFact() throws {
        let expected = [
            try RelativeDistinguishedName.Attribute(type: .NameAttributes.commonName, printableString: "efgh"),
            RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcd"),
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
            RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcd"),
            RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcde"),
            RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcdef"),
        ]
        let nameA = RelativeDistinguishedName(expected)
        let nameB = RelativeDistinguishedName(expected.reversed())
        XCTAssertEqual(Array(nameA), expected)
        XCTAssertEqual(Array(nameB), expected)
    }

    func testSimpleRelativeDistinguishedNameRemoveAt() throws {
        var rdn = RelativeDistinguishedName([
            RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcd"),
            RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcde"),
            RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcdef"),
        ])

        XCTAssertEqual(
            rdn.remove(at: 1),
            RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcde")
        )
        XCTAssertEqual(
            rdn,
            RelativeDistinguishedName([
                RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcd"),
                RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcdef"),
            ])
        )

        XCTAssertEqual(
            rdn.remove(at: 0),
            RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcd")
        )
        XCTAssertEqual(
            rdn,
            RelativeDistinguishedName([
                RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcdef")
            ])
        )

        XCTAssertEqual(
            rdn.remove(at: 0),
            RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcdef")
        )
        XCTAssertEqual(rdn, RelativeDistinguishedName())
    }

    func testSimpleRelativeDistinguishedNameRemoveAll() throws {
        var rdn = RelativeDistinguishedName([
            RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcd"),
            RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcde"),
            RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcdef"),
        ])

        rdn.removeAll(where: {
            $0 == RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcde")
        })

        XCTAssertEqual(
            rdn,
            RelativeDistinguishedName([
                RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcd"),
                RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcdef"),
            ])
        )

        rdn.removeAll(where: {
            $0 == RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcd")
        })
        XCTAssertEqual(
            rdn,
            RelativeDistinguishedName([
                RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcdef")
            ])
        )

        rdn.removeAll(where: {
            $0 == RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcdef")
        })
        XCTAssertEqual(rdn, RelativeDistinguishedName())
    }

    func testSimpleRelativeDistinguishedNameRemoveAllInOneGo() throws {
        var rdn = RelativeDistinguishedName([
            RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcd"),
            RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcde"),
            RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcdef"),
        ])

        rdn.removeAll(where: { _ in true })

        XCTAssertEqual(rdn, RelativeDistinguishedName())
    }

    func testSimpleRelativeDistinguishedNameRoundTrips() throws {
        let name = RelativeDistinguishedName([
            RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcd"),
            try RelativeDistinguishedName.Attribute(type: .NameAttributes.commonName, printableString: "efgh"),
        ])
        try self.assertRoundTrips(name)
    }

    func testSimpleRelativeDistinguishedNameSerializesAsExpected() throws {
        let name = RelativeDistinguishedName([
            try RelativeDistinguishedName.Attribute(type: .NameAttributes.commonName, printableString: "efgh"),
            RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcd"),
        ])

        var serializer = DER.Serializer()
        try serializer.serialize(name)

        let expectedBytes: [UInt8] = [
            49, 26, 48, 11, 6, 3, 85, 4, 3, 19, 4, 0x65, 0x66, 0x67, 0x68, 48, 11, 6, 3, 85, 4, 41, 12, 4, 0x61, 0x62,
            0x63, 0x64,
        ]

        XCTAssertEqual(serializer.serializedBytes, expectedBytes)
    }

    func testSimpleDistinguishedNameRoundTrips() throws {
        let firstName = RelativeDistinguishedName([
            RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcd"),
            try RelativeDistinguishedName.Attribute(type: .NameAttributes.commonName, printableString: "efgh"),
        ])
        let secondName = RelativeDistinguishedName([
            RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "ijkl"),
            try RelativeDistinguishedName.Attribute(type: .NameAttributes.commonName, printableString: "mnop"),
        ])
        let name = DistinguishedName([firstName, secondName])
        try self.assertRoundTrips(name)
    }

    func testSimpleDistinguishedNameSerializesAsExpected() throws {
        let firstName = RelativeDistinguishedName([
            RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "abcd"),
            try RelativeDistinguishedName.Attribute(type: .NameAttributes.commonName, printableString: "efgh"),
        ])
        let secondName = RelativeDistinguishedName([
            RelativeDistinguishedName.Attribute(type: .NameAttributes.name, utf8String: "ijkl"),
            try RelativeDistinguishedName.Attribute(type: .NameAttributes.commonName, printableString: "mnop"),
        ])
        let name = DistinguishedName([firstName, secondName])

        var serializer = DER.Serializer()
        try serializer.serialize(name)

        let expectedBytes: [UInt8] = [
            48, 56, 49, 26, 48, 11, 6, 3, 85, 4, 3, 19, 4, 0x65, 0x66, 0x67, 0x68, 48, 11, 6, 3, 85,
            4, 41, 12, 4, 0x61, 0x62, 0x63, 0x64, 49, 26, 48, 11, 6, 3, 85, 4, 3, 19, 4, 0x6d, 0x6e, 0x6f,
            0x70, 48, 11, 6, 3, 85, 4, 41, 12, 4, 0x69, 0x6a, 0x6b, 0x6c,
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
                RelativeDistinguishedName.Attribute(
                    type: .RDNAttributeType.organizationName,
                    utf8String: "DigiCert Inc"
                ),
                RelativeDistinguishedName.Attribute(
                    type: .RDNAttributeType.organizationalUnitName,
                    utf8String: "www.digicert.com"
                ),
                RelativeDistinguishedName.Attribute(
                    type: .RDNAttributeType.commonName,
                    utf8String: "DigiCert Global Root G3"
                ),
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
                RelativeDistinguishedName.Attribute(
                    type: .RDNAttributeType.organizationName,
                    utf8String: "DigiCert Inc"
                ),
                RelativeDistinguishedName.Attribute(
                    type: .RDNAttributeType.organizationalUnitName,
                    utf8String: "www.digicert.com"
                ),
                RelativeDistinguishedName.Attribute(
                    type: .RDNAttributeType.streetAddress,
                    utf8String: "123 Real Street"
                ),
                RelativeDistinguishedName.Attribute(type: .RDNAttributeType.commonName, utf8String: "baz"),
            ])
        )
    }

    func testDistinguishedNameRepresentation() throws {
        let name = try DistinguishedName([
            RelativeDistinguishedName.Attribute(type: .RDNAttributeType.countryName, utf8String: "US"),
            RelativeDistinguishedName.Attribute(type: .RDNAttributeType.organizationName, utf8String: "DigiCert Inc"),
            RelativeDistinguishedName.Attribute(
                type: .RDNAttributeType.organizationalUnitName,
                utf8String: "www.digicert.com"
            ),
            RelativeDistinguishedName.Attribute(
                type: .RDNAttributeType.commonName,
                utf8String: "DigiCert Global Root G3"
            ),
        ])

        let s = String(describing: name)
        XCTAssertEqual(s, "CN=DigiCert Global Root G3,OU=www.digicert.com,O=DigiCert Inc,C=US")
    }

    func testDistinguishedNameRepresentationWithNestedAttributes() throws {
        let name = try DistinguishedName([
            RelativeDistinguishedName([
                RelativeDistinguishedName.Attribute(type: .RDNAttributeType.countryName, utf8String: "US")
            ]),
            RelativeDistinguishedName([
                RelativeDistinguishedName.Attribute(type: .RDNAttributeType.stateOrProvinceName, printableString: "CA"),
                RelativeDistinguishedName.Attribute(
                    type: .RDNAttributeType.stateOrProvinceName,
                    utf8String: "California"
                ),
            ]),
            RelativeDistinguishedName([
                RelativeDistinguishedName.Attribute(
                    type: .RDNAttributeType.organizationName,
                    utf8String: "DigiCert Inc"
                )
            ]),
            RelativeDistinguishedName([
                RelativeDistinguishedName.Attribute(
                    type: .RDNAttributeType.organizationalUnitName,
                    utf8String: "www.digicert.com"
                )
            ]),
            RelativeDistinguishedName([
                RelativeDistinguishedName.Attribute(
                    type: .RDNAttributeType.commonName,
                    utf8String: "DigiCert Global Root G3"
                )
            ]),
        ])

        let s = String(describing: name)
        XCTAssertEqual(s, "CN=DigiCert Global Root G3,OU=www.digicert.com,O=DigiCert Inc,ST=CA+ST=California,C=US")
    }

    func testDistinguishedNameRepresentationWithCommasAndNewlines() throws {
        let name = try DistinguishedName([
            RelativeDistinguishedName.Attribute(type: .RDNAttributeType.countryName, utf8String: "US "),
            RelativeDistinguishedName.Attribute(type: .RDNAttributeType.organizationName, utf8String: " DigiCert Inc"),
            RelativeDistinguishedName.Attribute(
                type: .RDNAttributeType.organizationalUnitName,
                utf8String: "#www.digicert.com"
            ),
            RelativeDistinguishedName.Attribute(type: .RDNAttributeType.commonName, utf8String: ",+\"\\<>;"),
        ])

        let s = String(describing: name)
        XCTAssertEqual(s, "CN=\\,\\+\\\"\\\\\\<\\>\\;,OU=\\#www.digicert.com,O=\\ DigiCert Inc,C=US\\ ")
    }

    func testRDNAttributeValue() {
        func XCTAssertEqualValueAndHash<Value>(
            _ expression1: @autoclosure () throws -> Value,
            _ expression2: @autoclosure () throws -> Value,
            _ message: @autoclosure () -> String = "",
            file: StaticString = #filePath,
            line: UInt = #line
        ) where Value: Hashable {
            let lhs: Value
            do {
                lhs = try expression1()
            } catch {
                XCTFail("\(error)", file: file, line: line)
                return
            }
            let rhs: Value
            do {
                rhs = try expression2()
            } catch {
                XCTFail("\(error)", file: file, line: line)
                return
            }
            XCTAssertEqual(lhs, rhs, file: file, line: line)

            var lhsHasher = Hasher()
            lhsHasher.combine(lhs)
            var rhsHasher = Hasher()
            rhsHasher.combine(rhs)

            XCTAssertEqual(
                lhsHasher.finalize(),
                rhsHasher.finalize(),
                "hashes should be the same for \(lhs) and \(rhs)",
                file: file,
                line: line
            )
        }

        XCTAssertEqualValueAndHash(
            try RelativeDistinguishedName.Attribute.Value(
                asn1Any: ASN1Any(erasing: ASN1UTF8String("This is a fancy UTF8 String with Emojies 🥳🐥"))
            ),
            RelativeDistinguishedName.Attribute.Value(utf8String: "This is a fancy UTF8 String with Emojies 🥳🐥")
        )

        XCTAssertEqualValueAndHash(
            try RelativeDistinguishedName.Attribute.Value(
                asn1Any: ASN1Any(erasing: ASN1PrintableString("This is a simple printable string 123456789 ():="))
            ),
            try RelativeDistinguishedName.Attribute.Value(
                printableString: "This is a simple printable string 123456789 ():="
            )
        )

        XCTAssertEqualValueAndHash(
            try RelativeDistinguishedName.Attribute.Value(
                asn1Any: ASN1Any(erasing: ASN1UTF8String(String(repeating: "A", count: 129)))
            ),
            RelativeDistinguishedName.Attribute.Value(utf8String: String(repeating: "A", count: 129))
        )

        XCTAssertEqualValueAndHash(
            try RelativeDistinguishedName.Attribute.Value(
                asn1Any: ASN1Any(erasing: ASN1UTF8String(String(repeating: "A", count: Int(UInt16.max) + 1)))
            ),
            RelativeDistinguishedName.Attribute.Value(utf8String: String(repeating: "A", count: Int(UInt16.max) + 1))
        )
    }

    func testRDNAttributeValuesCanBeConvertedToStrings() throws {
        let examplesAndResults: [(RelativeDistinguishedName.Attribute, String?)] = try [
            (.init(type: .RDNAttributeType.commonName, printableString: "foo"), "foo"),
            (.init(type: .RDNAttributeType.commonName, utf8String: "bar"), "bar"),
            (.init(type: .RDNAttributeType.commonName, value: ASN1Any(erasing: ASN1IA5String("foo"))), nil),
        ]

        for (example, result) in examplesAndResults {
            XCTAssertEqual(String(example.value), result)
        }
    }

    func testRDNAttributeValuesCanBeConvertedToStringsInSomeOfTheAnyCasesToo() throws {
        let weirdOID: ASN1ObjectIdentifier = [1, 2, 3, 4, 5]

        let examplesAndResults: [(RelativeDistinguishedName.Attribute, String?)] = try [
            (.init(type: weirdOID, printableString: "foo"), "foo"),
            (.init(type: weirdOID, utf8String: "bar"), "bar"),
            (.init(type: weirdOID, value: ASN1Any(erasing: ASN1UTF8String("foo"))), "foo"),
            (.init(type: weirdOID, value: ASN1Any(erasing: ASN1PrintableString("baz"))), "baz"),
            (.init(type: weirdOID, value: ASN1Any(erasing: ASN1IA5String("foo"))), nil),
            (.init(type: weirdOID, value: ASN1Any(erasing: 5)), nil),
            (.init(type: weirdOID, value: ASN1Any(erasing: ASN1OctetString(contentBytes: [1, 2, 3, 4]))), nil),
        ]

        for (example, result) in examplesAndResults {
            XCTAssertEqual(String(example.value), result)
        }
    }
}
