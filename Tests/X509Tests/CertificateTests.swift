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

final class CertificateTests: XCTestCase {
    func testPrintingSerial() {
        let serial = Certificate.SerialNumber(bytes: [10, 20, 30, 40])
        let s = String(describing: serial)
        XCTAssertEqual(s, "a:14:1e:28")
    }

    func testPrintingVersions() {
        XCTAssertEqual(String(describing: Certificate.Version.v1), "X509v1")
        XCTAssertEqual(String(describing: Certificate.Version.v3), "X509v3")
        XCTAssertEqual(String(describing: Certificate.Version(rawValue: 5)), "X509v6")
    }

    func testPrintingGeneralName() throws {
        let testDN = try DistinguishedName([
            RelativeDistinguishedName.Attribute(type: .RDNAttributeType.countryName, utf8String: "US"),
            RelativeDistinguishedName.Attribute(type: .RDNAttributeType.organizationName, utf8String: "DigiCert Inc"),
            RelativeDistinguishedName.Attribute(type: .RDNAttributeType.organizationalUnitName, utf8String: "www.digicert.com"),
            RelativeDistinguishedName.Attribute(type: .RDNAttributeType.commonName, utf8String: "DigiCert Global Root G3"),
        ])

        XCTAssertEqual(
            String(describing: GeneralName.dnsName("www.apple.com")),
            "dnsName: www.apple.com"
        )
        XCTAssertEqual(
            String(describing: GeneralName.directoryName(testDN)),
            "directoryName: CN=DigiCert Global Root G3,OU=www.digicert.com,O=DigiCert Inc,C=US"
        )
        XCTAssertEqual(
            try String(describing: GeneralName.ediPartyName(ASN1Any(erasing: ASN1Null()))),
            "ediPartyName: ASN1Any([5, 0])"
        )
        XCTAssertEqual(
            String(describing: GeneralName.ipAddress(ASN1OctetString(contentBytes: [127, 0, 0, 1]))),
            "ipAddress: [127, 0, 0, 1]"
        )
        XCTAssertEqual(
            String(describing: GeneralName.registeredID([1, 2, 3, 4, 5])),
            "registeredID: 1.2.3.4.5"
        )
        XCTAssertEqual(
            String(describing: GeneralName.rfc822Name("mail@example.com")),
            "rfc822Name: mail@example.com"
        )
        XCTAssertEqual(
            try String(describing: GeneralName.x400Address(ASN1Any(erasing: ASN1Null()))),
            "x400Address: ASN1Any([5, 0])"
        )
        XCTAssertEqual(
            String(describing: GeneralName.uniformResourceIdentifier("http://www.apple.com/")),
            "uri: http://www.apple.com/"
        )
    }

    func testPrintingAIAExtension() throws {
        let ext = AuthorityInformationAccess([
            .init(method: .issuingCA, location: .uniformResourceIdentifier("https://example.com/ca")),
            .init(method: .ocspServer, location: .uniformResourceIdentifier("http://example.com/ocsp")),
            .init(method: .init(.unknownType([1, 2, 3, 4])), location: .rfc822Name("mail@example.com")),
        ])
        let s = String(describing: ext)
        XCTAssertEqual(
            s,
            "Issuer: uri: https://example.com/ca, OCSP Server: uri: http://example.com/ocsp, 1.2.3.4: rfc822Name: mail@example.com"
        )
    }

    func testPrintingAKIExtension() throws {
        var ext = AuthorityKeyIdentifier(
            keyIdentifier: [10, 20, 30, 40],
            authorityCertIssuer: [.uniformResourceIdentifier("https://example.com/ca")],
            authorityCertSerialNumber: .init(bytes: [50, 60, 70, 80])
        )
        var s = String(describing: ext)
        XCTAssertEqual(
            s,
            "keyID: a:14:1e:28, issuer: [uri: https://example.com/ca], issuerSerial: 32:3c:46:50"
        )

        ext.keyIdentifier = nil
        s = String(describing: ext)
        XCTAssertEqual(
            s,
            "issuer: [uri: https://example.com/ca], issuerSerial: 32:3c:46:50"
        )

        ext.authorityCertSerialNumber = nil
        s = String(describing: ext)
        XCTAssertEqual(
            s,
            "issuer: [uri: https://example.com/ca]"
        )

        ext.authorityCertIssuer = nil
        s = String(describing: ext)
        XCTAssertEqual(
            s,
            ""
        )
    }

    func testPrintingSKIExtension() throws {
        let ext = SubjectKeyIdentifier(keyIdentifier: [10, 20, 30, 40])
        let s = String(describing: ext)
        XCTAssertEqual(s, "a:14:1e:28")
    }

    func testPrintingKeyUsageExtension() {
        var ext = KeyUsage()
        var s = String(describing: ext)
        XCTAssertEqual(s, "")

        ext.decipherOnly = true
        s = String(describing: ext)
        XCTAssertEqual(s, "decipherOnly")

        ext.encipherOnly = true
        s = String(describing: ext)
        XCTAssertEqual(s, "encipherOnly, decipherOnly")

        ext.digitalSignature = true
        s = String(describing: ext)
        XCTAssertEqual(s, "digitalSignature, encipherOnly, decipherOnly")

        ext.keyEncipherment = true
        s = String(describing: ext)
        XCTAssertEqual(s, "digitalSignature, keyEncipherment, encipherOnly, decipherOnly")

        ext.dataEncipherment = true
        s = String(describing: ext)
        XCTAssertEqual(
            s,
            "digitalSignature, keyEncipherment, dataEncipherment, encipherOnly, decipherOnly"
        )

        ext.nonRepudiation = true
        s = String(describing: ext)
        XCTAssertEqual(
            s,
            "digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment, encipherOnly, decipherOnly"
        )

        ext.cRLSign = true
        s = String(describing: ext)
        XCTAssertEqual(
            s,
            "digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment, cRLSign, encipherOnly, decipherOnly"
        )

        ext.keyAgreement = true
        s = String(describing: ext)
        XCTAssertEqual(
            s,
            "digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment, keyAgreement, cRLSign, encipherOnly, decipherOnly"
        )

        ext.keyCertSign = true
        s = String(describing: ext)
        XCTAssertEqual(
            s,
            "digitalSignature, nonRepudiation, keyEncipherment, dataEncipherment, keyAgreement, keyCertSign, cRLSign, encipherOnly, decipherOnly"
        )
    }

    func testPrintingSANFields() throws {
        // This is mostly redundant with general name, so we're only checking formatting.
        let san = SubjectAlternativeNames([
            .dnsName("example.com"),
            .dnsName("example.org"),
            .ipAddress(ASN1OctetString(contentBytes: [127, 0, 0, 1])),
        ])
        let s = String(describing: san)
        XCTAssertEqual(
            s,
            "dnsName: example.com, dnsName: example.org, ipAddress: [127, 0, 0, 1]"
        )
    }

    func testPrintingBasicConstraints() throws {
        var ext = BasicConstraints.notCertificateAuthority
        XCTAssertEqual(
            String(describing: ext),
            "CA=FALSE"
        )

        ext = .isCertificateAuthority(maxPathLength: nil)
        XCTAssertEqual(
            String(describing: ext),
            "CA=TRUE"
        )

        ext = .isCertificateAuthority(maxPathLength: 5)
        XCTAssertEqual(
            String(describing: ext),
            "CA=TRUE, maxPathLength=5"
        )
    }

    func testPrintingNameConstraints() throws {
        // This test is again mostly redundant with general name, so we're just testing the composition
        var ext = NameConstraints(
            permittedSubtrees: [.dnsName("example.com"), .uniformResourceIdentifier("http://example.com")],
            excludedSubtrees: [.dnsName("example.org"), .rfc822Name("mail@example.com")]
        )
        XCTAssertEqual(
            String(describing: ext),
            "permittedSubtrees: dnsName: example.com, uri: http://example.com; excludedSubtrees: dnsName: example.org, rfc822Name: mail@example.com"
        )

        ext.permittedSubtrees = []
        XCTAssertEqual(
            String(describing: ext),
            "excludedSubtrees: dnsName: example.org, rfc822Name: mail@example.com"
        )

        swap(&ext.permittedSubtrees, &ext.excludedSubtrees)
        XCTAssertEqual(
            String(describing: ext),
            "permittedSubtrees: dnsName: example.org, rfc822Name: mail@example.com"
        )
    }

    func testPrintingEKU() throws {
        let eku = ExtendedKeyUsage([
            .any,
            .certificateTransparency,
            .timeStamping,
            .ocspSigning,
            .init(oid: [1, 2, 3, 4]),
            .clientAuth,
            .serverAuth,
            .codeSigning,
            .emailProtection,
        ])
        XCTAssertEqual(
            String(describing: eku),
            "anyKeyUsage, certificateTransparency, timeStamping, ocspSigning, 1.2.3.4, clientAuth, serverAuth, codeSigning, emailProtection"
        )
    }
    
    func testSerialNumberRandomNumberGenerator() {
        struct StaticNumberGenerator: RandomNumberGenerator {
            var numbers: [UInt8]
            var nextIndex: Int = 0

            mutating func next() -> UInt64 {
                defer { nextIndex += 1}
                
                let startOffset = nextIndex * MemoryLayout<UInt64>.size
                precondition(numbers.indices.contains(startOffset), "static number generator is out of numbers")
                
                // assemble UInt64 from eight UInt8s
                var uint64 = UInt64()
                for byte in 0..<(MemoryLayout<UInt64>.size) {
                    let offset = startOffset + byte
                    guard numbers.indices.contains(offset) else {
                        continue
                    }
                    let number = UInt64(numbers[startOffset + byte])
                    let shifted = number << (byte * 8)
                    uint64 |= shifted
                }
                return uint64
            }
        }
        
        var rngWithLeadingZero = StaticNumberGenerator(numbers: [0, 1, 2, 3, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20])
        XCTAssertEqual(Certificate.SerialNumber(generator: &rngWithLeadingZero).bytes, [1, 2, 3, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20])
        
        var rngWithZeroAtTheSecondPosition = StaticNumberGenerator(numbers: [1, 0, 2, 3, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20])
        XCTAssertEqual(Certificate.SerialNumber(generator: &rngWithZeroAtTheSecondPosition).bytes, [1, 0, 2, 3, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20])
        
        var rngWithoutLeadingZero = StaticNumberGenerator(numbers: [1, 2, 3, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21])
        XCTAssertEqual(Certificate.SerialNumber(generator: &rngWithoutLeadingZero).bytes, [1, 2, 3, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21])
        
        var rngWithTrailingZero = StaticNumberGenerator(numbers: [1, 2, 3, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0])
        XCTAssertEqual(Certificate.SerialNumber(generator: &rngWithTrailingZero).bytes, [1, 2, 3, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0])
    }
}
