//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCertificate open source project
//
// Copyright (c) 2022 Apple Inc. and the SwiftCertificate project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.md for the list of SwiftCertificate project authors
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
        XCTAssertEqual(String(describing: Certificate.Version(rawValue: 5)), "X509v4")
    }

    func testPrintingGeneralName() throws {
        let testDN = try DistinguishedName([
            RelativeDistinguishedName.Attribute(type: .RDNAttributeType.countryName, utf8String: "US"),
            RelativeDistinguishedName.Attribute(type: .RDNAttributeType.organizationName, utf8String: "DigiCert Inc"),
            RelativeDistinguishedName.Attribute(type: .RDNAttributeType.organizationalUnitName, utf8String: "www.digicert.com"),
            RelativeDistinguishedName.Attribute(type: .RDNAttributeType.commonName, utf8String: "DigiCert Global Root G3"),
        ])

        XCTAssertEqual(
            String(describing: GeneralName.dNSName("www.apple.com")),
            "dNSName: www.apple.com"
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
            String(describing: GeneralName.iPAddress(ASN1OctetString(contentBytes: [127, 0, 0, 1]))),
            "iPAddress: [127, 0, 0, 1]"
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
        let ext = Certificate.Extensions.AuthorityInformationAccess([
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
        var ext = Certificate.Extensions.AuthorityKeyIdentifier(
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
        let ext = Certificate.Extensions.SubjectKeyIdentifier(keyIdentifier: [10, 20, 30, 40])
        let s = String(describing: ext)
        XCTAssertEqual(s, "a:14:1e:28")
    }

    func testPrintingKeyUsageExtension() {
        var ext = Certificate.Extensions.KeyUsage()
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
        let san = Certificate.Extensions.SubjectAlternativeNames([
            .dNSName("example.com"),
            .dNSName("example.org"),
            .iPAddress(ASN1OctetString(contentBytes: [127, 0, 0, 1])),
        ])
        let s = String(describing: san)
        XCTAssertEqual(
            s,
            "dNSName: example.com, dNSName: example.org, iPAddress: [127, 0, 0, 1]"
        )
    }

    func testPrintingBasicConstraints() throws {
        var ext = Certificate.Extensions.BasicConstraints.notCertificateAuthority
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
        var ext = Certificate.Extensions.NameConstraints(
            permittedSubtrees: [.dNSName("example.com"), .uniformResourceIdentifier("http://example.com")],
            excludedSubtrees: [.dNSName("example.org"), .rfc822Name("mail@example.com")]
        )
        XCTAssertEqual(
            String(describing: ext),
            "permittedSubtrees: dNSName: example.com, uri: http://example.com; excludedSubtrees: dNSName: example.org, rfc822Name: mail@example.com"
        )

        ext.permittedSubtrees = []
        XCTAssertEqual(
            String(describing: ext),
            "excludedSubtrees: dNSName: example.org, rfc822Name: mail@example.com"
        )

        swap(&ext.permittedSubtrees, &ext.excludedSubtrees)
        XCTAssertEqual(
            String(describing: ext),
            "permittedSubtrees: dNSName: example.org, rfc822Name: mail@example.com"
        )
    }

    func testPrintingEKU() throws {
        let eku = Certificate.Extensions.ExtendedKeyUsage([
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
}
