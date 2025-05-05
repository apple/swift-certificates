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
import Crypto
import _CryptoExtras
import SwiftASN1
@testable import X509

final class CertificateTests: XCTestCase {
    func testPrintingSerial() {
        let serial = Certificate.SerialNumber(bytes: [10, 20, 30, 40])
        let s = String(describing: serial)
        XCTAssertEqual(s, "a:14:1e:28")
    }

    @available(macOS 13.3, iOS 16.4, watchOS 9.4, tvOS 16.4, macCatalyst 16.4, visionOS 1.0, *)
    func testSerialNumberStaticBigInt() {
        XCTAssertEqual(
            (0b0000_0001__0000_0010__0000_0011__0000_0100__0000_0101__0000_0110__0000_0111__0000_1000__0000_1001__0000_1010__0000_1011__0000_1100__0000_1101__0000_1110
                as Certificate.SerialNumber).bytes,
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14]
        )

        XCTAssertEqual(
            (0x00_01_02_03_04_05_06_07_08_09_0A_0B_0C_0D_0E_0F_10_11_12_13_14 as Certificate.SerialNumber).bytes,
            [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]
        )
        XCTAssertEqual(Certificate.SerialNumber(123_456_789), 123_456_789)
    }

    func testSerialNumberInits() {
        XCTAssertEqual(Certificate.SerialNumber(bytes: [0, 1, 2, 3, 4, 5, 6, 7, 8]).bytes, [1, 2, 3, 4, 5, 6, 7, 8])
        XCTAssertEqual(
            Certificate.SerialNumber(bytes: [0, 1, 2, 3, 4, 5, 6, 7, 8][...]).bytes,
            [1, 2, 3, 4, 5, 6, 7, 8]
        )
        XCTAssertEqual(
            Certificate.SerialNumber(bytes: AnyCollection([0, 1, 2, 3, 4, 5, 6, 7, 8])).bytes,
            [1, 2, 3, 4, 5, 6, 7, 8]
        )
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
            RelativeDistinguishedName.Attribute(
                type: .RDNAttributeType.organizationalUnitName,
                utf8String: "www.digicert.com"
            ),
            RelativeDistinguishedName.Attribute(
                type: .RDNAttributeType.commonName,
                utf8String: "DigiCert Global Root G3"
            ),
        ])

        XCTAssertEqual(
            String(describing: GeneralName.dnsName("www.apple.com")),
            "DNSName(\"www.apple.com\")"
        )
        XCTAssertEqual(
            String(describing: GeneralName.directoryName(testDN)),
            #"DirectoryName("CN=DigiCert Global Root G3,OU=www.digicert.com,O=DigiCert Inc,C=US")"#
        )
        XCTAssertEqual(
            try String(describing: GeneralName.ediPartyName(ASN1Any(erasing: ASN1Null()))),
            "EDIPartyName(ASN1Any([5, 0]))"
        )
        XCTAssertEqual(
            String(describing: GeneralName.ipAddress(ASN1OctetString(contentBytes: [127, 0, 0, 1]))),
            "IPAddress([127, 0, 0, 1])"
        )
        XCTAssertEqual(
            String(describing: GeneralName.registeredID([1, 2, 3, 4, 5])),
            "RegisteredID(1.2.3.4.5)"
        )
        XCTAssertEqual(
            String(describing: GeneralName.rfc822Name("mail@example.com")),
            "RFC822Name(\"mail@example.com\")"
        )
        XCTAssertEqual(
            try String(describing: GeneralName.x400Address(ASN1Any(erasing: ASN1Null()))),
            "X400Address(ASN1Any([5, 0]))"
        )
        XCTAssertEqual(
            String(describing: GeneralName.uniformResourceIdentifier("http://www.apple.com/")),
            "URI(\"http://www.apple.com/\")"
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
            "(Issuer: URI(\"https://example.com/ca\")), (OCSP Server: URI(\"http://example.com/ocsp\")), (1.2.3.4: RFC822Name(\"mail@example.com\"))"
        )
    }

    func testRangeReplaceableCollectionConformance() throws {
        var ext = AuthorityInformationAccess([
            .init(method: .issuingCA, location: .uniformResourceIdentifier("https://example.com/ca")),
            .init(method: .ocspServer, location: .uniformResourceIdentifier("http://example.com/ocsp")),
            .init(method: .init(.unknownType([1, 2, 3, 4])), location: .rfc822Name("mail@example.com")),
        ])

        ext.replaceSubrange(
            1..<2,
            with: [
                .init(method: .ocspServer, location: .uniformResourceIdentifier("http://example.com/ocsp/a")),
                .init(method: .ocspServer, location: .uniformResourceIdentifier("http://example.com/ocsp/b")),
            ]
        )

        XCTAssertEqual(
            Array(ext),
            [
                .init(method: .issuingCA, location: .uniformResourceIdentifier("https://example.com/ca")),
                .init(method: .ocspServer, location: .uniformResourceIdentifier("http://example.com/ocsp/a")),
                .init(method: .ocspServer, location: .uniformResourceIdentifier("http://example.com/ocsp/b")),
                .init(method: .init(.unknownType([1, 2, 3, 4])), location: .rfc822Name("mail@example.com")),
            ]
        )

        func conformsToRangeReplaceableCollection(_ value: some Any) -> Bool {
            value is any RangeReplaceableCollection
        }
        // writing out `ext is any RangeReplaceableCollection` will produce a warning that this is always true
        // therefore we go through this indirection to silence this warning
        XCTAssertTrue(conformsToRangeReplaceableCollection(ext))
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
            "keyID: a:14:1e:28, issuer: [URI(\"https://example.com/ca\")], issuerSerial: 32:3c:46:50"
        )

        ext.keyIdentifier = nil
        s = String(describing: ext)
        XCTAssertEqual(
            s,
            "issuer: [URI(\"https://example.com/ca\")], issuerSerial: 32:3c:46:50"
        )

        ext.authorityCertSerialNumber = nil
        s = String(describing: ext)
        XCTAssertEqual(
            s,
            "issuer: [URI(\"https://example.com/ca\")]"
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
            "DNSName(\"example.com\"), DNSName(\"example.org\"), IPAddress([127, 0, 0, 1])"
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
            "permittedSubtrees: [DNSName(\"example.com\"), URI(\"http://example.com\")], excludedSubtrees: [DNSName(\"example.org\"), RFC822Name(\"mail@example.com\")]"
        )

        ext.permittedSubtrees = []
        XCTAssertEqual(
            String(describing: ext),
            "excludedSubtrees: [DNSName(\"example.org\"), RFC822Name(\"mail@example.com\")]"
        )

        swap(&ext.permittedSubtrees, &ext.excludedSubtrees)
        XCTAssertEqual(
            String(describing: ext),
            "permittedSubtrees: [DNSName(\"example.org\"), RFC822Name(\"mail@example.com\")]"
        )
    }

    func testPrintingEKU() throws {
        let eku = try ExtendedKeyUsage([
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
                defer { nextIndex += 1 }

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

        var rngWithLeadingZero = StaticNumberGenerator(numbers: [
            0, 1, 2, 3, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        ])
        XCTAssertEqual(
            Certificate.SerialNumber(generator: &rngWithLeadingZero).bytes,
            [1, 2, 3, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]
        )

        var rngWithZeroAtTheSecondPosition = StaticNumberGenerator(numbers: [
            1, 0, 2, 3, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20,
        ])
        XCTAssertEqual(
            Certificate.SerialNumber(generator: &rngWithZeroAtTheSecondPosition).bytes,
            [1, 0, 2, 3, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20]
        )

        var rngWithoutLeadingZero = StaticNumberGenerator(numbers: [
            1, 2, 3, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21,
        ])
        XCTAssertEqual(
            Certificate.SerialNumber(generator: &rngWithoutLeadingZero).bytes,
            [1, 2, 3, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21]
        )

        var rngWithTrailingZero = StaticNumberGenerator(numbers: [
            1, 2, 3, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0,
        ])
        XCTAssertEqual(
            Certificate.SerialNumber(generator: &rngWithTrailingZero).bytes,
            [1, 2, 3, 4, 5, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 0]
        )
    }

    func testRoundTrippingKeys() throws {
        let p256 = P256.Signing.PrivateKey()
        let p384 = P384.Signing.PrivateKey()
        let p521 = P521.Signing.PrivateKey()
        let rsa = try _RSA.Signing.PrivateKey(keySize: .bits2048)

        XCTAssertEqual(
            p256.publicKey.rawRepresentation,
            P256.Signing.PublicKey(Certificate.PublicKey(p256.publicKey))?.rawRepresentation
        )
        XCTAssertEqual(
            p384.publicKey.rawRepresentation,
            P384.Signing.PublicKey(Certificate.PublicKey(p384.publicKey))?.rawRepresentation
        )
        XCTAssertEqual(
            p521.publicKey.rawRepresentation,
            P521.Signing.PublicKey(Certificate.PublicKey(p521.publicKey))?.rawRepresentation
        )
        XCTAssertEqual(
            rsa.publicKey.derRepresentation,
            _RSA.Signing.PublicKey(Certificate.PublicKey(rsa.publicKey))?.derRepresentation
        )

        // Don't project to other things
        XCTAssertNil(
            P256.Signing.PublicKey(Certificate.PublicKey(p384.publicKey))
        )
        XCTAssertNil(
            P256.Signing.PublicKey(Certificate.PublicKey(p521.publicKey))
        )
        XCTAssertNil(
            P256.Signing.PublicKey(Certificate.PublicKey(rsa.publicKey))
        )
        XCTAssertNil(
            P384.Signing.PublicKey(Certificate.PublicKey(p256.publicKey))
        )
        XCTAssertNil(
            P384.Signing.PublicKey(Certificate.PublicKey(p521.publicKey))
        )
        XCTAssertNil(
            P384.Signing.PublicKey(Certificate.PublicKey(rsa.publicKey))
        )
        XCTAssertNil(
            P521.Signing.PublicKey(Certificate.PublicKey(p256.publicKey))
        )
        XCTAssertNil(
            P521.Signing.PublicKey(Certificate.PublicKey(p384.publicKey))
        )
        XCTAssertNil(
            P521.Signing.PublicKey(Certificate.PublicKey(rsa.publicKey))
        )
        XCTAssertNil(
            _RSA.Signing.PublicKey(Certificate.PublicKey(p256.publicKey))
        )
        XCTAssertNil(
            _RSA.Signing.PublicKey(Certificate.PublicKey(p384.publicKey))
        )
        XCTAssertNil(
            _RSA.Signing.PublicKey(Certificate.PublicKey(p521.publicKey))
        )
    }

    func testPublicKeysExposeSubjectPublicKeyInfoBytes() throws {
        let p256 = P256.Signing.PrivateKey()
        let p384 = P384.Signing.PrivateKey()
        let p521 = P521.Signing.PrivateKey()
        let rsa = try _RSA.Signing.PrivateKey(keySize: .bits2048)

        XCTAssertEqual(
            p256.publicKey.x963Representation,
            Data(Certificate.PublicKey(p256.publicKey).subjectPublicKeyInfoBytes)
        )
        XCTAssertEqual(
            p384.publicKey.x963Representation,
            Data(Certificate.PublicKey(p384.publicKey).subjectPublicKeyInfoBytes)
        )
        XCTAssertEqual(
            p521.publicKey.x963Representation,
            Data(Certificate.PublicKey(p521.publicKey).subjectPublicKeyInfoBytes)
        )
        XCTAssertEqual(
            rsa.publicKey.pkcs1DERRepresentation,
            Data(Certificate.PublicKey(rsa.publicKey).subjectPublicKeyInfoBytes)
        )
    }

    private static let referenceTime = Date(timeIntervalSince1970: 1_691_504_774)

    @available(macOS 11.0, iOS 14, tvOS 14, watchOS 7, macCatalyst 14, visionOS 1.0, *)
    func testCertificateDescription() throws {
        let caPrivateKey = P384.Signing.PrivateKey()
        let certificateName1 = try! DistinguishedName {
            CountryName("US")
            OrganizationName("Apple")
            CommonName("Swift Certificate Test CA 1")
        }
        let caNotValidBefore = Self.referenceTime - .days(365)
        let caNotValidAfter = Self.referenceTime + .days(3650)

        let ca = try Certificate(
            version: .v3,
            serialNumber: .init(bytes: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10]),
            publicKey: .init(caPrivateKey.publicKey),
            notValidBefore: caNotValidBefore,
            notValidAfter: caNotValidAfter,
            issuer: certificateName1,
            subject: certificateName1,
            signatureAlgorithm: .ecdsaWithSHA384,
            extensions: Certificate.Extensions {
                Critical(
                    BasicConstraints.isCertificateAuthority(maxPathLength: nil)
                )
                KeyUsage(keyCertSign: true)
                SubjectKeyIdentifier(
                    keyIdentifier: ArraySlice(Insecure.SHA1.hash(data: caPrivateKey.publicKey.derRepresentation))
                )
            },
            issuerPrivateKey: .init(caPrivateKey)
        )

        XCTAssertEqual(
            String(describing: ca),
            """
            Certificate(\
            version: X509v3, \
            serialNumber: 1:2:3:4:5:6:7:8:9:a, \
            issuer: "CN=Swift Certificate Test CA 1,O=Apple,C=US", \
            subject: "CN=Swift Certificate Test CA 1,O=Apple,C=US", \
            notValidBefore: \(String(reflecting: caNotValidBefore)), \
            notValidAfter: \(String(reflecting: caNotValidAfter)), \
            publicKey: P384.PublicKey, \
            signature: ECDSA, \
            extensions: [\
            BasicConstraints(CA=TRUE), \
            KeyUsage(keyCertSign), \
            SubjectKeyIdentifier(\(try ca.extensions.subjectKeyIdentifier!.keyIdentifier.map { String($0, radix: 16) }.joined(separator: ":")))\
            ]\
            )
            """
        )

        let intermediatePrivateKey = P256.Signing.PrivateKey()
        let intermediateName = try! DistinguishedName {
            CountryName("US")
            OrganizationName("Apple")
            CommonName("Swift Certificate Test Intermediate CA 1")
        }
        let intermediateNotValidBefore = Self.referenceTime - .days(365)
        let intermediateNotValidAfter = Self.referenceTime + .days(5 * 365)

        let intermediate: Certificate = {
            return try! Certificate(
                version: .v3,
                serialNumber: .init(bytes: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11]),
                publicKey: .init(intermediatePrivateKey.publicKey),
                notValidBefore: intermediateNotValidBefore,
                notValidAfter: intermediateNotValidAfter,
                issuer: ca.subject,
                subject: intermediateName,
                signatureAlgorithm: .ecdsaWithSHA384,
                extensions: Certificate.Extensions {
                    Critical(
                        BasicConstraints.isCertificateAuthority(maxPathLength: 1)
                    )
                    KeyUsage(keyCertSign: true)
                    AuthorityKeyIdentifier(keyIdentifier: try! ca.extensions.subjectKeyIdentifier!.keyIdentifier)
                    SubjectKeyIdentifier(
                        keyIdentifier: ArraySlice(
                            Insecure.SHA1.hash(data: intermediatePrivateKey.publicKey.derRepresentation)
                        )
                    )
                    NameConstraints(
                        permittedDNSDomains: ["apple.com."],
                        excludedDNSDomains: ["www.apple.com."],
                        permittedIPRanges: [.v4(subnet: "127.0.0.0", mask: "0.0.0.255")],
                        excludedIPRanges: [.v4("127.0.0.1")],
                        permittedEmailAddresses: ["foo@exmaple.com.", "bar@example.com."],
                        excludedEmailAddresses: ["bar@example.com."],
                        permittedURIDomains: [".example.com"],
                        forbiddenURIDomains: [".foo.example.com"]
                    )
                },
                issuerPrivateKey: .init(caPrivateKey)
            )
        }()

        XCTAssertEqual(
            String(describing: intermediate),
            """
            Certificate(\
            version: X509v3, \
            serialNumber: 1:2:3:4:5:6:7:8:9:a:b, \
            issuer: "CN=Swift Certificate Test CA 1,O=Apple,C=US", \
            subject: "CN=Swift Certificate Test Intermediate CA 1,O=Apple,C=US", \
            notValidBefore: \(String(reflecting: intermediateNotValidBefore)), \
            notValidAfter: \(String(reflecting: intermediateNotValidAfter)), \
            publicKey: P256.PublicKey, \
            signature: ECDSA, \
            extensions: [\
            BasicConstraints(CA=TRUE, maxPathLength=1), \
            KeyUsage(keyCertSign), \
            AuthorityKeyIdentifier(keyID: \(try intermediate.extensions.authorityKeyIdentifier!.keyIdentifier!.map { String($0, radix: 16) }.joined(separator: ":"))), \
            SubjectKeyIdentifier(\(try intermediate.extensions.subjectKeyIdentifier!.keyIdentifier.map { String($0, radix: 16) }.joined(separator: ":"))), \
            NameConstraints(\
            permittedSubtrees: [DNSName("apple.com."), IPAddress([127, 0, 0, 0, 0, 0, 0, 255]), RFC822Name("foo@exmaple.com."), RFC822Name("bar@example.com."), URI(".example.com")], \
            excludedSubtrees: [DNSName("www.apple.com."), IPAddress([127, 0, 0, 1]), RFC822Name("bar@example.com."), URI(".foo.example.com")]\
            )\
            ])
            """
        )

        let localhostPrivateKey = P256.Signing.PrivateKey()
        let leafNotValidBefore = Self.referenceTime - .days(365)
        let leafNotValidAfter = Self.referenceTime + .days(365)

        let leaf = try Certificate(
            version: .v3,
            serialNumber: .init(bytes: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]),
            publicKey: .init(localhostPrivateKey.publicKey),
            notValidBefore: leafNotValidBefore,
            notValidAfter: leafNotValidAfter,
            issuer: intermediateName,
            subject: try DistinguishedName {
                CountryName("US")
                OrganizationName("Apple")
                CommonName("localhost")
                StreetAddress("Infinite Loop")
            },
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: Certificate.Extensions {
                Critical(
                    BasicConstraints.notCertificateAuthority
                )
                KeyUsage(keyCertSign: true)
                AuthorityKeyIdentifier(keyIdentifier: try! intermediate.extensions.subjectKeyIdentifier!.keyIdentifier)
            },
            issuerPrivateKey: .init(localhostPrivateKey)
        )

        XCTAssertEqual(
            String(describing: leaf),
            """
            Certificate(\
            version: X509v3, \
            serialNumber: 1:2:3:4:5:6:7:8:9:a:b:c, \
            issuer: "CN=Swift Certificate Test Intermediate CA 1,O=Apple,C=US", \
            subject: "STREET=Infinite Loop,CN=localhost,O=Apple,C=US", \
            notValidBefore: \(String(reflecting: leafNotValidBefore)), \
            notValidAfter: \(String(reflecting: leafNotValidAfter)), \
            publicKey: P256.PublicKey, \
            signature: ECDSA, \
            extensions: [\
            BasicConstraints(CA=FALSE), \
            KeyUsage(keyCertSign), \
            AuthorityKeyIdentifier(keyID: \(try leaf.extensions.authorityKeyIdentifier!.keyIdentifier!.map { String($0, radix: 16) }.joined(separator: ":")))\
            ]\
            )
            """
        )
        print(intermediate)
    }

    func testAKISerialization() throws {
        let t = GeneralName.directoryName(
            try DistinguishedName {
                CommonName("CA")
                OrganizationName("Some Org")
                CountryName("Some Country")
            }
        )
        let aki = AuthorityKeyIdentifierValue(AuthorityKeyIdentifier(authorityCertIssuer: [t]))
        var serializer = DER.Serializer()
        try serializer.serialize(aki)
        let bytes = serializer.serializedBytes

        let decoded = try AuthorityKeyIdentifierValue(derEncoded: bytes)
        XCTAssertEqual(decoded.authorityCertIssuer, aki.authorityCertIssuer)

        XCTAssertEqual(
            bytes,
            [
                0x30, 0x3d,  // SEQUENCE, length 61 bytes
                0xa1, 0x3b,  // [1], length 59 bytes
                0xa4, 0x39,  // [4], length 57 bytes
                0x30, 0x37,  // SEQUENCE, length 55 bytes
                0x31, 0xb,  // SET, length 11 bytes
                0x30, 0x9,  // SEQUENCE, length 9 bytes
                0x6, 0x3, 0x55, 0x4, 0x3,  // OID, common name
                0xc, 0x2, 0x43, 0x41,  // UTF-8 string, "CA"
                0x31, 0x11,  // SET, length 17 bytes
                0x30, 0xf,  // SEQUENCE, length 15 bytes
                0x6, 0x3, 0x55, 0x4, 0xa,  // OID, organizationName
                0xc, 0x8, 0x53, 0x6f, 0x6d, 0x65, 0x20, 0x4f, 0x72, 0x67,  // UTF-8 string, "Some Org"
                0x31, 0x15,  // SET, length 21 bytes
                0x30, 0x13,  // SEQUENCE, length 19 bytes
                0x6, 0x3, 0x55, 0x4, 0x6,  // OID, countryName
                0x13, 0xc, 0x53, 0x6f, 0x6d, 0x65, 0x20, 0x43, 0x6f, 0x75, 0x6e, 0x74, 0x72, 0x79,
                // Printable string, "Some Country"
            ]
        )
    }

    func testRFC8410Ed25519PublicKey() throws {
        let pemKey = """
            -----BEGIN PUBLIC KEY-----
            MCowBQYDK2VwAyEAGb9ECWmEzf6FQbrBZ9w7lshQhqowtrbLDFw4rXAxZuE=
            -----END PUBLIC KEY-----
            """
        let resultingKey = try Certificate.PublicKey(pemEncoded: pemKey)
        let unwrappedKey = Curve25519.Signing.PublicKey(resultingKey)
        let reWrappedKey = Certificate.PublicKey(unwrappedKey!)
        XCTAssertEqual(reWrappedKey, resultingKey)
        XCTAssertEqual(try reWrappedKey.serializeAsPEM().pemString, pemKey)
    }

    @available(macOS 11.0, iOS 14, tvOS 14, watchOS 7, macCatalyst 14, visionOS 1.0, *)
    func testRFC8410Ed25519PrivateKey() throws {
        let pemKey = """
            -----BEGIN PRIVATE KEY-----
            MC4CAQAwBQYDK2VwBCIEINTuctv5E1hK1bbY8fdp+K06/nwoy/HU++CXqI9EdVhC
            -----END PRIVATE KEY-----
            """
        let resultingKey = try Certificate.PrivateKey(pemEncoded: pemKey)
        XCTAssertEqual(try resultingKey.serializeAsPEM().pemString, pemKey)
    }

    func testExampleEd25519SelfIssuedSelfSignedCert() throws {
        let cert = """
            -----BEGIN CERTIFICATE-----
            MIIBCDCBuwIUGW78zw0OL0GptJi++a91dBa7DsQwBQYDK2VwMCcxCzAJBgNVBAYT
            AkRFMRgwFgYDVQQDDA93d3cuZXhhbXBsZS5jb20wHhcNMTkwMzMxMTc1MTIyWhcN
            MjEwMjI4MTc1MTIyWjAnMQswCQYDVQQGEwJERTEYMBYGA1UEAwwPd3d3LmV4YW1w
            bGUuY29tMCowBQYDK2VwAyEAK87g0b8CC1eA5mvKXt9uezZwJYWEyg74Y0xTZEkq
            CcwwBQYDK2VwA0EAIIu/aa3Qtr3IE5to/nvWVY9y3ciwG5DnA70X3ALUhFs+U5aL
            tfY8sNT1Ng72ht+UBwByuze20UsL9qMsmknQCA==
            -----END CERTIFICATE-----
            """
        let parsedCert = try Certificate(pemEncoded: cert)
        XCTAssertTrue(parsedCert.publicKey.isValidSignature(parsedCert.signature, for: parsedCert))
        XCTAssertNotNil(Curve25519.Signing.PublicKey(parsedCert.publicKey))

        let reEncoded = try parsedCert.serializeAsPEM().pemString
        XCTAssertEqual(cert, reEncoded)
    }

    func testDefaultRSASignatureAlgorithm() throws {
        let privateKey = try Certificate.PrivateKey(_RSA.Signing.PrivateKey(keySize: .bits2048))
        let certificate = try self.issueSelfSignedCertificate(privateKey: privateKey)
        XCTAssertEqual(certificate.signatureAlgorithm.description, "SignatureAlgorithm.sha256WithRSAEncryption")
    }

    func testDefaultP256SignatureAlgorithm() throws {
        let privateKey = Certificate.PrivateKey(P256.Signing.PrivateKey())
        let certificate = try self.issueSelfSignedCertificate(privateKey: privateKey)
        XCTAssertEqual(certificate.signatureAlgorithm.description, "SignatureAlgorithm.ecdsaWithSHA256")
    }

    func testDefaultP384SignatureAlgorithm() throws {
        let privateKey = Certificate.PrivateKey(P384.Signing.PrivateKey())
        let certificate = try self.issueSelfSignedCertificate(privateKey: privateKey)
        XCTAssertEqual(certificate.signatureAlgorithm.description, "SignatureAlgorithm.ecdsaWithSHA384")
    }

    func testDefaultP521SignatureAlgorithm() throws {
        let privateKey = Certificate.PrivateKey(P521.Signing.PrivateKey())
        let certificate = try self.issueSelfSignedCertificate(privateKey: privateKey)
        XCTAssertEqual(certificate.signatureAlgorithm.description, "SignatureAlgorithm.ecdsaWithSHA512")
    }

    func testDefaultEd25519SignatureAlgorithm() throws {
        let privateKey = Certificate.PrivateKey(Curve25519.Signing.PrivateKey())
        let certificate = try self.issueSelfSignedCertificate(privateKey: privateKey)
        XCTAssertEqual(certificate.signatureAlgorithm.description, "SignatureAlgorithm.ed25519")
    }

    private func issueSelfSignedCertificate(privateKey: Certificate.PrivateKey) throws -> Certificate {
        let name = try DistinguishedName { CommonName("test") }
        return try Certificate(
            version: .v3,
            serialNumber: .init(bytes: [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12]),
            publicKey: privateKey.publicKey,
            notValidBefore: Date(),
            notValidAfter: Date() + 3600,
            issuer: name,
            subject: name,
            extensions: Certificate.Extensions {},
            issuerPrivateKey: privateKey
        )
    }
}
