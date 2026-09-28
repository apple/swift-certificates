//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCertificates open source project
//
// Copyright (c) 2025 Apple Inc. and the SwiftCertificates project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCertificates project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import XCTest
import Crypto
import _CryptoExtras
import SwiftASN1
@testable @_spi(CMS) import X509

final class CMSTests: XCTestCase {
    static let rootCertKey = Certificate.PrivateKey(P256.Signing.PrivateKey())
    static let rootCertName = try! DistinguishedName {
        CommonName("CMS Root CA")
    }
    static let rootCert = try! Certificate(
        version: .v3,
        serialNumber: .init(),
        publicKey: rootCertKey.publicKey,
        notValidBefore: Date(),
        notValidAfter: Date().advanced(by: 60 * 60 * 24 * 360),
        issuer: rootCertName,
        subject: rootCertName,
        signatureAlgorithm: .ecdsaWithSHA256,
        extensions: try! Certificate.Extensions {
            Critical(
                BasicConstraints.isCertificateAuthority(maxPathLength: nil)
            )
        },
        issuerPrivateKey: rootCertKey
    )

    static let leaf1Key = Certificate.PrivateKey(P256.Signing.PrivateKey())
    static let leaf1Name = try! DistinguishedName {
        CommonName("CMS Leaf 1")
    }
    static let leaf1Cert = try! Certificate(
        version: .v3,
        serialNumber: .init(),
        publicKey: leaf1Key.publicKey,
        notValidBefore: Date(),
        notValidAfter: Date().advanced(by: 60 * 60 * 24 * 360),
        issuer: rootCertName,
        subject: leaf1Name,
        signatureAlgorithm: .ecdsaWithSHA256,
        extensions: try! Certificate.Extensions {
            Critical(
                BasicConstraints.notCertificateAuthority
            )
            // This can be any random thing.
            SubjectKeyIdentifier(keyIdentifier: [1, 2, 3, 4, 5])
        },
        issuerPrivateKey: rootCertKey
    )

    static let secondRootKey = Certificate.PrivateKey(P256.Signing.PrivateKey())
    static let secondRootName = try! DistinguishedName {
        CommonName("CMS Root CA 2")
    }
    static let secondRootCert = try! Certificate(
        version: .v3,
        serialNumber: .init(),
        publicKey: secondRootKey.publicKey,
        notValidBefore: Date(),
        notValidAfter: Date().advanced(by: 60 * 60 * 24 * 360),
        issuer: secondRootName,
        subject: secondRootName,
        signatureAlgorithm: .ecdsaWithSHA256,
        extensions: try! Certificate.Extensions {
            Critical(
                BasicConstraints.isCertificateAuthority(maxPathLength: nil)
            )
        },
        issuerPrivateKey: secondRootKey
    )

    static let intermediateKey = Certificate.PrivateKey(P256.Signing.PrivateKey())
    static let intermediateName = try! DistinguishedName {
        CommonName("CMS Intermediate CA 1")
    }
    static let intermediateCert = try! Certificate(
        version: .v3,
        serialNumber: .init(),
        publicKey: intermediateKey.publicKey,
        notValidBefore: Date(),
        notValidAfter: Date().advanced(by: 60 * 60 * 24 * 360),
        issuer: rootCertName,
        subject: intermediateName,
        signatureAlgorithm: .ecdsaWithSHA256,
        extensions: try! Certificate.Extensions {
            Critical(
                BasicConstraints.isCertificateAuthority(maxPathLength: nil)
            )
        },
        issuerPrivateKey: rootCertKey
    )

    static let leaf2Key = Certificate.PrivateKey(P256.Signing.PrivateKey())
    static let leaf2Name = try! DistinguishedName {
        CommonName("CMS Leaf 2")
    }
    static let leaf2Cert = try! Certificate(
        version: .v3,
        serialNumber: .init(),
        publicKey: leaf2Key.publicKey,
        notValidBefore: Date(),
        notValidAfter: Date().advanced(by: 60 * 60 * 24 * 360),
        issuer: intermediateName,
        subject: leaf2Name,
        signatureAlgorithm: .ecdsaWithSHA256,
        extensions: try! Certificate.Extensions {
            Critical(
                BasicConstraints.notCertificateAuthority
            )
            // This can be any random thing.
            SubjectKeyIdentifier(keyIdentifier: [1, 2, 3, 4, 5])
        },
        issuerPrivateKey: intermediateKey
    )

    static let rsaCertKey = try! Certificate.PrivateKey(_RSA.Signing.PrivateKey(keySize: .bits2048))
    static let rsaCertName = try! DistinguishedName {
        CommonName("CMS RSA")
    }
    static let rsaCert = try! Certificate(
        version: .v3,
        serialNumber: .init(),
        publicKey: rsaCertKey.publicKey,
        notValidBefore: Date(),
        notValidAfter: Date().advanced(by: 60 * 60 * 24 * 360),
        issuer: rsaCertName,
        subject: rsaCertName,
        signatureAlgorithm: .sha256WithRSAEncryption,
        extensions: try! Certificate.Extensions {
            Critical(
                BasicConstraints.isCertificateAuthority(maxPathLength: nil)
            )
        },
        issuerPrivateKey: rsaCertKey
    )

    static let rsaCert2Key = try! Certificate.PrivateKey(_RSA.Signing.PrivateKey(keySize: .bits2048))
    static let rsaCert2Name = try! DistinguishedName {
        CommonName("CMS RSA 2")
    }
    static let rsaCert2 = try! Certificate(
        version: .v3,
        serialNumber: .init(),
        publicKey: rsaCert2Key.publicKey,
        notValidBefore: Date(),
        notValidAfter: Date().advanced(by: 60 * 60 * 24 * 360),
        issuer: rsaCert2Name,
        subject: rsaCert2Name,
        signatureAlgorithm: .sha256WithRSAEncryption,
        extensions: try! Certificate.Extensions {
            Critical(
                BasicConstraints.isCertificateAuthority(maxPathLength: nil)
            )
        },
        issuerPrivateKey: rsaCert2Key
    )

    static let ed25519CertKey = Certificate.PrivateKey(Curve25519.Signing.PrivateKey())
    static let ed25519CertName = try! DistinguishedName {
        CommonName("CMS ED25519")
    }
    static let ed25519Cert = try! Certificate(
        version: .v3,
        serialNumber: .init(),
        publicKey: ed25519CertKey.publicKey,
        notValidBefore: Date(),
        notValidAfter: Date().advanced(by: 60 * 60 * 24 * 360),
        issuer: ed25519CertName,
        subject: ed25519CertName,
        signatureAlgorithm: .ed25519,
        extensions: try! Certificate.Extensions {
            Critical(
                BasicConstraints.isCertificateAuthority(maxPathLength: nil)
            )
        },
        issuerPrivateKey: ed25519CertKey
    )

    @PolicyBuilder static var defaultPolicies: some VerifierPolicy {
        RFC5280Policy()
    }


    private func assertRoundTrips<ASN1Object: DERParseable & DERSerializable & Equatable>(_ value: ASN1Object) throws {
        var serializer = DER.Serializer()
        try serializer.serialize(value)
        let parsed = try ASN1Object(derEncoded: serializer.serializedBytes)
        XCTAssertEqual(parsed, value)
    }

    private func envelopedData(from bytes: [UInt8]) throws -> CMSEnvelopedData {
        let contentInfo = try CMSContentInfo(berEncoded: ArraySlice(bytes))
        return try XCTUnwrap(try contentInfo.envelopedData)
    }

    func testIssuerAndSerialNumber() throws {
        try assertRoundTrips(
            CMSIssuerAndSerialNumber(
                issuer: .init {
                    CountryName("US")
                    OrganizationName("Apple Inc.")
                    CommonName("Apple Public EV Server ECC CA 1 - G1")
                },
                serialNumber: .init(bytes: [10, 20, 30, 40])
            )
        )
    }
    func testCMSIssuerAndSerialNumberParsesBERIndefiniteLengthIssuerName() throws {
        let bytes: [UInt8] = [
            0x30, 0x13,
            0x30, 0x80,
            0x31, 0x0a,
            0x30, 0x08,
            0x06, 0x03, 0x55, 0x04, 0x03,
            0x0c, 0x01, 0x41,
            0x00, 0x00,
            0x02, 0x01, 0x01,
        ]
        let parsed = try CMSIssuerAndSerialNumber(berEncoded: ArraySlice(bytes))
        let expectedIssuer = try DistinguishedName {
            CommonName("A")
        }
        XCTAssertEqual(parsed.issuer, expectedIssuer)
        XCTAssertEqual(parsed.serialNumber, Certificate.SerialNumber(bytes: [0x01]))
    }

    func testCMSIssuerAndSerialNumberNormalizesConstructedBERBMPStringIssuerName() throws {
        let bytes: [UInt8] = [
            0x30, 0x80,
            0x30, 0x80,
            0x31, 0x0f,
            0x30, 0x0d,
            0x06, 0x03, 0x55, 0x04, 0x03,
            0x3e, 0x80,
            0x04, 0x02, 0x00, 0x41,
            0x00, 0x00,
            0x00, 0x00,
            0x02, 0x01, 0x01,
            0x00, 0x00,
        ]
        let parsed = try CMSIssuerAndSerialNumber(berEncoded: ArraySlice(bytes))
        let bmpBytes: [UInt8] = [0x00, 0x41]
        let expectedIssuer = DistinguishedName([
            RelativeDistinguishedName([
                RelativeDistinguishedName.Attribute(
                    type: .RDNAttributeType.commonName,
                    value: try ASN1Any(erasing: ASN1BMPString(contentBytes: bmpBytes[...]))
                )
            ])
        ])

        XCTAssertEqual(parsed.issuer, expectedIssuer)
        XCTAssertEqual(parsed.serialNumber, Certificate.SerialNumber(bytes: [0x01]))
    }

    func testSignerIdentifierBERParsingNormalizesConstructedBMPStringIssuer() throws {
        // BER bytes for an issuerAndSerialNumber SignerIdentifier whose issuer
        // DistinguishedName contains a constructed (indefinite-length) BMPString.
        // Without explicit BER CHOICE dispatch on CMSSignerIdentifier, the default
        // DER-fallback path stores the raw BER bytes via ASN1Any without normalizing
        // the DirectoryString, causing a DistinguishedName equality mismatch.
        let bytes: [UInt8] = [
            0x30, 0x80,       // IssuerAndSerialNumber SEQUENCE (indefinite)
            0x30, 0x80,       // DistinguishedName SEQUENCE (indefinite)
            0x31, 0x0f,       // RDN SET, length 15
            0x30, 0x0d,       // ATV SEQUENCE, length 13
            0x06, 0x03, 0x55, 0x04, 0x03,  // OID 2.5.4.3 (commonName)
            0x3e, 0x80,       // BMPString, constructed, indefinite
            0x04, 0x02, 0x00, 0x41,  // OCTET STRING segment: BMP "A"
            0x00, 0x00,       // EOC (BMPString)
            0x00, 0x00,       // EOC (DistinguishedName)
            0x02, 0x01, 0x01, // INTEGER 1 (serialNumber)
            0x00, 0x00,       // EOC (IssuerAndSerialNumber)
        ]
        let parsed = try CMSSignerIdentifier(berEncoded: ArraySlice(bytes))

        let bmpBytes: [UInt8] = [0x00, 0x41]
        let expectedIssuer = DistinguishedName([
            RelativeDistinguishedName([
                RelativeDistinguishedName.Attribute(
                    type: .RDNAttributeType.commonName,
                    value: try ASN1Any(erasing: ASN1BMPString(contentBytes: bmpBytes[...]))
                )
            ])
        ])

        let expected = CMSSignerIdentifier.issuerAndSerialNumber(
            .init(issuer: expectedIssuer, serialNumber: .init(bytes: [0x01]))
        )

        XCTAssertEqual(parsed, expected)
    }

    func testCMSSignerInfoBERParsingNormalizesConstructedDirectoryStringIssuer() throws {
        // A minimal CMSSignerInfo (v1, no signed/unsigned attrs) whose
        // signerIdentifier contains a BER-constructed BMPString in the issuer DN.
        // Exercises the full CMSSignerInfo(berEncoded:) → CMSSignerIdentifier(berEncoded:)
        // → CMSIssuerAndSerialNumber(berEncoded:) chain after BER CHOICE dispatch exists.
        let bytes: [UInt8] = [
            // SignerInfo SEQUENCE, length 64 (0x40)
            0x30, 0x40,
            // version: INTEGER 1 (v1 matches issuerAndSerialNumber)
            0x02, 0x01, 0x01,
            // IssuerAndSerialNumber SEQUENCE, length 24 (0x18)
            0x30, 0x18,
            //   DistinguishedName SEQUENCE (indefinite)
            0x30, 0x80,
            //     RDN SET, length 15 (0x0f)
            0x31, 0x0f,
            //       ATV SEQUENCE, length 13 (0x0d)
            0x30, 0x0d,
            //         OID 2.5.4.3 (commonName)
            0x06, 0x03, 0x55, 0x04, 0x03,
            //         BMPString, constructed, indefinite
            0x3e, 0x80,
            //           OCTET STRING segment: BMP "A"
            0x04, 0x02, 0x00, 0x41,
            //           EOC (BMPString)
            0x00, 0x00,
            //     EOC (DistinguishedName)
            0x00, 0x00,
            //   serialNumber: INTEGER 1
            0x02, 0x01, 0x01,
            // digestAlgorithm: sha256WithRSAEncryption (nil params)
            0x30, 0x0b, 0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x01, 0x0b,
            // signatureAlgorithm: ecdsaWithSHA256
            0x30, 0x0a, 0x06, 0x08, 0x2a, 0x86, 0x48, 0xce, 0x3d, 0x04, 0x03, 0x02,
            // signature: 8-byte placeholder
            0x04, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        ]

        let parsed = try CMSSignerInfo(berEncoded: ArraySlice(bytes))

        guard case .issuerAndSerialNumber(let ias) = parsed.signerIdentifier else {
            XCTFail("Expected issuerAndSerialNumber signerIdentifier")
            return
        }

        let bmpBytes: [UInt8] = [0x00, 0x41]
        let expectedIssuer = DistinguishedName([
            RelativeDistinguishedName([
                RelativeDistinguishedName.Attribute(
                    type: .RDNAttributeType.commonName,
                    value: try ASN1Any(erasing: ASN1BMPString(contentBytes: bmpBytes[...]))
                )
            ])
        ])

        XCTAssertEqual(parsed.version, .v1)
        XCTAssertEqual(ias.issuer, expectedIssuer)
        XCTAssertEqual(ias.serialNumber, Certificate.SerialNumber(bytes: [0x01]))
    }

    func testSignerIdentifier() throws {
        try assertRoundTrips(
            CMSSignerIdentifier.issuerAndSerialNumber(
                .init(
                    issuer: .init {
                        CountryName("US")
                        OrganizationName("Apple Inc.")
                        CommonName("Apple Public EV Server ECC CA 1 - G1")
                    },
                    serialNumber: .init(bytes: [20, 30, 40, 50])
                )
            )
        )
        try assertRoundTrips(
            CMSSignerIdentifier.subjectKeyIdentifier(.init(keyIdentifier: [10, 20, 30, 40]))
        )
    }
    func testCMSSignerInfo() throws {
        try assertRoundTrips(
            CMSSignerInfo(
                version: .v1,
                signerIdentifier: .issuerAndSerialNumber(
                    .init(
                        issuer: .init {
                            CountryName("US")
                            OrganizationName("Apple Inc.")
                            CommonName("Apple Public EV Server ECC CA 1 - G1")
                        },
                        serialNumber: .init(bytes: [20, 30, 40, 50])
                    )
                ),
                digestAlgorithm: .sha256WithRSAEncryptionUsingNil,
                signatureAlgorithm: .ecdsaWithSHA256,
                signature: .init(contentBytes: [100, 110, 120, 130, 140])
            )
        )

        try assertRoundTrips(
            CMSSignerInfo(
                version: .v3,
                signerIdentifier: .subjectKeyIdentifier(.init(keyIdentifier: [10, 20, 30, 40])),
                digestAlgorithm: .sha256WithRSAEncryptionUsingNil,
                signatureAlgorithm: .ecdsaWithSHA256,
                signature: .init(contentBytes: [100, 110, 120, 130, 140])
            )
        )

        XCTAssertThrowsError(
            try assertRoundTrips(
                CMSSignerInfo(
                    version: .v3,
                    signerIdentifier: .issuerAndSerialNumber(
                        .init(
                            issuer: .init {
                                CountryName("US")
                                OrganizationName("Apple Inc.")
                                CommonName("Apple Public EV Server ECC CA 1 - G1")
                            },
                            serialNumber: .init(bytes: [20, 30, 40, 50])
                        )
                    ),
                    digestAlgorithm: .sha256WithRSAEncryptionUsingNil,
                    signatureAlgorithm: .ecdsaWithSHA256,
                    signature: .init(contentBytes: [100, 110, 120, 130, 140])
                )
            ),
            "unexpected signerIdentifier for version should throw"
        )

        XCTAssertThrowsError(
            try assertRoundTrips(
                CMSSignerInfo(
                    version: .v1,
                    signerIdentifier: .subjectKeyIdentifier(.init(keyIdentifier: [10, 20, 30, 40])),
                    digestAlgorithm: .sha256WithRSAEncryptionUsingNil,
                    signatureAlgorithm: .ecdsaWithSHA256,
                    signature: .init(contentBytes: [100, 110, 120, 130, 140])
                )
            ),
            "unexpected signerIdentifier for version should throw"
        )
    }
    func testEncapsulatedContentInfo() throws {
        try assertRoundTrips(
            CMSEncapsulatedContentInfo(
                eContentType: [1, 2, 3, 4],
                eContent: .init(contentBytes: [5, 6, 7, 8])
            )
        )
        try assertRoundTrips(
            CMSEncapsulatedContentInfo(
                eContentType: [1, 2, 3, 4],
                eContent: nil
            )
        )
    }
    func testSignedData() throws {
        try assertRoundTrips(
            CMSSignedData(
                version: .v1,
                digestAlgorithms: [],
                encapContentInfo: .init(eContentType: [1, 2, 3, 4]),
                certificates: nil,
                signerInfos: []
            )
        )
        try assertRoundTrips(
            CMSSignedData(
                version: .v1,
                digestAlgorithms: [.sha256WithRSAEncryptionUsingNil],
                encapContentInfo: .init(eContentType: [1, 2, 3, 4]),
                certificates: [],
                signerInfos: []
            )
        )
        try assertRoundTrips(
            CMSSignedData(
                version: .v1,
                digestAlgorithms: [.sha256WithRSAEncryptionUsingNil],
                encapContentInfo: .init(eContentType: [1, 2, 3, 4]),
                certificates: [],
                signerInfos: [
                    CMSSignerInfo(
                        version: .v3,
                        signerIdentifier: .subjectKeyIdentifier(.init(keyIdentifier: [10, 20, 30, 40])),
                        digestAlgorithm: .sha256WithRSAEncryptionUsingNil,
                        signatureAlgorithm: .ecdsaWithSHA256,
                        signature: .init(contentBytes: [100, 110, 120, 130, 140])
                    )
                ]
            )
        )

        let privateKey = P384.Signing.PrivateKey()
        try assertRoundTrips(
            CMSSignedData(
                version: .v1,
                digestAlgorithms: [
                    .sha256WithRSAEncryptionUsingNil
                ],
                encapContentInfo: .init(eContentType: [1, 2, 3, 4]),
                certificates: [
                    Certificate(
                        version: .v3,
                        serialNumber: .init(bytes: [1, 2, 3, 4]),
                        publicKey: .init(privateKey.publicKey),
                        notValidBefore: Date(),
                        notValidAfter: Date(),
                        issuer: DistinguishedName {
                            CountryName("US")
                            OrganizationName("Apple Inc.")
                            CommonName("Apple Public EV Server ECC CA 1 - G1")
                        },
                        subject: DistinguishedName {
                            CountryName("US")
                            OrganizationName("Apple Inc.")
                            CommonName("apple.com")
                        },
                        signatureAlgorithm: .ecdsaWithSHA384,
                        extensions: .init(),
                        issuerPrivateKey: .init(privateKey)
                    )
                ],
                signerInfos: []
            )
        )
    }

    func testContentInfo() throws {
        let privateKey = P384.Signing.PrivateKey()
        try assertRoundTrips(
            CMSContentInfo(
                CMSSignedData(
                    version: .v1,
                    digestAlgorithms: [
                        .sha256WithRSAEncryptionUsingNil
                    ],
                    encapContentInfo: .init(eContentType: [1, 2, 3, 4]),
                    certificates: [
                        Certificate(
                            version: .v3,
                            serialNumber: .init(bytes: [1, 2, 3, 4]),
                            publicKey: .init(privateKey.publicKey),
                            notValidBefore: Date(),
                            notValidAfter: Date(),
                            issuer: DistinguishedName {
                                CountryName("US")
                                OrganizationName("Apple Inc.")
                                CommonName("Apple Public EV Server ECC CA 1 - G1")
                            },
                            subject: DistinguishedName {
                                CountryName("US")
                                OrganizationName("Apple Inc.")
                                CommonName("apple.com")
                            },
                            signatureAlgorithm: .ecdsaWithSHA384,
                            extensions: .init(),
                            issuerPrivateKey: .init(privateKey)
                        )
                    ],
                    signerInfos: []
                )
            )
        )
    }

    func testCMSEncryptedContentInfo() throws {
        let encryptedContentInfo = try CMSEncryptedContentInfo(
            contentType: .cmsData,
            contentEncryptionAlgorithm: .cmsAES256CBC(
                iv: ASN1OctetString(contentBytes: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
            ),
            encryptedContent: ASN1OctetString(contentBytes: [1, 2, 3])
        )

        try assertRoundTrips(encryptedContentInfo)
        XCTAssertTrue(try encryptedContentInfo.encodedBytes.containsSubsequence([0x80, 0x03, 0x01, 0x02, 0x03]))
    }

    func testCMSEncryptedDataAndContentInfo() throws {
        let encryptedData = try CMSEncryptedData(
            version: .v0,
            encryptedContentInfo: CMSEncryptedContentInfo(
                contentType: .cmsData,
                contentEncryptionAlgorithm: .cmsAES256CBC(
                    iv: ASN1OctetString(contentBytes: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
                ),
                encryptedContent: ASN1OctetString(contentBytes: [1, 2, 3])
            ),
            unprotectedAttrs: nil
        )

        try assertRoundTrips(encryptedData)

        let contentInfo = try CMSContentInfo(encryptedData)
        try assertRoundTrips(contentInfo)
        XCTAssertNotNil(try contentInfo.encryptedData)
    }

    func testCMSRecipientIdentifiers() throws {
        let issuerAndSerialNumber = CMSIssuerAndSerialNumber(
            issuer: Self.rsaCert.issuer,
            serialNumber: Self.rsaCert.serialNumber
        )
        try assertRoundTrips(CMSRecipientIdentifier.issuerAndSerialNumber(issuerAndSerialNumber))

        let subjectKeyIdentifier = CMSRecipientIdentifier.subjectKeyIdentifier(
            SubjectKeyIdentifier(keyIdentifier: [10, 20, 30, 40])
        )
        try assertRoundTrips(subjectKeyIdentifier)
        XCTAssertEqual(try subjectKeyIdentifier.encodedBytes, [0x80, 0x04, 10, 20, 30, 40])

        let recipientKeyIdentifier = CMSKeyAgreeRecipientIdentifier.recipientKeyIdentifier(
            CMSRecipientKeyIdentifier(subjectKeyIdentifier: SubjectKeyIdentifier(keyIdentifier: [9]))
        )
        try assertRoundTrips(recipientKeyIdentifier)
        let recipientKeyIdentifierBytes = try recipientKeyIdentifier.encodedBytes
        XCTAssertEqual(recipientKeyIdentifierBytes[0], 0xa0)
        XCTAssertEqual(recipientKeyIdentifierBytes[2], 0x04)
    }

    func testCMSRecipientKeyIdentifierParsesBEROptionalFields() throws {
        let bytes: [UInt8] = [
            0x30, 0x80,  // RecipientKeyIdentifier SEQUENCE (indefinite)
            0x04, 0x01, 0x09,  // subjectKeyIdentifier
            0x38, 0x80,  // constructed GeneralizedTime (indefinite)
            // SwiftASN1's BER GeneralizedTime parser flattens constructed content as octet strings.
            0x04, 0x08, 0x32, 0x30, 0x32, 0x36, 0x30, 0x31, 0x30, 0x31,  // "20260101"
            0x04, 0x07, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a,  // "000000Z"
            0x00, 0x00,
            0x30, 0x80,  // OtherKeyAttribute SEQUENCE (indefinite)
            0x06, 0x02, 0x2a, 0x03,  // 1.2.3
            0x00, 0x00,
            0x00, 0x00,
        ]
        let parsed = try CMSRecipientKeyIdentifier(berEncoded: ArraySlice(bytes))
        let expectedDate = try GeneralizedTime(
            year: 2026,
            month: 1,
            day: 1,
            hours: 0,
            minutes: 0,
            seconds: 0,
            fractionalSeconds: 0
        )
        let expectedOtherOID: ASN1ObjectIdentifier = [1, 2, 3]

        XCTAssertEqual(Array(parsed.subjectKeyIdentifier.keyIdentifier), [0x09])
        XCTAssertEqual(parsed.date, expectedDate)
        XCTAssertEqual(parsed.other?.keyAttributeIdentifier, expectedOtherOID)
        XCTAssertNil(parsed.other?.keyAttribute)
    }

    func testCMSKEKIdentifierParsesBEROptionalFields() throws {
        let bytes: [UInt8] = [
            0x30, 0x80,  // KEKIdentifier SEQUENCE (indefinite)
            0x04, 0x03, 0x01, 0x02, 0x03,  // keyIdentifier
            0x38, 0x80,  // constructed GeneralizedTime (indefinite)
            // SwiftASN1's BER GeneralizedTime parser flattens constructed content as octet strings.
            0x04, 0x08, 0x32, 0x30, 0x32, 0x36, 0x30, 0x31, 0x30, 0x31,  // "20260101"
            0x04, 0x07, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5a,  // "000000Z"
            0x00, 0x00,
            0x30, 0x80,  // OtherKeyAttribute SEQUENCE (indefinite)
            0x06, 0x02, 0x2a, 0x03,  // 1.2.3
            0x00, 0x00,
            0x00, 0x00,
        ]
        let parsed = try CMSKEKIdentifier(berEncoded: ArraySlice(bytes))
        let expectedDate = try GeneralizedTime(
            year: 2026,
            month: 1,
            day: 1,
            hours: 0,
            minutes: 0,
            seconds: 0,
            fractionalSeconds: 0
        )
        let expectedOtherOID: ASN1ObjectIdentifier = [1, 2, 3]

        XCTAssertEqual(Array(parsed.keyIdentifier.bytes), [0x01, 0x02, 0x03])
        XCTAssertEqual(parsed.date, expectedDate)
        XCTAssertEqual(parsed.other?.keyAttributeIdentifier, expectedOtherOID)
        XCTAssertNil(parsed.other?.keyAttribute)
    }

    func testCMSRecipientInfoChoiceTags() throws {
        let keyTransRecipientInfo = CMSRecipientInfo.keyTransRecipientInfo(
            CMSKeyTransRecipientInfo(
                recipientIdentifier: .init(issuerAndSerialNumber: Self.rsaCert),
                keyEncryptionAlgorithm: .cmsRSAESOAEPWithSHA256,
                encryptedKey: ASN1OctetString(contentBytes: [1, 2, 3])
            )
        )
        try assertRoundTrips(keyTransRecipientInfo)
        XCTAssertEqual(try keyTransRecipientInfo.encodedBytes.first, 0x30)

        let keyAgreeRecipientInfo = CMSRecipientInfo.keyAgreeRecipientInfo(
            CMSKeyAgreeRecipientInfo(
                originator: .subjectKeyIdentifier(SubjectKeyIdentifier(keyIdentifier: [1])),
                keyEncryptionAlgorithm: AlgorithmIdentifier(algorithm: [1, 2, 3], parameters: nil),
                recipientEncryptedKeys: [
                    CMSRecipientEncryptedKey(
                        recipientIdentifier: .recipientKeyIdentifier(
                            CMSRecipientKeyIdentifier(
                                subjectKeyIdentifier: SubjectKeyIdentifier(keyIdentifier: [9])
                            )
                        ),
                        encryptedKey: ASN1OctetString(contentBytes: [8])
                    )
                ]
            )
        )
        try assertRoundTrips(keyAgreeRecipientInfo)
        let keyAgreeBytes = try keyAgreeRecipientInfo.encodedBytes
        XCTAssertEqual(keyAgreeBytes[0], 0xa1)
        XCTAssertEqual(keyAgreeBytes[2], 0x02)
        XCTAssertTrue(keyAgreeBytes.containsSubsequence([0x30, 0x0a, 0x30, 0x08, 0xa0, 0x03, 0x04, 0x01, 0x09, 0x04, 0x01, 0x08]))
        XCTAssertFalse(keyAgreeBytes.containsSubsequence([0x31, 0x0a, 0x30, 0x08]))

        let kekRecipientInfo = CMSRecipientInfo.kekRecipientInfo(
            CMSKEKRecipientInfo(
                kekIdentifier: CMSKEKIdentifier(keyIdentifier: ASN1OctetString(contentBytes: [1, 2, 3])),
                keyEncryptionAlgorithm: AlgorithmIdentifier(algorithm: [1, 2, 3], parameters: nil),
                encryptedKey: ASN1OctetString(contentBytes: [4, 5, 6])
            )
        )
        try assertRoundTrips(kekRecipientInfo)
        XCTAssertEqual(try kekRecipientInfo.encodedBytes.first, 0xa2)

        let passwordRecipientInfo = CMSRecipientInfo.passwordRecipientInfo(
            CMSPasswordRecipientInfo(
                keyEncryptionAlgorithm: AlgorithmIdentifier(algorithm: [1, 2, 3], parameters: nil),
                encryptedKey: ASN1OctetString(contentBytes: [4, 5, 6])
            )
        )
        try assertRoundTrips(passwordRecipientInfo)
        XCTAssertEqual(try passwordRecipientInfo.encodedBytes.first, 0xa3)

        let otherRecipientInfo = try CMSRecipientInfo.otherRecipientInfo(
            CMSOtherRecipientInfo(type: [1, 2, 3], value: ASN1Any(erasing: ASN1Null()))
        )
        try assertRoundTrips(otherRecipientInfo)
        XCTAssertEqual(try otherRecipientInfo.encodedBytes.first, 0xa4)
    }

    func testCMSPasswordRecipientInfoKeyDerivationAlgorithmIsOptionalAndTagged() throws {
        let withoutKeyDerivationAlgorithm = CMSPasswordRecipientInfo(
            keyEncryptionAlgorithm: AlgorithmIdentifier(algorithm: [1, 2, 3], parameters: nil),
            encryptedKey: ASN1OctetString(contentBytes: [4, 5, 6])
        )
        try assertRoundTrips(withoutKeyDerivationAlgorithm)
        let reparsedWithoutKDF = try CMSPasswordRecipientInfo(
            derEncoded: withoutKeyDerivationAlgorithm.encodedBytes
        )
        XCTAssertNil(reparsedWithoutKDF.keyDerivationAlgorithm)

        let withKeyDerivationAlgorithm = CMSPasswordRecipientInfo(
            keyDerivationAlgorithm: AlgorithmIdentifier(algorithm: [1, 2, 3], parameters: nil),
            keyEncryptionAlgorithm: AlgorithmIdentifier(algorithm: [1, 2, 3], parameters: nil),
            encryptedKey: ASN1OctetString(contentBytes: [4, 5, 6])
        )
        try assertRoundTrips(withKeyDerivationAlgorithm)
        XCTAssertTrue(try withKeyDerivationAlgorithm.encodedBytes.containsSubsequence([0xa0, 0x04, 0x06, 0x02, 0x2a, 0x03]))
    }

    func testCMSEnvelopedDataAndContentInfo() throws {
        let envelopedData = try CMSEnvelopedData(
            version: .v0,
            originatorInfo: nil,
            recipientInfos: [
                .keyTransRecipientInfo(
                    CMSKeyTransRecipientInfo(
                        recipientIdentifier: .init(issuerAndSerialNumber: Self.rsaCert),
                        keyEncryptionAlgorithm: .cmsRSAESOAEPWithSHA256,
                        encryptedKey: ASN1OctetString(contentBytes: [1, 2, 3])
                    )
                )
            ],
            encryptedContentInfo: CMSEncryptedContentInfo(
                contentType: .cmsData,
                contentEncryptionAlgorithm: .cmsAES256CBC(
                    iv: ASN1OctetString(contentBytes: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
                ),
                encryptedContent: ASN1OctetString(contentBytes: [1, 2, 3])
            ),
            unprotectedAttrs: nil
        )

        try assertRoundTrips(envelopedData)
        XCTAssertEqual(envelopedData.expectedVersion, .v0)

        let contentInfo = try CMSContentInfo(envelopedData)
        try assertRoundTrips(contentInfo)
        XCTAssertNotNil(try contentInfo.envelopedData)
    }

    func testEncryptDecryptSingleRecipientRSA() throws {
        let plaintext = Array("swift-certificates cms".utf8)
        let encrypted = try CMS.encrypt(plaintext, recipientCertificates: [Self.rsaCert])
        let contentInfo = try CMSContentInfo(berEncoded: ArraySlice(encrypted))
        let envelopedData = try XCTUnwrap(try contentInfo.envelopedData)
        XCTAssertEqual(envelopedData.version, .v0)
        XCTAssertEqual(envelopedData.recipientInfos.count, 1)
        XCTAssertEqual(envelopedData.encryptedContentInfo.contentType, .cmsData)
        XCTAssertEqual(envelopedData.encryptedContentInfo.contentEncryptionAlgorithm.algorithm, .AlgorithmIdentifier.aes256CBC)
        let contentEncryptionParameters = try XCTUnwrap(envelopedData.encryptedContentInfo.contentEncryptionAlgorithm.parameters)
        XCTAssertEqual(try ASN1OctetString(asn1Any: contentEncryptionParameters).bytes.count, 16)
        guard case .keyTransRecipientInfo(let recipientInfo) = envelopedData.recipientInfos[0] else {
            return XCTFail("Expected key transport recipient info")
        }
        XCTAssertEqual(recipientInfo.keyEncryptionAlgorithm.algorithm, .AlgorithmIdentifier.rsaESOAEP)
        let keyEncryptionParameters = try XCTUnwrap(recipientInfo.keyEncryptionAlgorithm.parameters)
        let rsaOAEPParams = try CMSRSAESOAEPParams(asn1Any: keyEncryptionParameters)
        XCTAssertEqual(rsaOAEPParams.hashAlgorithm, .sha256)
        XCTAssertEqual(rsaOAEPParams.maskGenAlgorithm, .cmsMGF1WithSHA256)

        let decrypted = try CMS.decrypt(encrypted, recipientCertificate: Self.rsaCert, privateKey: Self.rsaCertKey)
        XCTAssertEqual(decrypted, plaintext)
    }

    func testEncryptDecryptMultipleRecipientRSA() throws {
        let plaintext = Array("multi recipient cms".utf8)
        let encrypted = try CMS.encrypt(plaintext, recipientCertificates: [Self.rsaCert, Self.rsaCert2])

        XCTAssertEqual(try CMS.decrypt(encrypted, recipientCertificate: Self.rsaCert, privateKey: Self.rsaCertKey), plaintext)
        XCTAssertEqual(try CMS.decrypt(encrypted, recipientCertificate: Self.rsaCert2, privateKey: Self.rsaCert2Key), plaintext)
    }

    func testDecryptWrongPrivateKeyFails() throws {
        let encrypted = try CMS.encrypt([1, 2, 3, 4], recipientCertificates: [Self.rsaCert])

        XCTAssertThrowsError(
            try CMS.decrypt(encrypted, recipientCertificate: Self.rsaCert, privateKey: Self.rsaCert2Key)
        )
    }

    func testDecryptMissingMatchingRecipientFails() throws {
        let encrypted = try CMS.encrypt([1, 2, 3, 4], recipientCertificates: [Self.rsaCert])

        XCTAssertThrowsError(
            try CMS.decrypt(encrypted, recipientCertificate: Self.rsaCert2, privateKey: Self.rsaCert2Key)
        )
    }

    func testEncryptRequiresRSACertificate() throws {
        XCTAssertThrowsError(try CMS.encrypt([1, 2, 3, 4], recipientCertificates: [Self.ed25519Cert]))
    }

    func testDecryptVersionMismatchFails() throws {
        let envelopedData = try CMSEnvelopedData(
            version: .v3,
            originatorInfo: nil,
            recipientInfos: [
                .keyAgreeRecipientInfo(
                    CMSKeyAgreeRecipientInfo(
                        originator: .subjectKeyIdentifier(SubjectKeyIdentifier(keyIdentifier: [1])),
                        keyEncryptionAlgorithm: AlgorithmIdentifier(algorithm: [1, 2, 3], parameters: nil),
                        recipientEncryptedKeys: [
                            CMSRecipientEncryptedKey(
                                recipientIdentifier: .recipientKeyIdentifier(
                                    CMSRecipientKeyIdentifier(
                                        subjectKeyIdentifier: SubjectKeyIdentifier(keyIdentifier: [9])
                                    )
                                ),
                                encryptedKey: ASN1OctetString(contentBytes: [8])
                            )
                        ]
                    )
                )
            ],
            encryptedContentInfo: CMSEncryptedContentInfo(
                contentType: .cmsData,
                contentEncryptionAlgorithm: .cmsAES256CBC(
                    iv: ASN1OctetString(contentBytes: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
                ),
                encryptedContent: ASN1OctetString(contentBytes: [1, 2, 3])
            ),
            unprotectedAttrs: nil
        )
        let encrypted = try CMSContentInfo(envelopedData).encodedBytes

        XCTAssertThrowsError(try CMS.decrypt(encrypted, recipientCertificate: Self.rsaCert, privateKey: Self.rsaCertKey))
    }

    func testDecryptUnsupportedContentAlgorithmFails() throws {
        var envelopedData = try self.envelopedData(from: CMS.encrypt([1, 2, 3, 4], recipientCertificates: [Self.rsaCert]))
        envelopedData.encryptedContentInfo.contentEncryptionAlgorithm = .sha256
        let encrypted = try CMSContentInfo(envelopedData).encodedBytes

        XCTAssertThrowsError(try CMS.decrypt(encrypted, recipientCertificate: Self.rsaCert, privateKey: Self.rsaCertKey))
    }

    func testDecryptUnsupportedKeyEncryptionAlgorithmFails() throws {
        var envelopedData = try self.envelopedData(from: CMS.encrypt([1, 2, 3, 4], recipientCertificates: [Self.rsaCert]))
        guard case .keyTransRecipientInfo(var recipientInfo) = envelopedData.recipientInfos[0] else {
            return XCTFail("Expected key transport recipient info")
        }
        recipientInfo.keyEncryptionAlgorithm = .sha256
        envelopedData.recipientInfos[0] = .keyTransRecipientInfo(recipientInfo)
        let encrypted = try CMSContentInfo(envelopedData).encodedBytes

        XCTAssertThrowsError(try CMS.decrypt(encrypted, recipientCertificate: Self.rsaCert, privateKey: Self.rsaCertKey))
    }

    func testDecryptMalformedEnvelopedDataVersionFails() throws {
        var envelopedData = try self.envelopedData(from: CMS.encrypt([1, 2, 3, 4], recipientCertificates: [Self.rsaCert]))
        envelopedData.version = .v3
        let encrypted = try CMSContentInfo(envelopedData).encodedBytes

        XCTAssertThrowsError(try CMS.decrypt(encrypted, recipientCertificate: Self.rsaCert, privateKey: Self.rsaCertKey))
    }

    func testDecryptWrongContentInfoTypeFails() throws {
        let encryptedData = try CMSEncryptedData(
            version: .v0,
            encryptedContentInfo: CMSEncryptedContentInfo(
                contentType: .cmsData,
                contentEncryptionAlgorithm: .cmsAES256CBC(
                    iv: ASN1OctetString(contentBytes: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
                ),
                encryptedContent: ASN1OctetString(contentBytes: [1, 2, 3])
            ),
            unprotectedAttrs: nil
        )
        let encrypted = try CMSContentInfo(encryptedData).encodedBytes

        XCTAssertThrowsError(try CMS.decrypt(encrypted, recipientCertificate: Self.rsaCert, privateKey: Self.rsaCertKey))
    }


    func testSimpleSigningVerifying() async throws {
        let data: [UInt8] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]

        let signature = try CMS.sign(
            data,
            signatureAlgorithm: .ecdsaWithSHA256,
            certificate: Self.leaf1Cert,
            privateKey: Self.leaf1Key
        )
        let log = DiagnosticsLog()
        let isValidSignature = await CMS.isValidSignature(
            dataBytes: data,
            signatureBytes: signature,
            trustRoots: CertificateStore([Self.rootCert]),
            diagnosticCallback: log.append(_:)
        ) { Self.defaultPolicies }
        XCTAssertValidSignature(isValidSignature)

        XCTAssertEqual(
            log,
            [
                .searchingForIssuerOfPartialChain([Self.leaf1Cert]),
                .foundCandidateIssuersOfPartialChainInRootStore([Self.leaf1Cert], issuers: [Self.rootCert]),
                .foundValidCertificateChain([Self.leaf1Cert, Self.rootCert]),
            ]
        )
    }

    func testAttachedSigningVerifying() async throws {
        let data: [UInt8] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]

        let signature = try CMS.sign(
            data,
            signatureAlgorithm: .ecdsaWithSHA256,
            certificate: Self.leaf1Cert,
            privateKey: Self.leaf1Key,
            detached: false
        )
        let log = DiagnosticsLog()
        let isValidSignature = await CMS.isValidSignature(
            dataBytes: data,
            signatureBytes: signature,
            trustRoots: CertificateStore([Self.rootCert]),
            diagnosticCallback: log.append(_:),
            allowAttachedContent: true
        ) { Self.defaultPolicies }
        XCTAssertValidSignature(isValidSignature)

        XCTAssertEqual(
            log,
            [
                .searchingForIssuerOfPartialChain([Self.leaf1Cert]),
                .foundCandidateIssuersOfPartialChainInRootStore([Self.leaf1Cert], issuers: [Self.rootCert]),
                .foundValidCertificateChain([Self.leaf1Cert, Self.rootCert]),
            ]
        )
    }

    func testForbidsDetachedSignatureVerifyingAsAttached() async throws {
        let data: [UInt8] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]

        let signature = try CMS.sign(
            data,
            signatureAlgorithm: .ecdsaWithSHA256,
            certificate: Self.leaf1Cert,
            privateKey: Self.leaf1Key,
            detached: true
        )
        let log = DiagnosticsLog()
        let isValidAttachedSignature = await CMS.isValidAttachedSignature(
            signatureBytes: signature,
            trustRoots: CertificateStore([Self.rootCert]),
            diagnosticCallback: log.append(_:)
        ) { Self.defaultPolicies }
        XCTAssertInvalidCMSBlock(isValidAttachedSignature)
    }

    func testToleratesAttachedSignatureVerifyingAsDetached() async throws {
        let data: [UInt8] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]

        let signature = try CMS.sign(
            data,
            signatureAlgorithm: .ecdsaWithSHA256,
            certificate: Self.leaf1Cert,
            privateKey: Self.leaf1Key,
            detached: false
        )
        let log = DiagnosticsLog()
        let isValidDetachedSignature = await CMS.isValidSignature(
            dataBytes: data,
            signatureBytes: signature,
            trustRoots: CertificateStore([Self.rootCert]),
            diagnosticCallback: log.append(_:),
            allowAttachedContent: true
        ) { Self.defaultPolicies }
        XCTAssertValidSignature(isValidDetachedSignature)
    }

    func testParsingSimpleSignature() async throws {
        let data: [UInt8] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]

        let signatureBytes = try CMS.sign(
            data,
            signatureAlgorithm: .ecdsaWithSHA256,
            certificate: Self.leaf1Cert,
            privateKey: Self.leaf1Key
        )
        let signature = try CMSSignature(derEncoded: signatureBytes)

        XCTAssertEqual(try signature.signers, [CMSSignature.Signer(certificate: Self.leaf1Cert)])
        XCTAssertEqual(signature.certificates, [Self.leaf1Cert])

        XCTAssertEqual(signatureBytes, try signature.encodedBytes)
    }

    func testParsingSignatureWithIntermediates() async throws {
        let data: [UInt8] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]

        let signatureBytes = try CMS.sign(
            data,
            signatureAlgorithm: .ecdsaWithSHA256,
            additionalIntermediateCertificates: [Self.intermediateCert],
            certificate: Self.leaf2Cert,
            privateKey: Self.leaf2Key
        )
        let signature = try CMSSignature(derEncoded: signatureBytes)

        XCTAssertEqual(try signature.signers, [CMSSignature.Signer(certificate: Self.leaf2Cert)])
        XCTAssertEqual(signature.certificates, [Self.intermediateCert, Self.leaf2Cert])

        XCTAssertEqual(signatureBytes, try signature.encodedBytes)
    }

    func testToleratesAdditionalSignerInfos() async throws {
        let data: [UInt8] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
        var cmsData = try CMS.generateSignedTestData(
            data,
            signatureAlgorithm: .ecdsaWithSHA256,
            certificate: Self.leaf1Cert,
            privateKey: Self.leaf1Key
        )

        // Add a second, identical, signer info.
        var signedData = try CMSSignedData(asn1Any: cmsData.content)
        signedData.signerInfos.append(signedData.signerInfos[0])
        cmsData.content = try ASN1Any(erasing: signedData)

        let signature = try CMSSignature(derEncoded: cmsData.encodedBytes)
        XCTAssertEqual(
            try signature.signers,
            [CMSSignature.Signer(certificate: Self.leaf1Cert), CMSSignature.Signer(certificate: Self.leaf1Cert)]
        )
        XCTAssertEqual(signature.certificates, [Self.leaf1Cert])

        XCTAssertEqual(try cmsData.encodedBytes, try signature.encodedBytes)
    }

    func testRequireCMSV1SignatureOnCMSSignatureType() async throws {
        let data: [UInt8] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
        var cmsData = try CMS.generateSignedTestData(
            data,
            signatureAlgorithm: .ecdsaWithSHA256,
            certificate: Self.leaf1Cert,
            privateKey: Self.leaf1Key
        )

        // Change the version number to v3
        var signedData = try CMSSignedData(asn1Any: cmsData.content)
        signedData.version = .v3
        cmsData.content = try ASN1Any(erasing: signedData)

        XCTAssertThrowsError(try CMSSignature(derEncoded: cmsData.encodedBytes))
    }

    func testRejectsSignatureWithoutRoot() async throws {
        let data: [UInt8] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]

        let signature = try CMS.sign(
            data,
            signatureAlgorithm: .ecdsaWithSHA256,
            certificate: Self.leaf1Cert,
            privateKey: Self.leaf1Key
        )
        let isValidSignature = await CMS.isValidSignature(
            dataBytes: data,
            signatureBytes: signature,
            trustRoots: CertificateStore([Self.secondRootCert])
        ) {}
        XCTAssertUnableToValidateSigner(isValidSignature)
    }

    func testPoliciesAreApplied() async throws {
        final class RejectAllPolicy: VerifierPolicy {
            let verifyingCriticalExtensions: [ASN1ObjectIdentifier] = []

            func chainMeetsPolicyRequirements(
                chain: X509.UnverifiedCertificateChain
            ) async -> X509.PolicyEvaluationResult {
                return .failsToMeetPolicy(reason: "all chains are forbidden")
            }
        }

        let data: [UInt8] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]

        let signature = try CMS.sign(
            data,
            signatureAlgorithm: .ecdsaWithSHA256,
            certificate: Self.leaf1Cert,
            privateKey: Self.leaf1Key
        )
        let isValidSignature = await CMS.isValidSignature(
            dataBytes: data,
            signatureBytes: signature,
            trustRoots: CertificateStore([Self.rootCert])
        ) {
            RejectAllPolicy()
        }
        XCTAssertUnableToValidateSigner(isValidSignature)
    }

    func testRequireCMSSignedData() async throws {
        let data: [UInt8] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
        var cmsData = try CMS.generateSignedTestData(
            data,
            signatureAlgorithm: .ecdsaWithSHA256,
            certificate: Self.leaf1Cert,
            privateKey: Self.leaf1Key
        )

        // This is a meaningless OID to use here, I just want to use something I know we don't support.
        cmsData.contentType = .sha256NoSign
        let isValidSignature = try await CMS.isValidSignature(
            dataBytes: data,
            signatureBytes: cmsData.encodedBytes,
            trustRoots: CertificateStore([Self.rootCert])
        ) {}
        XCTAssertInvalidCMSBlock(isValidSignature)
    }

    func testRequireCMSV1SignatureWhenInvalidV3SignerInfo() async throws {
        let data: [UInt8] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
        var cmsData = try CMS.generateSignedTestData(
            data,
            signatureAlgorithm: .ecdsaWithSHA256,
            certificate: Self.leaf1Cert,
            privateKey: Self.leaf1Key
        )

        // Change the version number to v3 in both places, but not the signerIdentifier
        var signedData = try CMSSignedData(asn1Any: cmsData.content)
        signedData.version = .v3
        signedData.signerInfos[0].version = .v3
        cmsData.content = try ASN1Any(erasing: signedData)

        let isValidSignature = try await CMS.isValidSignature(
            dataBytes: data,
            signatureBytes: cmsData.encodedBytes,
            trustRoots: CertificateStore([Self.rootCert])
        ) {}
        XCTAssertInvalidCMSBlock(isValidSignature)
    }

    func testRequireCMSV1SignatureEvenOnTheSignerInfo() async throws {
        let data: [UInt8] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
        var cmsData = try CMS.generateSignedTestData(
            data,
            signatureAlgorithm: .ecdsaWithSHA256,
            certificate: Self.leaf1Cert,
            privateKey: Self.leaf1Key
        )

        // Change the version number to v3, but only in the signer info.
        var signedData = try CMSSignedData(asn1Any: cmsData.content)
        signedData.signerInfos[0].version = .v3
        cmsData.content = try ASN1Any(erasing: signedData)

        let isValidSignature = try await CMS.isValidSignature(
            dataBytes: data,
            signatureBytes: cmsData.encodedBytes,
            trustRoots: CertificateStore([Self.rootCert])
        ) {}
        XCTAssertInvalidCMSBlock(isValidSignature)
    }

    func testRequireCMSV1SignatureEvenWhenV3IsCorrectlyAttestedOnSignerInfo() async throws {
        let data: [UInt8] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
        var cmsData = try CMS.generateSignedTestData(
            data,
            signatureAlgorithm: .ecdsaWithSHA256,
            certificate: Self.leaf1Cert,
            privateKey: Self.leaf1Key
        )

        // Change the version number to v3, but only in the signer info.
        var signedData = try CMSSignedData(asn1Any: cmsData.content)
        signedData.signerInfos[0].version = .v3
        signedData.signerInfos[0].signerIdentifier = try .subjectKeyIdentifier(
            Self.leaf1Cert.extensions.subjectKeyIdentifier!
        )
        cmsData.content = try ASN1Any(erasing: signedData)

        let isValidSignature = try await CMS.isValidSignature(
            dataBytes: data,
            signatureBytes: cmsData.encodedBytes,
            trustRoots: CertificateStore([Self.rootCert])
        ) {}
        XCTAssertInvalidCMSBlock(isValidSignature)
    }

    func testCMSV3Signature() async throws {
        let data: [UInt8] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
        var cmsData = try CMS.generateSignedTestData(
            data,
            signatureAlgorithm: .ecdsaWithSHA256,
            certificate: Self.leaf1Cert,
            privateKey: Self.leaf1Key
        )

        // Change the version number to v3 everywhere
        var signedData = try CMSSignedData(asn1Any: cmsData.content)
        signedData.version = .v3
        signedData.signerInfos[0].version = .v3
        signedData.signerInfos[0].signerIdentifier = try .subjectKeyIdentifier(
            Self.leaf1Cert.extensions.subjectKeyIdentifier!
        )
        cmsData.content = try ASN1Any(erasing: signedData)

        let isValidSignature = try await CMS.isValidSignature(
            dataBytes: data,
            signatureBytes: cmsData.encodedBytes,
            trustRoots: CertificateStore([Self.rootCert])
        ) {}
        XCTAssertUnableToValidateSigner(isValidSignature)
    }

    func testCMSV4SignatureWithV1SignerInfo() async throws {
        let data: [UInt8] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
        var cmsData = try CMS.generateSignedTestData(
            data,
            signatureAlgorithm: .ecdsaWithSHA256,
            certificate: Self.leaf1Cert,
            privateKey: Self.leaf1Key
        )

        // Change the version number to v4
        var signedData = try CMSSignedData(asn1Any: cmsData.content)
        signedData.version = .v4
        cmsData.content = try ASN1Any(erasing: signedData)

        let isValidSignature = try await CMS.isValidSignature(
            dataBytes: data,
            signatureBytes: cmsData.encodedBytes,
            trustRoots: CertificateStore([Self.rootCert])
        ) {}
        XCTAssertUnableToValidateSigner(isValidSignature)
    }

    func testCMSV4SignatureWithV3SignerInfo() async throws {
        let data: [UInt8] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
        var cmsData = try CMS.generateSignedTestData(
            data,
            signatureAlgorithm: .ecdsaWithSHA256,
            certificate: Self.leaf1Cert,
            privateKey: Self.leaf1Key
        )

        // Change the version number to v4
        var signedData = try CMSSignedData(asn1Any: cmsData.content)
        signedData.version = .v4
        // change the signerInfo to v3
        signedData.signerInfos[0].version = .v3
        signedData.signerInfos[0].signerIdentifier = try .subjectKeyIdentifier(
            Self.leaf1Cert.extensions.subjectKeyIdentifier!
        )
        cmsData.content = try ASN1Any(erasing: signedData)

        let isValidSignature = try await CMS.isValidSignature(
            dataBytes: data,
            signatureBytes: cmsData.encodedBytes,
            trustRoots: CertificateStore([Self.rootCert])
        ) {}
        XCTAssertUnableToValidateSigner(isValidSignature)
    }

    func testCMSV4SignatureWithInvalidV3SignerInfo() async throws {
        let data: [UInt8] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
        var cmsData = try CMS.generateSignedTestData(
            data,
            signatureAlgorithm: .ecdsaWithSHA256,
            certificate: Self.leaf1Cert,
            privateKey: Self.leaf1Key
        )

        // Change the version number to v4
        var signedData = try CMSSignedData(asn1Any: cmsData.content)
        signedData.version = .v4
        // change the signerInfo to invalid v3
        signedData.signerInfos[0].version = .v3
        cmsData.content = try ASN1Any(erasing: signedData)

        let isValidSignature = try await CMS.isValidSignature(
            dataBytes: data,
            signatureBytes: cmsData.encodedBytes,
            trustRoots: CertificateStore([Self.rootCert])
        ) {}
        XCTAssertInvalidCMSBlock(isValidSignature)
    }

    func testCMSAttachedSignature() async throws {
        let data: [UInt8] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
        let cmsData = try CMS.generateSignedTestData(
            data,
            signatureAlgorithm: .ecdsaWithSHA256,
            certificate: Self.leaf1Cert,
            privateKey: Self.leaf1Key,
            detached: false
        )

        let isValidSignature = try await CMS.isValidAttachedSignature(
            signatureBytes: cmsData.encodedBytes,
            trustRoots: CertificateStore([Self.rootCert])
        ) {}
        XCTAssertUnableToValidateSigner(isValidSignature)
    }

    func testForbidsAdditionalSignerInfos() async throws {
        let data: [UInt8] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
        var cmsData = try CMS.generateSignedTestData(
            data,
            signatureAlgorithm: .ecdsaWithSHA256,
            certificate: Self.leaf1Cert,
            privateKey: Self.leaf1Key
        )

        // Add a second, identical, signer info. There's nothing invalid about this!
        var signedData = try CMSSignedData(asn1Any: cmsData.content)
        signedData.signerInfos.append(signedData.signerInfos[0])
        cmsData.content = try ASN1Any(erasing: signedData)

        let isValidSignature = try await CMS.isValidSignature(
            dataBytes: data,
            signatureBytes: cmsData.encodedBytes,
            trustRoots: CertificateStore([Self.rootCert])
        ) {}
        XCTAssertInvalidCMSBlock(isValidSignature)
    }

    func testRequireCMSDataTypeInEncapContent() async throws {
        let data: [UInt8] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
        var cmsData = try CMS.generateSignedTestData(
            data,
            signatureAlgorithm: .ecdsaWithSHA256,
            certificate: Self.leaf1Cert,
            privateKey: Self.leaf1Key
        )

        // This is a weird OID to use here, we just want to prove we reject it.
        var signedData = try CMSSignedData(asn1Any: cmsData.content)
        signedData.encapContentInfo.eContentType = .cmsSignedData
        cmsData.content = try ASN1Any(erasing: signedData)

        let isValidSignature = try await CMS.isValidSignature(
            dataBytes: data,
            signatureBytes: cmsData.encodedBytes,
            trustRoots: CertificateStore([Self.rootCert])
        ) {}
        XCTAssertInvalidCMSBlock(isValidSignature)
    }

    func testRequireAttachedSignature() async throws {
        let data: [UInt8] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
        let cmsData = try CMS.generateSignedTestData(
            data,
            signatureAlgorithm: .ecdsaWithSHA256,
            certificate: Self.leaf1Cert,
            privateKey: Self.leaf1Key,
            detached: true
        )

        let isValidSignature = try await CMS.isValidAttachedSignature(
            signatureBytes: cmsData.encodedBytes,
            trustRoots: CertificateStore([Self.rootCert])
        ) {}
        XCTAssertInvalidCMSBlock(isValidSignature)
    }

    func testRequireDetachedSignature() async throws {
        let data: [UInt8] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
        let cmsData = try CMS.generateSignedTestData(
            data,
            signatureAlgorithm: .ecdsaWithSHA256,
            certificate: Self.leaf1Cert,
            privateKey: Self.leaf1Key,
            detached: false
        )

        let isValidSignature = try await CMS.isValidSignature(
            dataBytes: data,
            signatureBytes: cmsData.encodedBytes,
            trustRoots: CertificateStore([Self.rootCert])
        ) {}
        XCTAssertInvalidCMSBlock(isValidSignature)
    }

    func testRequireValidDetachedSignatureWhenTolerated() async throws {
        let data: [UInt8] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
        var cmsData = try CMS.generateSignedTestData(
            data,
            signatureAlgorithm: .ecdsaWithSHA256,
            certificate: Self.leaf1Cert,
            privateKey: Self.leaf1Key
        )

        // Let's add data not matching the signature
        var signedData = try CMSSignedData(asn1Any: cmsData.content)
        signedData.encapContentInfo.eContent = ASN1OctetString(contentBytes: [0xba, 0xd])
        cmsData.content = try ASN1Any(erasing: signedData)

        let isValidSignature = try await CMS.isValidSignature(
            dataBytes: data,
            signatureBytes: cmsData.encodedBytes,
            trustRoots: CertificateStore([Self.rootCert]),
            allowAttachedContent: true
        ) {}
        XCTAssertInvalidCMSBlock(isValidSignature)
    }

    func testDigestAlgorithmsNotPresentInTheMainSetAreRejected() async throws {
        let data: [UInt8] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
        var cmsData = try CMS.generateSignedTestData(
            data,
            signatureAlgorithm: .ecdsaWithSHA256,
            certificate: Self.leaf1Cert,
            privateKey: Self.leaf1Key
        )

        // Let's add a few algorithms to the digest algorithms, none of which are what we actually used.
        var signedData = try CMSSignedData(asn1Any: cmsData.content)
        signedData.digestAlgorithms = [.sha1, .sha384UsingNil]
        cmsData.content = try ASN1Any(erasing: signedData)

        let isValidSignature = try await CMS.isValidSignature(
            dataBytes: data,
            signatureBytes: cmsData.encodedBytes,
            trustRoots: CertificateStore([Self.rootCert])
        ) {}
        XCTAssertInvalidCMSBlock(isValidSignature)
    }

    func testDigestAlgorithmAndSigningAlgorithmMismatch() async throws {
        let data: [UInt8] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
        var cmsData = try CMS.generateSignedTestData(
            data,
            signatureAlgorithm: .ecdsaWithSHA256,
            certificate: Self.leaf1Cert,
            privateKey: Self.leaf1Key
        )

        // This test confirms that if the data was hashed with a digest function other than the one implied by the
        // signature algorithm, we'll reject it.
        var signedData = try CMSSignedData(asn1Any: cmsData.content)
        signedData.digestAlgorithms = [.sha384UsingNil]
        signedData.signerInfos[0].digestAlgorithm = .sha384UsingNil
        cmsData.content = try ASN1Any(erasing: signedData)

        let isValidSignature = try await CMS.isValidSignature(
            dataBytes: data,
            signatureBytes: cmsData.encodedBytes,
            trustRoots: CertificateStore([Self.rootCert])
        ) {}
        XCTAssertInvalidCMSBlock(isValidSignature)
    }

    func testInvalidSignatureIsRejected() async throws {
        let data: [UInt8] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
        var cmsData = try CMS.generateSignedTestData(
            data,
            signatureAlgorithm: .ecdsaWithSHA256,
            certificate: Self.leaf1Cert,
            privateKey: Self.leaf1Key
        )

        // This test validates that invalid signatures cause validation failures.
        // Specifically, we'll produce a valid signature, with the wrong key.
        var signedData = try CMSSignedData(asn1Any: cmsData.content)
        signedData.signerInfos[0].signature = try ASN1OctetString(
            Self.rootCertKey.sign(bytes: data, signatureAlgorithm: .ecdsaWithSHA256)
        )
        cmsData.content = try ASN1Any(erasing: signedData)

        let isValidSignature = try await CMS.isValidSignature(
            dataBytes: data,
            signatureBytes: cmsData.encodedBytes,
            trustRoots: CertificateStore([Self.rootCert])
        ) {}
        XCTAssertInvalidCMSBlock(isValidSignature)
    }

    func testNotInsertingIntermediatesLeadsToCertValidationFailures() async throws {
        let data: [UInt8] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]

        let signature = try CMS.sign(
            data,
            signatureAlgorithm: .ecdsaWithSHA256,
            certificate: Self.leaf2Cert,
            privateKey: Self.leaf2Key
        )
        let isValidSignature = await CMS.isValidSignature(
            dataBytes: data,
            signatureBytes: signature,
            trustRoots: CertificateStore([Self.rootCert])
        ) {}
        XCTAssertUnableToValidateSigner(isValidSignature)
    }

    func testCanProvideIntermediatesDuringVerification() async throws {
        let data: [UInt8] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]

        let signature = try CMS.sign(
            data,
            signatureAlgorithm: .ecdsaWithSHA256,
            certificate: Self.leaf2Cert,
            privateKey: Self.leaf2Key
        )
        let isValidSignature = await CMS.isValidSignature(
            dataBytes: data,
            signatureBytes: signature,
            additionalIntermediateCertificates: [Self.intermediateCert],
            trustRoots: CertificateStore([Self.rootCert])
        ) {
            Self.defaultPolicies
        }
        XCTAssertValidSignature(isValidSignature)
    }

    func testCanProvideIntermediatesInSigningProcess() async throws {
        let data: [UInt8] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]

        let signature = try CMS.sign(
            data,
            signatureAlgorithm: .ecdsaWithSHA256,
            additionalIntermediateCertificates: [Self.intermediateCert],
            certificate: Self.leaf2Cert,
            privateKey: Self.leaf2Key
        )
        let isValidSignature = await CMS.isValidSignature(
            dataBytes: data,
            signatureBytes: signature,
            trustRoots: CertificateStore([Self.rootCert])
        ) {
            Self.defaultPolicies
        }
        XCTAssertValidSignature(isValidSignature)
    }

    func testDuplicateIntermediatesIsNotAnIssue() async throws {
        let data: [UInt8] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]

        let signature = try CMS.sign(
            data,
            signatureAlgorithm: .ecdsaWithSHA256,
            additionalIntermediateCertificates: [Self.intermediateCert],
            certificate: Self.leaf2Cert,
            privateKey: Self.leaf2Key
        )
        let isValidSignature = await CMS.isValidSignature(
            dataBytes: data,
            signatureBytes: signature,
            additionalIntermediateCertificates: [Self.intermediateCert],
            trustRoots: CertificateStore([Self.rootCert])
        ) {
            Self.defaultPolicies
        }
        XCTAssertValidSignature(isValidSignature)
    }

    func testSigningWithRSA() async throws {
        let data: [UInt8] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
        let signature = try CMS.sign(
            data,
            signatureAlgorithm: .sha256WithRSAEncryption,
            certificate: Self.rsaCert,
            privateKey: Self.rsaCertKey
        )
        let isValidSignature = await CMS.isValidSignature(
            dataBytes: data,
            signatureBytes: signature,
            trustRoots: CertificateStore([Self.rsaCert])
        ) {
            Self.defaultPolicies
        }
        XCTAssertValidSignature(isValidSignature)
    }

    func testSigningWithEd25519() async throws {
        let data: [UInt8] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
        let signature = try CMS.sign(
            data,
            signatureAlgorithm: .ed25519,
            certificate: Self.ed25519Cert,
            privateKey: Self.ed25519CertKey
        )
        let isValidSignature = await CMS.isValidSignature(
            dataBytes: data,
            signatureBytes: signature,
            trustRoots: CertificateStore([Self.ed25519Cert])
        ) {
            Self.defaultPolicies
        }
        XCTAssertValidSignature(isValidSignature)
    }

    func testSigningWithSigningTimeSignedAttr() async throws {
        let data: [UInt8] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
        let signature = try CMS.sign(
            data,
            signatureAlgorithm: .ecdsaWithSHA256,
            certificate: Self.leaf1Cert,
            privateKey: Self.leaf1Key,
            signingTime: Date()
        )
        let isValidSignature = await CMS.isValidSignature(
            dataBytes: data,
            signatureBytes: signature,
            trustRoots: CertificateStore([Self.rootCert])
        ) {
            Self.defaultPolicies
        }
        XCTAssertValidSignature(isValidSignature)
    }

    func testSigningWithSigningTimeSignedAttrAndSHA512() async throws {
        let data: [UInt8] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
        let signature = try CMS.sign(
            data,
            signatureAlgorithm: .ecdsaWithSHA512,
            certificate: Self.leaf1Cert,
            privateKey: Self.leaf1Key,
            signingTime: Date()
        )
        let isValidSignature = await CMS.isValidSignature(
            dataBytes: data,
            signatureBytes: signature,
            trustRoots: CertificateStore([Self.rootCert])
        ) {
            Self.defaultPolicies
        }
        XCTAssertValidSignature(isValidSignature)
    }

    func testSigningWithSigningTimeSignedAttrAndIntermediates() async throws {
        let data: [UInt8] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
        let signature = try CMS.sign(
            data,
            signatureAlgorithm: .ecdsaWithSHA256,
            additionalIntermediateCertificates: [Self.intermediateCert],
            certificate: Self.leaf2Cert,
            privateKey: Self.leaf2Key,
            signingTime: Date()
        )
        let isValidSignature = await CMS.isValidSignature(
            dataBytes: data,
            signatureBytes: signature,
            trustRoots: CertificateStore([Self.rootCert])
        ) {
            Self.defaultPolicies
        }
        XCTAssertValidSignature(isValidSignature)
    }

    func testSigningAttachedWithSigningTimeSignedAttr() async throws {
        let data: [UInt8] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
        let signature = try CMS.sign(
            data,
            signatureAlgorithm: .ecdsaWithSHA256,
            certificate: Self.leaf1Cert,
            privateKey: Self.leaf1Key,
            signingTime: Date(),
            detached: false
        )
        let isValidSignature = await CMS.isValidSignature(
            dataBytes: data,
            signatureBytes: signature,
            trustRoots: CertificateStore([Self.rootCert]),
            allowAttachedContent: true
        ) {
            Self.defaultPolicies
        }
        XCTAssertValidSignature(isValidSignature)
    }

    func testToleratesAttachedSignatureWithSigningTimeSignedAttrVerifyingAsDetached() async throws {
        let data: [UInt8] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
        let signature = try CMS.sign(
            data,
            signatureAlgorithm: .ecdsaWithSHA256,
            certificate: Self.leaf1Cert,
            privateKey: Self.leaf1Key,
            signingTime: Date(),
            detached: false
        )
        let isValidDetachedSignature = await CMS.isValidSignature(
            dataBytes: data,
            signatureBytes: signature,
            trustRoots: CertificateStore([Self.rootCert]),
            allowAttachedContent: true
        ) {
            Self.defaultPolicies
        }
        XCTAssertValidSignature(isValidDetachedSignature)
    }

    func testForbidsDetachedSignatureWithSigningTimeSignedAttrVerifyingAsAttached() async throws {
        let data: [UInt8] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
        let signature = try CMS.sign(
            data,
            signatureAlgorithm: .ecdsaWithSHA256,
            certificate: Self.leaf1Cert,
            privateKey: Self.leaf1Key,
            signingTime: Date(),
            detached: true
        )
        let isValidAttachedSignature = await CMS.isValidAttachedSignature(
            signatureBytes: signature,
            trustRoots: CertificateStore([Self.rootCert])
        ) {
            Self.defaultPolicies
        }
        XCTAssertInvalidCMSBlock(isValidAttachedSignature)
    }

    func testSigningContentBytesWithSigningTimeSignedAttrsIsInvalidSignature() async throws {
        let data: [UInt8] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]

        let contentInfo = try CMS.generateInvalidSignedTestDataWithSignedAttrs(
            data,
            signatureAlgorithm: .ecdsaWithSHA256,
            certificate: Self.leaf1Cert,
            privateKey: Self.leaf1Key
        )

        let signature = try contentInfo.signedData!.encodedBytes

        let isValidSignature = await CMS.isValidSignature(
            dataBytes: data,
            signatureBytes: signature,
            trustRoots: CertificateStore([Self.rootCert])
        ) {
            Self.defaultPolicies
        }
        XCTAssertInvalidCMSBlock(isValidSignature)
    }

    func testSubjectKeyIdentifierIsCorrectlyImplicitylyTagged() throws {
        let implicitlyTaggedSki: [UInt8] = [
            0x80,  // Context-specific tag [0]
            0x04,  // Length
            0x0a, 0x14, 0x1e, 0x28,
        ]

        XCTAssertEqual(
            try CMSSignerIdentifier(derEncoded: implicitlyTaggedSki),
            CMSSignerIdentifier.subjectKeyIdentifier(.init(keyIdentifier: [10, 20, 30, 40]))
        )
    }

    func testDefaultRSASignatureAlgorithm() throws {
        let privateKey = try Certificate.PrivateKey(_RSA.Signing.PrivateKey(keySize: .bits2048))
        let signerInfo = try self.signAndExtractSignerInfo(privateKey: privateKey)
        XCTAssertEqual(signerInfo?.signatureAlgorithm.description, "sha256WithRSAEncryption")
    }

    func testDefaultP256SignatureAlgorithm() throws {
        let privateKey = Certificate.PrivateKey(P256.Signing.PrivateKey())
        let signerInfo = try self.signAndExtractSignerInfo(privateKey: privateKey)
        XCTAssertEqual(signerInfo?.signatureAlgorithm.description, "ecdsaWithSHA256")
    }

    func testDefaultP384SignatureAlgorithm() throws {
        let privateKey = Certificate.PrivateKey(P384.Signing.PrivateKey())
        let signerInfo = try self.signAndExtractSignerInfo(privateKey: privateKey)
        XCTAssertEqual(signerInfo?.signatureAlgorithm.description, "ecdsaWithSHA384")
    }

    func testDefaultP521SignatureAlgorithm() throws {
        let privateKey = Certificate.PrivateKey(P521.Signing.PrivateKey())
        let signerInfo = try self.signAndExtractSignerInfo(privateKey: privateKey)
        XCTAssertEqual(signerInfo?.signatureAlgorithm.description, "ecdsaWithSHA512")
    }

    func testDefaultEd25519SignatureAlgorithm() throws {
        let privateKey = Certificate.PrivateKey(Curve25519.Signing.PrivateKey())
        let signerInfo = try self.signAndExtractSignerInfo(privateKey: privateKey)
        XCTAssertEqual(signerInfo?.signatureAlgorithm.description, "ed25519")
    }

    private func signAndExtractSignerInfo(privateKey: Certificate.PrivateKey) throws -> CMSSignerInfo? {
        let name = try DistinguishedName { CommonName("test") }
        let certificate = try Certificate(
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
        let data: [UInt8] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
        let signatureBytes = try CMS.sign(data, certificate: certificate, privateKey: privateKey)
        let contentInfo = try CMSContentInfo(derEncoded: signatureBytes)
        return try contentInfo.signedData?.signerInfos.first
    }

    @available(*, deprecated, message: "testing that deprecated initializer and new initialize work as expected")
    func testSignerValidationFailureInitializerDeprecation() throws {
        // Generate input data.
        let privateKey = Certificate.PrivateKey(Curve25519.Signing.PrivateKey())
        let name = try DistinguishedName { CommonName("test") }
        let certificate = try Certificate(
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
        let unverifiedCertificateChain = UnverifiedCertificateChain([certificate])
        let policyFailureReason = PolicyFailureReason("not a real failure")
        let otherPolicyFailureReason = PolicyFailureReason("not a real failure, but different")

        // Create policy failures and check their conversion.
        let policyFailureDeprecated1 = VerificationResult.PolicyFailure(
            chain: unverifiedCertificateChain,
            policyFailureReason: policyFailureReason
        )
        let policyFailure1 = CertificateValidationResult.PolicyFailure(
            chain: unverifiedCertificateChain,
            policyFailureReason: policyFailureReason
        )
        XCTAssertEqual(policyFailureDeprecated1.upgrade(), policyFailure1)
        XCTAssertEqual(policyFailureDeprecated1, VerificationResult.PolicyFailure(policyFailure1))

        // Create SignerValidationFailure with both constructors and check that they result in the same data.
        let usingDeprecatedConstructor = CMS.VerificationError.SignerValidationFailure(
            validationFailures: [policyFailureDeprecated1],
            signer: certificate
        )
        var usingNewConstructor = CMS.VerificationError.SignerValidationFailure(
            validationFailures: [policyFailure1],
            signer: certificate
        )
        XCTAssertEqual(usingDeprecatedConstructor.validationFailures, usingNewConstructor.validationFailures)
        XCTAssertEqual(usingDeprecatedConstructor.policyFailures, usingNewConstructor.policyFailures)
        XCTAssertEqual(usingDeprecatedConstructor.signer, usingNewConstructor.signer)

        // Create PolicyFailures that differ from our previous failures.
        let policyFailure2 = CertificateValidationResult.PolicyFailure(
            chain: unverifiedCertificateChain,
            policyFailureReason: otherPolicyFailureReason
        )
        let policyFailureDeprecated2 = VerificationResult.PolicyFailure(
            chain: unverifiedCertificateChain,
            policyFailureReason: otherPolicyFailureReason
        )
        XCTAssertNotEqual(policyFailure1, policyFailure2)
        XCTAssertNotEqual(policyFailureDeprecated1, policyFailureDeprecated2)

        // Verify that different values override the old ones.
        usingNewConstructor.validationFailures = [policyFailureDeprecated2]
        XCTAssertNotEqual(usingNewConstructor.policyFailures, [policyFailure1])
        XCTAssertEqual(usingNewConstructor.policyFailures, [policyFailure2])
        // We can assign the same data to make them equal again.
        usingNewConstructor.validationFailures = [policyFailureDeprecated1]
        XCTAssertEqual(usingNewConstructor.policyFailures, [policyFailure1])
        XCTAssertNotEqual(usingNewConstructor.policyFailures, [policyFailure2])
        // And the other way around.
        usingNewConstructor.policyFailures = [policyFailure2]
        XCTAssertEqual(usingNewConstructor.validationFailures, [policyFailureDeprecated2])
        XCTAssertNotEqual(usingNewConstructor.validationFailures, [policyFailureDeprecated1])
    }
}

extension DERSerializable {
    fileprivate var encodedBytes: [UInt8] {
        get throws {
            var serializer = DER.Serializer()
            try serializer.serialize(self)
            return serializer.serializedBytes
        }
    }
}

extension Array where Element: Equatable {
    fileprivate func containsSubsequence(_ subsequence: [Element]) -> Bool {
        guard !subsequence.isEmpty, self.count >= subsequence.count else {
            return subsequence.isEmpty
        }

        for index in self.indices where self[index] == subsequence[0] {
            let endIndex = self.index(index, offsetBy: subsequence.count, limitedBy: self.endIndex)
            guard let endIndex else {
                continue
            }
            if Array(self[index..<endIndex]) == subsequence {
                return true
            }
        }

        return false
    }
}

private func XCTAssertValidSignature(
    _ result: CMS.SignatureVerificationResult,
    file: StaticString = #filePath,
    line: UInt = #line
) {
    guard case .success = result else {
        XCTFail("Expected valid signature, got \(result)", file: file, line: line)
        return
    }
}

private func XCTAssertInvalidCMSBlock(
    _ result: CMS.SignatureVerificationResult,
    file: StaticString = #filePath,
    line: UInt = #line
) {
    guard case .failure(.invalidCMSBlock) = result else {
        XCTFail("Expected invalid CMS Block, got \(result)", file: file, line: line)
        return
    }
}

private func XCTAssertUnableToValidateSigner(
    _ result: CMS.SignatureVerificationResult,
    file: StaticString = #filePath,
    line: UInt = #line
) {
    guard case .failure(.unableToValidateSigner) = result else {
        XCTFail("Expected unable to validate signer, got \(result)", file: file, line: line)
        return
    }
}

extension CMS {
    static func generateSignedTestData<Bytes: DataProtocol>(
        _ bytes: Bytes,
        signatureAlgorithm: Certificate.SignatureAlgorithm,
        additionalIntermediateCertificates: [Certificate] = [],
        certificate: Certificate,
        privateKey: Certificate.PrivateKey,
        detached: Bool = true
    ) throws -> CMSContentInfo {
        let signature = try privateKey.sign(bytes: bytes, signatureAlgorithm: signatureAlgorithm)
        return try generateSignedData(
            signatureBytes: ASN1OctetString(signature),
            signatureAlgorithm: signatureAlgorithm,
            additionalIntermediateCertificates: additionalIntermediateCertificates,
            certificate: certificate,
            withContent: detached ? nil : bytes
        )
    }
    static func generateInvalidSignedTestDataWithSignedAttrs<Bytes: DataProtocol>(
        _ bytes: Bytes,
        signatureAlgorithm: Certificate.SignatureAlgorithm,
        additionalIntermediateCertificates: [Certificate] = [],
        certificate: Certificate,
        privateKey: Certificate.PrivateKey
    ) throws -> CMSContentInfo {
        // Sign the content bytes but include signedAttrs for the signerInfo. This should be invalid accorindg to RFC 5652 section 5.4 which specifies:

        // When the [signedAttrs] field is present, however, the result is the message
        // digest of the complete DER encoding of the SignedAttrs value
        // contained in the signedAttrs field.
        let signature = try privateKey.sign(bytes: bytes, signatureAlgorithm: signatureAlgorithm)

        var signedAttrs: [CMSAttribute] = []
        // As specified in RFC 5652 section 11 when including signedAttrs we need to include a minimum of:
        // 1. content-type
        // 2. message-digest

        // add content-type signedAttr cms data
        let contentTypeVal = try ASN1Any(erasing: ASN1ObjectIdentifier.cmsData)
        let contentTypeAttribute = CMSAttribute(attrType: .contentType, attrValues: [contentTypeVal])
        signedAttrs.append(contentTypeAttribute)

        // add message-digest sha256 of provided content bytes
        let computedDigest = SHA256.hash(data: bytes)
        let messageDigest = ASN1OctetString(contentBytes: ArraySlice(computedDigest))
        let messageDigestVal = try ASN1Any(erasing: messageDigest)
        let messageDigestAttr = CMSAttribute(attrType: .messageDigest, attrValues: [messageDigestVal])
        signedAttrs.append(messageDigestAttr)

        // add signing time utc time in 'YYMMDDHHMMSSZ' format as specificed in `UTCTime`
        let utcTime = try UTCTime(Date().utcDate)
        let signingTimeAttrVal = try ASN1Any(erasing: utcTime)
        let signingTimeAttribute = CMSAttribute(attrType: .signingTime, attrValues: [signingTimeAttrVal])
        signedAttrs.append(signingTimeAttribute)

        return try generateSignedData(
            signatureBytes: ASN1OctetString(signature),
            signatureAlgorithm: signatureAlgorithm,
            additionalIntermediateCertificates: additionalIntermediateCertificates,
            certificate: certificate,
            signedAttrs: signedAttrs,
            withContent: nil as Data?
        )
    }
}
