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
import Crypto
import SwiftASN1
@testable import X509

final class CMSTests: XCTestCase {
    private func assertRoundTrips<ASN1Object: DERParseable & DERSerializable & Equatable>(_ value: ASN1Object) throws {
        var serializer = DER.Serializer()
        try serializer.serialize(value)
        let parsed = try ASN1Object(derEncoded: serializer.serializedBytes)
        XCTAssertEqual(parsed, value)
    }
    
    func testIssuerAndSerialNumber() throws {
        try assertRoundTrips(CMSIssuerAndSerialNumber(issuer: .init {
            CountryName("US")
            OrganizationName("Apple Inc.")
            CommonName("Apple Public EV Server ECC CA 1 - G1")
        }, serialNumber: .init(bytes: [10, 20, 30, 40])))
    }
    func testSignerIdentifier() throws {
        try assertRoundTrips(
            CMSSignerIdentifier.issuerAndSerialNumber(.init(issuer: .init {
                CountryName("US")
                OrganizationName("Apple Inc.")
                CommonName("Apple Public EV Server ECC CA 1 - G1")
            }, serialNumber: .init(bytes: [20, 30, 40, 50])))
        )
        try assertRoundTrips(
            CMSSignerIdentifier.subjectKeyIdentifier(.init(keyIdentifier: [10, 20, 30, 40]))
        )
    }
    func testCMSSignerInfo() throws {
        try assertRoundTrips(CMSSignerInfo(
            version: .v1,
            signerIdentifier: .issuerAndSerialNumber(.init(
                issuer: .init {
                    CountryName("US")
                    OrganizationName("Apple Inc.")
                    CommonName("Apple Public EV Server ECC CA 1 - G1")
                },
                serialNumber: .init(bytes: [20, 30, 40, 50])
            )),
            digestAlgorithm: .sha256WithRSAEncryptionUsingNil,
            signatureAlgorithm: .ecdsaWithSHA256,
            signature: .init(contentBytes: [100, 110, 120, 130, 140])
        ))
        
        try assertRoundTrips(CMSSignerInfo(
            version: .v3,
            signerIdentifier: .subjectKeyIdentifier(.init(keyIdentifier: [10, 20, 30, 40])),
            digestAlgorithm: .sha256WithRSAEncryptionUsingNil,
            signatureAlgorithm: .ecdsaWithSHA256,
            signature: .init(contentBytes: [100, 110, 120, 130, 140])
        ))
        
        XCTAssertThrowsError(try assertRoundTrips(CMSSignerInfo(
            version: .v3,
            signerIdentifier: .issuerAndSerialNumber(.init(
                issuer: .init {
                    CountryName("US")
                    OrganizationName("Apple Inc.")
                    CommonName("Apple Public EV Server ECC CA 1 - G1")
                },
                serialNumber: .init(bytes: [20, 30, 40, 50])
            )),
            digestAlgorithm: .sha256WithRSAEncryptionUsingNil,
            signatureAlgorithm: .ecdsaWithSHA256,
            signature: .init(contentBytes: [100, 110, 120, 130, 140])
        )), "unexpected signerIdentifier for version should throw")
        
        XCTAssertThrowsError(try assertRoundTrips(CMSSignerInfo(
            version: .v1,
            signerIdentifier: .subjectKeyIdentifier(.init(keyIdentifier: [10, 20, 30, 40])),
            digestAlgorithm: .sha256WithRSAEncryptionUsingNil,
            signatureAlgorithm: .ecdsaWithSHA256,
            signature: .init(contentBytes: [100, 110, 120, 130, 140])
        )), "unexpected signerIdentifier for version should throw")
    }
    func testEncapsulatedContentInfo() throws {
        try assertRoundTrips(CMSEncapsulatedContentInfo(
            eContentType: [1, 2, 3, 4],
            eContent: .init(contentBytes: [5, 6, 7, 8])
        ))
        try assertRoundTrips(CMSEncapsulatedContentInfo(
            eContentType: [1, 2, 3, 4],
            eContent: nil
        ))
    }
    func testSignedData() throws {
        try assertRoundTrips(CMSSignedData(
            version: .v1,
            digestAlgorithms: [],
            encapContentInfo: .init(eContentType: [1, 2, 3, 4]),
            certificates: nil,
            signerInfos: []
        ))
        try assertRoundTrips(CMSSignedData(
            version: .v1,
            digestAlgorithms: [.sha256WithRSAEncryptionUsingNil],
            encapContentInfo: .init(eContentType: [1, 2, 3, 4]),
            certificates: [],
            signerInfos: []
        ))
        try assertRoundTrips(CMSSignedData(
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
        ))
        
        let privateKey = P384.Signing.PrivateKey()
        try assertRoundTrips(CMSSignedData(
            version: .v1,
            digestAlgorithms: [
                .sha256WithRSAEncryptionUsingNil
            ],
            encapContentInfo: .init(eContentType: [1, 2, 3, 4]),
            certificates: [Certificate(
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
            )],
            signerInfos: []
        ))
    }
    
    func testContentInfo() throws {
        let privateKey = P384.Signing.PrivateKey()
        try assertRoundTrips(CMSContentInfo(CMSSignedData(
            version: .v1,
            digestAlgorithms: [
                .sha256WithRSAEncryptionUsingNil
            ],
            encapContentInfo: .init(eContentType: [1, 2, 3, 4]),
            certificates: [Certificate(
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
            )],
            signerInfos: []
        )))
    }
}
