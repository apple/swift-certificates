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

import Foundation
import XCTest
import Crypto
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

    static var defaultPolicies: PolicySet {
        PolicySet(policies: [RFC5280Policy(validationTime: Date())])
    }

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

    func testSimpleSigningVerifying() async throws {
        let data: [UInt8] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]

        let signature = try CMS.sign(data, signatureAlgorithm: .ecdsaWithSHA256, certificate: Self.leaf1Cert, privateKey: Self.leaf1Key)
        let isValidSignature = await CMS.isValidSignature(dataBytes: data, signatureBytes: signature, trustRoots: CertificateStore([Self.rootCert])) { Self.defaultPolicies }
        XCTAssertValidSignature(isValidSignature)
    }

    func testParsingSimpleSignature() async throws {
        let data: [UInt8] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]

        let signatureBytes = try CMS.sign(data, signatureAlgorithm: .ecdsaWithSHA256, certificate: Self.leaf1Cert, privateKey: Self.leaf1Key)
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
        var cmsData = try CMS.generateSignedTestData(data, signatureAlgorithm: .ecdsaWithSHA256, certificate: Self.leaf1Cert, privateKey: Self.leaf1Key)

        // Add a second, identical, signer info.
        var signedData = try CMSSignedData(asn1Any: cmsData.content)
        signedData.signerInfos.append(signedData.signerInfos[0])
        cmsData.content = try ASN1Any(erasing: signedData)

        let signature = try CMSSignature(derEncoded: cmsData.encodedBytes)
        XCTAssertEqual(try signature.signers, [CMSSignature.Signer(certificate: Self.leaf1Cert), CMSSignature.Signer(certificate: Self.leaf1Cert)])
        XCTAssertEqual(signature.certificates, [Self.leaf1Cert])

        XCTAssertEqual(try cmsData.encodedBytes, try signature.encodedBytes)
    }

    func testRequireCMSV1SignatureOnCMSSignatureType() async throws {
        let data: [UInt8] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
        var cmsData = try CMS.generateSignedTestData(data, signatureAlgorithm: .ecdsaWithSHA256, certificate: Self.leaf1Cert, privateKey: Self.leaf1Key)

        // Change the version number to v3 in both places.
        var signedData = try CMSSignedData(asn1Any: cmsData.content)
        signedData.version = .v3
        cmsData.content = try ASN1Any(erasing: signedData)

        XCTAssertThrowsError(try CMSSignature(derEncoded: cmsData.encodedBytes))
    }

    func testRejectsSignatureWithoutRoot() async throws {
        let data: [UInt8] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]

        let signature = try CMS.sign(data, signatureAlgorithm: .ecdsaWithSHA256, certificate: Self.leaf1Cert, privateKey: Self.leaf1Key)
        let isValidSignature = await CMS.isValidSignature(dataBytes: data, signatureBytes: signature, trustRoots: CertificateStore([Self.secondRootCert])) { }
        XCTAssertUnableToValidateSigner(isValidSignature)
    }

    func testPoliciesAreApplied() async throws {
        final class RejectAllPolicy: VerifierPolicy {
            let verifyingCriticalExtensions: [ASN1ObjectIdentifier] = []
            
            func chainMeetsPolicyRequirements(chain: X509.UnverifiedCertificateChain) async -> X509.PolicyEvaluationResult {
                return .failsToMeetPolicy(reason: "all chains are forbidden")
            }
        }

        let data: [UInt8] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]

        let signature = try CMS.sign(data, signatureAlgorithm: .ecdsaWithSHA256, certificate: Self.leaf1Cert, privateKey: Self.leaf1Key)
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
        var cmsData = try CMS.generateSignedTestData(data, signatureAlgorithm: .ecdsaWithSHA256, certificate: Self.leaf1Cert, privateKey: Self.leaf1Key)

        // This is a meaningless OID to use here, I just want to use something I know we don't support.
        cmsData.contentType = .sha256NoSign
        let isValidSignature = try await CMS.isValidSignature(
            dataBytes: data,
            signatureBytes: cmsData.encodedBytes,
            trustRoots: CertificateStore([Self.rootCert])
        ) { }
        XCTAssertInvalidCMSBlock(isValidSignature)
    }

    func testRequireCMSV1Signature() async throws {
        let data: [UInt8] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
        var cmsData = try CMS.generateSignedTestData(data, signatureAlgorithm: .ecdsaWithSHA256, certificate: Self.leaf1Cert, privateKey: Self.leaf1Key)

        // Change the version number to v3 in both places.
        var signedData = try CMSSignedData(asn1Any: cmsData.content)
        signedData.version = .v3
        signedData.signerInfos[0].version = .v3
        cmsData.content = try ASN1Any(erasing: signedData)

        let isValidSignature = try await CMS.isValidSignature(
            dataBytes: data,
            signatureBytes: cmsData.encodedBytes,
            trustRoots: CertificateStore([Self.rootCert])
        ) { }
        XCTAssertInvalidCMSBlock(isValidSignature)
    }

    func testRequireCMSV1SignatureEvenOnTheSignerInfo() async throws {
        let data: [UInt8] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
        var cmsData = try CMS.generateSignedTestData(data, signatureAlgorithm: .ecdsaWithSHA256, certificate: Self.leaf1Cert, privateKey: Self.leaf1Key)

        // Change the version number to v3, but only in the signer info.
        var signedData = try CMSSignedData(asn1Any: cmsData.content)
        signedData.signerInfos[0].version = .v3
        cmsData.content = try ASN1Any(erasing: signedData)

        let isValidSignature = try await CMS.isValidSignature(
            dataBytes: data,
            signatureBytes: cmsData.encodedBytes,
            trustRoots: CertificateStore([Self.rootCert])
        ) { }
        XCTAssertInvalidCMSBlock(isValidSignature)
    }

    func testRequireCMSV1SignatureEvenWhenV3IsCorrectlyAttestedOnSignerInfo() async throws {
        let data: [UInt8] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
        var cmsData = try CMS.generateSignedTestData(data, signatureAlgorithm: .ecdsaWithSHA256, certificate: Self.leaf1Cert, privateKey: Self.leaf1Key)

        // Change the version number to v3, but only in the signer info.
        var signedData = try CMSSignedData(asn1Any: cmsData.content)
        signedData.signerInfos[0].version = .v3
        signedData.signerInfos[0].signerIdentifier = try .subjectKeyIdentifier(Self.leaf1Cert.extensions.subjectKeyIdentifier!)
        cmsData.content = try ASN1Any(erasing: signedData)

        let isValidSignature = try await CMS.isValidSignature(
            dataBytes: data,
            signatureBytes: cmsData.encodedBytes,
            trustRoots: CertificateStore([Self.rootCert])
        ) { }
        XCTAssertInvalidCMSBlock(isValidSignature)
    }

    func testForbidsAdditionalSignerInfos() async throws {
        let data: [UInt8] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
        var cmsData = try CMS.generateSignedTestData(data, signatureAlgorithm: .ecdsaWithSHA256, certificate: Self.leaf1Cert, privateKey: Self.leaf1Key)

        // Add a second, identical, signer info. There's nothing invalid about this!
        var signedData = try CMSSignedData(asn1Any: cmsData.content)
        signedData.signerInfos.append(signedData.signerInfos[0])
        cmsData.content = try ASN1Any(erasing: signedData)

        let isValidSignature = try await CMS.isValidSignature(
            dataBytes: data,
            signatureBytes: cmsData.encodedBytes,
            trustRoots: CertificateStore([Self.rootCert])
        ) { }
        XCTAssertInvalidCMSBlock(isValidSignature)
    }

    func testRequireCMSDataTypeInEncapContent() async throws {
        let data: [UInt8] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
        var cmsData = try CMS.generateSignedTestData(data, signatureAlgorithm: .ecdsaWithSHA256, certificate: Self.leaf1Cert, privateKey: Self.leaf1Key)

        // This is a weird OID to use here, we just want to prove we reject it.
        var signedData = try CMSSignedData(asn1Any: cmsData.content)
        signedData.encapContentInfo.eContentType = .cmsSignedData
        cmsData.content = try ASN1Any(erasing: signedData)

        let isValidSignature = try await CMS.isValidSignature(
            dataBytes: data,
            signatureBytes: cmsData.encodedBytes,
            trustRoots: CertificateStore([Self.rootCert])
        ) { }
        XCTAssertInvalidCMSBlock(isValidSignature)
    }

    func testRequireDetachedSignature() async throws {
        let data: [UInt8] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
        var cmsData = try CMS.generateSignedTestData(data, signatureAlgorithm: .ecdsaWithSHA256, certificate: Self.leaf1Cert, privateKey: Self.leaf1Key)

        // Let's add the signed data in here!
        var signedData = try CMSSignedData(asn1Any: cmsData.content)
        signedData.encapContentInfo.eContent = ASN1OctetString(contentBytes: data[...])
        cmsData.content = try ASN1Any(erasing: signedData)

        let isValidSignature = try await CMS.isValidSignature(
            dataBytes: data,
            signatureBytes: cmsData.encodedBytes,
            trustRoots: CertificateStore([Self.rootCert])
        ) { }
        XCTAssertInvalidCMSBlock(isValidSignature)
    }

    func testDigestAlgorithmsNotPresentInTheMainSetAreRejected() async throws {
        let data: [UInt8] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
        var cmsData = try CMS.generateSignedTestData(data, signatureAlgorithm: .ecdsaWithSHA256, certificate: Self.leaf1Cert, privateKey: Self.leaf1Key)

        // Let's add a few algorithms to the digest algorithms, none of which are what we actually used.
        var signedData = try CMSSignedData(asn1Any: cmsData.content)
        signedData.digestAlgorithms = [.sha1, .sha384UsingNil]
        cmsData.content = try ASN1Any(erasing: signedData)

        let isValidSignature = try await CMS.isValidSignature(
            dataBytes: data,
            signatureBytes: cmsData.encodedBytes,
            trustRoots: CertificateStore([Self.rootCert])
        ) { }
        XCTAssertInvalidCMSBlock(isValidSignature)
    }

    func testDigestAlgorithmAndSigningAlgorithmMismatch() async throws {
        let data: [UInt8] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
        var cmsData = try CMS.generateSignedTestData(data, signatureAlgorithm: .ecdsaWithSHA256, certificate: Self.leaf1Cert, privateKey: Self.leaf1Key)

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
        ) { }
        XCTAssertInvalidCMSBlock(isValidSignature)
    }

    func testInvalidSignatureIsRejected() async throws {
        let data: [UInt8] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]
        var cmsData = try CMS.generateSignedTestData(data, signatureAlgorithm: .ecdsaWithSHA256, certificate: Self.leaf1Cert, privateKey: Self.leaf1Key)

        // This test validates that invalid signatures cause validation failures.
        // Specifically, we'll produce a valid signature, with the wrong key.
        var signedData = try CMSSignedData(asn1Any: cmsData.content)
        signedData.signerInfos[0].signature = try ASN1OctetString(Self.rootCertKey.sign(bytes: data, signatureAlgorithm: .ecdsaWithSHA256))
        cmsData.content = try ASN1Any(erasing: signedData)

        let isValidSignature = try await CMS.isValidSignature(
            dataBytes: data,
            signatureBytes: cmsData.encodedBytes,
            trustRoots: CertificateStore([Self.rootCert])
        ) { }
        XCTAssertInvalidCMSBlock(isValidSignature)
    }

    func testNotInsertingIntermediatesLeadsToCertValidationFailures() async throws {
        let data: [UInt8] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]

        let signature = try CMS.sign(data, signatureAlgorithm: .ecdsaWithSHA256, certificate: Self.leaf2Cert, privateKey: Self.leaf2Key)
        let isValidSignature = await CMS.isValidSignature(dataBytes: data, signatureBytes: signature, trustRoots: CertificateStore([Self.rootCert])) { }
        XCTAssertUnableToValidateSigner(isValidSignature)
    }

    func testCanProvideIntermediatesDuringVerification() async throws {
        let data: [UInt8] = [0, 1, 2, 3, 4, 5, 6, 7, 8, 9]

        let signature = try CMS.sign(data, signatureAlgorithm: .ecdsaWithSHA256, certificate: Self.leaf2Cert, privateKey: Self.leaf2Key)
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

fileprivate func XCTAssertValidSignature(_ result: CMS.SignatureVerificationResult, file: StaticString = #file, line: UInt = #line) {
    guard case .success = result else {
        XCTFail("Expected valid signature, got \(result)", file: file, line: line)
        return
    }
}

fileprivate func XCTAssertInvalidCMSBlock(_ result: CMS.SignatureVerificationResult, file: StaticString = #file, line: UInt = #line) {
    guard case .failure(.invalidCMSBlock) = result else {
        XCTFail("Expected invalid CMS Block, got \(result)", file: file, line: line)
        return
    }
}

fileprivate func XCTAssertUnableToValidateSigner(_ result: CMS.SignatureVerificationResult, file: StaticString = #file, line: UInt = #line) {
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
        privateKey: Certificate.PrivateKey
    ) throws -> CMSContentInfo {
        let signature = try privateKey.sign(bytes: bytes, signatureAlgorithm: signatureAlgorithm)
        return try generateSignedData(
            signatureBytes: ASN1OctetString(signature),
            signatureAlgorithm: signatureAlgorithm,
            additionalIntermediateCertificates: additionalIntermediateCertificates,
            certificate: certificate
        )
    }
}
