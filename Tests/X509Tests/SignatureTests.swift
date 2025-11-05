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
@preconcurrency import Crypto
import _CryptoExtras
import SwiftASN1
@testable import X509
#if canImport(Darwin)
@preconcurrency import Security
#endif

final class SignatureTests: XCTestCase {
    static let now = Date()
    static let oneYearFromNow = {
        now + (60 * 60 * 24 * 365)
    }()
    static let p256Key = P256.Signing.PrivateKey()
    static let p384Key = P384.Signing.PrivateKey()
    static let p521Key = P521.Signing.PrivateKey()
    static let rsaKey = try! _RSA.Signing.PrivateKey(keySize: .bits2048)
    static let ed25519Key = Curve25519.Signing.PrivateKey()
    #if canImport(Darwin)
    static let secureEnclaveP256 = try? SecureEnclave.P256.Signing.PrivateKey()
    static let secKeyRSA = try? generateSecKey(keyType: kSecAttrKeyTypeRSA, keySize: 2048, useSEP: false)
    static let secKeyEC256 = try? generateSecKey(keyType: kSecAttrKeyTypeECSECPrimeRandom, keySize: 256, useSEP: false)
    static let secKeyEC384 = try? generateSecKey(keyType: kSecAttrKeyTypeECSECPrimeRandom, keySize: 384, useSEP: false)
    static let secKeyEC521 = try? generateSecKey(keyType: kSecAttrKeyTypeECSECPrimeRandom, keySize: 521, useSEP: false)
    // SEP currently supports 256 and 384 bit EC keys
    static let secKeyEnclaveEC256 = try? generateSecKey(
        keyType: kSecAttrKeyTypeECSECPrimeRandom,
        keySize: 256,
        useSEP: true
    )
    static let secKeyEnclaveEC384 = try? generateSecKey(
        keyType: kSecAttrKeyTypeECSECPrimeRandom,
        keySize: 384,
        useSEP: true
    )
    #endif

    func testRSASignatureBytes() throws {
        let input = Array("Hello World".utf8)
        let privateKey = Certificate.PrivateKey(Self.rsaKey)

        let expected = try Self.rsaKey.signature(for: SHA256.hash(data: input), padding: .insecurePKCS1v1_5)
        let found = try privateKey.sign(bytes: input, signatureAlgorithm: .sha256WithRSAEncryption)

        XCTAssertEqual(.init(expected.rawRepresentation), found.rawRepresentation)
    }

    func testEd25519SignatureBytes() throws {
        let input = Array("Hello World".utf8)

        let expected = try Self.ed25519Key.signature(for: input)
        let signature = try Certificate.Signature(
            signatureAlgorithm: .ed25519,
            signatureBytes: .init(bytes: Array(expected)[...])
        )

        XCTAssertEqual(.init(expected), signature.rawRepresentation)
    }

    func testECDSASignatureBytes() throws {
        let input = Array("Hello World".utf8)

        let expected = try Self.p384Key.signature(for: SHA256.hash(data: input))
        let signature = try Certificate.Signature(
            signatureAlgorithm: .ecdsaWithSHA256,
            signatureBytes: .init(bytes: Array(expected.derRepresentation)[...])
        )

        XCTAssertEqual(.init(expected.derRepresentation), signature.rawRepresentation)
    }

    func testP384Signature() throws {
        // This is the P384 signature over LetsEncrypt Intermediate E1.
        let signatureBytes: [UInt8] = [
            0x30, 0x64, 0x02, 0x30, 0x7B, 0x74,
            0xD5, 0x52, 0x13, 0x8D, 0x61, 0xFE, 0x0D, 0xBA, 0x3F,
            0x03, 0x00, 0x9D, 0xF3, 0xD7, 0x98, 0x84, 0xD9, 0x57,
            0x2E, 0xBD, 0xE9, 0x0F, 0x9C, 0x5C, 0x48, 0x04, 0x21,
            0xF2, 0xCB, 0xB3, 0x60, 0x72, 0x8E, 0x97, 0xD6, 0x12,
            0x4F, 0xCA, 0x44, 0xF6, 0x42, 0xC9, 0xD3, 0x7B, 0x86,
            0xA9, 0x02, 0x30, 0x5A, 0xB1, 0xB1, 0xB4, 0xED, 0xEA,
            0x60, 0x99, 0x20, 0xB1, 0x38, 0x03, 0xCA, 0x3D, 0xA0,
            0x26, 0xB8, 0xEE, 0x6E, 0x2D, 0x4A, 0xF6, 0xC6, 0x66,
            0x1F, 0x33, 0x9A, 0xDB, 0x92, 0x4A, 0xD5, 0xF5, 0x29,
            0x13, 0xC6, 0x70, 0x62, 0x28, 0xBA, 0x23, 0x8C, 0xCF,
            0x3D, 0x2F, 0xCB, 0x82, 0xE9, 0x7F,
        ]
        let signature = try Certificate.Signature(
            signatureAlgorithm: .ecdsaWithSHA384,
            signatureBytes: ASN1BitString(bytes: signatureBytes[...])
        )
        guard case .ecdsa(let sig) = signature.backing, let inner = P384.Signing.ECDSASignature(sig) else {
            XCTFail("Invalid signature decode")
            return
        }

        XCTAssertEqual(signature.rawRepresentation, .init(signatureBytes))

        // Validate that the signature is valid over the TBS certificate bytes.
        let issuingPublicKeyBytes: [UInt8] = [
            0x04, 0xCD, 0x9B, 0xD5, 0x9F, 0x80, 0x83, 0x0A, 0xEC, 0x09, 0x4A, 0xF3,
            0x16, 0x4A, 0x3E, 0x5C, 0xCF, 0x77, 0xAC, 0xDE, 0x67, 0x05, 0x0D, 0x1D, 0x07, 0xB6, 0xDC, 0x16,
            0xFB, 0x5A, 0x8B, 0x14, 0xDB, 0xE2, 0x71, 0x60, 0xC4, 0xBA, 0x45, 0x95, 0x11, 0x89, 0x8E, 0xEA,
            0x06, 0xDF, 0xF7, 0x2A, 0x16, 0x1C, 0xA4, 0xB9, 0xC5, 0xC5, 0x32, 0xE0, 0x03, 0xE0, 0x1E, 0x82,
            0x18, 0x38, 0x8B, 0xD7, 0x45, 0xD8, 0x0A, 0x6A, 0x6E, 0xE6, 0x00, 0x77, 0xFB, 0x02, 0x51, 0x7D,
            0x22, 0xD8, 0x0A, 0x6E, 0x9A, 0x5B, 0x77, 0xDF, 0xF0, 0xFA, 0x41, 0xEC, 0x39, 0xDC, 0x75, 0xCA,
            0x68, 0x07, 0x0C, 0x1F, 0xEA,
        ]
        let tbsCertificateBytes: [UInt8] = [
            0x30, 0x82, 0x02, 0x4D, 0xA0, 0x03, 0x02, 0x01, 0x02, 0x02, 0x11, 0x00,
            0xB3, 0xBD, 0xDF, 0xF8, 0xA7, 0x84, 0x5B, 0xBC, 0xE9, 0x03, 0xA0, 0x41, 0x35, 0xB3, 0x4A, 0x45,
            0x30, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x03, 0x03, 0x30, 0x4F, 0x31, 0x0B,
            0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x29, 0x30, 0x27, 0x06,
            0x03, 0x55, 0x04, 0x0A, 0x13, 0x20, 0x49, 0x6E, 0x74, 0x65, 0x72, 0x6E, 0x65, 0x74, 0x20, 0x53,
            0x65, 0x63, 0x75, 0x72, 0x69, 0x74, 0x79, 0x20, 0x52, 0x65, 0x73, 0x65, 0x61, 0x72, 0x63, 0x68,
            0x20, 0x47, 0x72, 0x6F, 0x75, 0x70, 0x31, 0x15, 0x30, 0x13, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13,
            0x0C, 0x49, 0x53, 0x52, 0x47, 0x20, 0x52, 0x6F, 0x6F, 0x74, 0x20, 0x58, 0x32, 0x30, 0x1E, 0x17,
            0x0D, 0x32, 0x30, 0x30, 0x39, 0x30, 0x34, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5A, 0x17, 0x0D,
            0x32, 0x35, 0x30, 0x39, 0x31, 0x35, 0x31, 0x36, 0x30, 0x30, 0x30, 0x30, 0x5A, 0x30, 0x32, 0x31,
            0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x06, 0x13, 0x02, 0x55, 0x53, 0x31, 0x16, 0x30, 0x14,
            0x06, 0x03, 0x55, 0x04, 0x0A, 0x13, 0x0D, 0x4C, 0x65, 0x74, 0x27, 0x73, 0x20, 0x45, 0x6E, 0x63,
            0x72, 0x79, 0x70, 0x74, 0x31, 0x0B, 0x30, 0x09, 0x06, 0x03, 0x55, 0x04, 0x03, 0x13, 0x02, 0x45,
            0x31, 0x30, 0x76, 0x30, 0x10, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01, 0x06, 0x05,
            0x2B, 0x81, 0x04, 0x00, 0x22, 0x03, 0x62, 0x00, 0x04, 0x24, 0x5C, 0x2D, 0xA2, 0x2A, 0xFD, 0x1C,
            0x4B, 0xA6, 0x5D, 0x97, 0x73, 0x27, 0x31, 0xAC, 0xB2, 0xA0, 0x69, 0x62, 0xEF, 0x65, 0xE8, 0xA6,
            0xB0, 0xF0, 0xAC, 0x4B, 0x9F, 0xFF, 0x1C, 0x0B, 0x70, 0x0F, 0xD3, 0x98, 0x2F, 0x4D, 0xFC, 0x0F,
            0x00, 0x9B, 0x37, 0xF0, 0x74, 0x05, 0x57, 0x32, 0x97, 0x2E, 0x05, 0xEF, 0x2A, 0x43, 0x25, 0xA3,
            0xFB, 0x6E, 0x34, 0x27, 0x13, 0xF6, 0x4F, 0x7E, 0x69, 0xD3, 0x02, 0x99, 0x5E, 0xEB, 0x24, 0x47,
            0x92, 0xC1, 0x24, 0x9B, 0xE6, 0xB1, 0x21, 0x8F, 0xC1, 0x24, 0x81, 0xFC, 0x68, 0xCC, 0x1F, 0x69,
            0xBA, 0x58, 0xF5, 0x19, 0x22, 0xF7, 0x74, 0xC6, 0x16, 0xA3, 0x82, 0x01, 0x08, 0x30, 0x82, 0x01,
            0x04, 0x30, 0x0E, 0x06, 0x03, 0x55, 0x1D, 0x0F, 0x01, 0x01, 0xFF, 0x04, 0x04, 0x03, 0x02, 0x01,
            0x86, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x25, 0x04, 0x16, 0x30, 0x14, 0x06, 0x08, 0x2B, 0x06,
            0x01, 0x05, 0x05, 0x07, 0x03, 0x02, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01,
            0x30, 0x12, 0x06, 0x03, 0x55, 0x1D, 0x13, 0x01, 0x01, 0xFF, 0x04, 0x08, 0x30, 0x06, 0x01, 0x01,
            0xFF, 0x02, 0x01, 0x00, 0x30, 0x1D, 0x06, 0x03, 0x55, 0x1D, 0x0E, 0x04, 0x16, 0x04, 0x14, 0x5A,
            0xF3, 0xED, 0x2B, 0xFC, 0x36, 0xC2, 0x37, 0x79, 0xB9, 0x52, 0x30, 0xEA, 0x54, 0x6F, 0xCF, 0x55,
            0xCB, 0x2E, 0xAC, 0x30, 0x1F, 0x06, 0x03, 0x55, 0x1D, 0x23, 0x04, 0x18, 0x30, 0x16, 0x80, 0x14,
            0x7C, 0x42, 0x96, 0xAE, 0xDE, 0x4B, 0x48, 0x3B, 0xFA, 0x92, 0xF8, 0x9E, 0x8C, 0xCF, 0x6D, 0x8B,
            0xA9, 0x72, 0x37, 0x95, 0x30, 0x32, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x01, 0x01,
            0x04, 0x26, 0x30, 0x24, 0x30, 0x22, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x02,
            0x86, 0x16, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F, 0x2F, 0x78, 0x32, 0x2E, 0x69, 0x2E, 0x6C, 0x65,
            0x6E, 0x63, 0x72, 0x2E, 0x6F, 0x72, 0x67, 0x2F, 0x30, 0x27, 0x06, 0x03, 0x55, 0x1D, 0x1F, 0x04,
            0x20, 0x30, 0x1E, 0x30, 0x1C, 0xA0, 0x1A, 0xA0, 0x18, 0x86, 0x16, 0x68, 0x74, 0x74, 0x70, 0x3A,
            0x2F, 0x2F, 0x78, 0x32, 0x2E, 0x63, 0x2E, 0x6C, 0x65, 0x6E, 0x63, 0x72, 0x2E, 0x6F, 0x72, 0x67,
            0x2F, 0x30, 0x22, 0x06, 0x03, 0x55, 0x1D, 0x20, 0x04, 0x1B, 0x30, 0x19, 0x30, 0x08, 0x06, 0x06,
            0x67, 0x81, 0x0C, 0x01, 0x02, 0x01, 0x30, 0x0D, 0x06, 0x0B, 0x2B, 0x06, 0x01, 0x04, 0x01, 0x82,
            0xDF, 0x13, 0x01, 0x01, 0x01,
        ]

        let digest = SHA384.hash(data: tbsCertificateBytes)
        let publicKey = try P384.Signing.PublicKey(x963Representation: issuingPublicKeyBytes)
        XCTAssertTrue(publicKey.isValidSignature(inner, for: digest))

    }

    // The base test implementation for the hash function mismatch tests. This test case validates that, if the combination is valid, we can
    // create and then verify a certificate signature using this pair of key and algorithm. If it's invalid, it confirms that we can't create
    // a signature of this combination, and that attempting to validate a signature would also fail.
    private func hashFunctionMismatchTest(
        privateKey: Certificate.PrivateKey,
        signatureAlgorithm: Certificate.SignatureAlgorithm,
        validCombination: Bool
    ) throws {
        let name = try DistinguishedName {
            CommonName("Hash function mismatch CA")
        }

        let extensions = try Certificate.Extensions {
            Critical(
                BasicConstraints.isCertificateAuthority(maxPathLength: nil)
            )
        }

        do {
            let certificate = try Certificate(
                version: .v3,
                serialNumber: .init(),
                publicKey: privateKey.publicKey,
                notValidBefore: Self.now,
                notValidAfter: Self.oneYearFromNow,
                issuer: name,
                subject: name,
                signatureAlgorithm: signatureAlgorithm,
                extensions: extensions,
                issuerPrivateKey: privateKey
            )
            XCTAssertTrue(
                validCombination,
                "Incorrectly able to create cert combining \(privateKey) and \(signatureAlgorithm)"
            )
            XCTAssertTrue(
                privateKey.publicKey.isValidSignature(certificate.signature, for: certificate),
                "Unable to validate signature combining \(privateKey) and \(signatureAlgorithm)"
            )
        } catch {
            XCTAssertFalse(validCombination, "Unable to create cert combining \(privateKey) and \(signatureAlgorithm)")
        }
    }

    func testHashFunctionMismatch_p256_ecdsaWithSHA256() throws {
        try self.hashFunctionMismatchTest(
            privateKey: .init(Self.p256Key),
            signatureAlgorithm: .ecdsaWithSHA256,
            validCombination: true
        )
    }

    func testHashFunctionMismatch_p256_ecdsaWithSHA384() throws {
        try self.hashFunctionMismatchTest(
            privateKey: .init(Self.p256Key),
            signatureAlgorithm: .ecdsaWithSHA384,
            validCombination: true
        )
    }

    func testHashFunctionMismatch_p256_ecdsaWithSHA512() throws {
        try self.hashFunctionMismatchTest(
            privateKey: .init(Self.p256Key),
            signatureAlgorithm: .ecdsaWithSHA512,
            validCombination: true
        )
    }

    func testHashFunctionMismatch_p256_sha1WithRSAEncryption() throws {
        try self.hashFunctionMismatchTest(
            privateKey: .init(Self.p256Key),
            signatureAlgorithm: .sha1WithRSAEncryption,
            validCombination: false
        )
    }

    func testHashFunctionMismatch_p256_sha256WithRSAEncryption() throws {
        try self.hashFunctionMismatchTest(
            privateKey: .init(Self.p256Key),
            signatureAlgorithm: .sha256WithRSAEncryption,
            validCombination: false
        )
    }

    func testHashFunctionMismatch_p256_sha384WithRSAEncryption() throws {
        try self.hashFunctionMismatchTest(
            privateKey: .init(Self.p256Key),
            signatureAlgorithm: .sha384WithRSAEncryption,
            validCombination: false
        )
    }

    func testHashFunctionMismatch_p256_sha512WithRSAEncryption() throws {
        try self.hashFunctionMismatchTest(
            privateKey: .init(Self.p256Key),
            signatureAlgorithm: .sha512WithRSAEncryption,
            validCombination: false
        )
    }

    func testHashFunctionMismatch_p256_ed25519() throws {
        try self.hashFunctionMismatchTest(
            privateKey: .init(Self.p256Key),
            signatureAlgorithm: .ed25519,
            validCombination: false
        )
    }

    func testHashFunctionMismatch_p384_ecdsaWithSHA256() throws {
        try self.hashFunctionMismatchTest(
            privateKey: .init(Self.p384Key),
            signatureAlgorithm: .ecdsaWithSHA256,
            validCombination: true
        )
    }

    func testHashFunctionMismatch_p384_ecdsaWithSHA384() throws {
        try self.hashFunctionMismatchTest(
            privateKey: .init(Self.p384Key),
            signatureAlgorithm: .ecdsaWithSHA384,
            validCombination: true
        )
    }

    func testHashFunctionMismatch_p384_ecdsaWithSHA512() throws {
        try self.hashFunctionMismatchTest(
            privateKey: .init(Self.p384Key),
            signatureAlgorithm: .ecdsaWithSHA512,
            validCombination: true
        )
    }

    func testHashFunctionMismatch_p384_sha1WithRSAEncryption() throws {
        try self.hashFunctionMismatchTest(
            privateKey: .init(Self.p384Key),
            signatureAlgorithm: .sha1WithRSAEncryption,
            validCombination: false
        )
    }

    func testHashFunctionMismatch_p384_sha256WithRSAEncryption() throws {
        try self.hashFunctionMismatchTest(
            privateKey: .init(Self.p384Key),
            signatureAlgorithm: .sha256WithRSAEncryption,
            validCombination: false
        )
    }

    func testHashFunctionMismatch_p384_sha384WithRSAEncryption() throws {
        try self.hashFunctionMismatchTest(
            privateKey: .init(Self.p384Key),
            signatureAlgorithm: .sha384WithRSAEncryption,
            validCombination: false
        )
    }

    func testHashFunctionMismatch_p384_sha512WithRSAEncryption() throws {
        try self.hashFunctionMismatchTest(
            privateKey: .init(Self.p384Key),
            signatureAlgorithm: .sha512WithRSAEncryption,
            validCombination: false
        )
    }

    func testHashFunctionMismatch_p384_ed25519() throws {
        try self.hashFunctionMismatchTest(
            privateKey: .init(Self.p384Key),
            signatureAlgorithm: .ed25519,
            validCombination: false
        )
    }

    func testHashFunctionMismatch_p521_ecdsaWithSHA256() throws {
        try self.hashFunctionMismatchTest(
            privateKey: .init(Self.p521Key),
            signatureAlgorithm: .ecdsaWithSHA256,
            validCombination: true
        )
    }

    func testHashFunctionMismatch_p521_ecdsaWithSHA384() throws {
        try self.hashFunctionMismatchTest(
            privateKey: .init(Self.p521Key),
            signatureAlgorithm: .ecdsaWithSHA384,
            validCombination: true
        )
    }

    func testHashFunctionMismatch_p521_ecdsaWithSHA512() throws {
        try self.hashFunctionMismatchTest(
            privateKey: .init(Self.p521Key),
            signatureAlgorithm: .ecdsaWithSHA512,
            validCombination: true
        )
    }

    func testHashFunctionMismatch_p521_sha1WithRSAEncryption() throws {
        try self.hashFunctionMismatchTest(
            privateKey: .init(Self.p521Key),
            signatureAlgorithm: .sha1WithRSAEncryption,
            validCombination: false
        )
    }

    func testHashFunctionMismatch_p521_sha256WithRSAEncryption() throws {
        try self.hashFunctionMismatchTest(
            privateKey: .init(Self.p521Key),
            signatureAlgorithm: .sha256WithRSAEncryption,
            validCombination: false
        )
    }

    func testHashFunctionMismatch_p521_sha384WithRSAEncryption() throws {
        try self.hashFunctionMismatchTest(
            privateKey: .init(Self.p521Key),
            signatureAlgorithm: .sha384WithRSAEncryption,
            validCombination: false
        )
    }

    func testHashFunctionMismatch_p521_sha512WithRSAEncryption() throws {
        try self.hashFunctionMismatchTest(
            privateKey: .init(Self.p521Key),
            signatureAlgorithm: .sha512WithRSAEncryption,
            validCombination: false
        )
    }

    func testHashFunctionMismatch_p521_ed25519() throws {
        try self.hashFunctionMismatchTest(
            privateKey: .init(Self.p521Key),
            signatureAlgorithm: .ed25519,
            validCombination: false
        )
    }

    func testHashFunctionMismatch_rsa_ecdsaWithSHA256() throws {
        try self.hashFunctionMismatchTest(
            privateKey: .init(Self.rsaKey),
            signatureAlgorithm: .ecdsaWithSHA256,
            validCombination: false
        )
    }

    func testHashFunctionMismatch_rsa_ecdsaWithSHA384() throws {
        try self.hashFunctionMismatchTest(
            privateKey: .init(Self.rsaKey),
            signatureAlgorithm: .ecdsaWithSHA384,
            validCombination: false
        )
    }

    func testHashFunctionMismatch_rsa_ecdsaWithSHA512() throws {
        try self.hashFunctionMismatchTest(
            privateKey: .init(Self.rsaKey),
            signatureAlgorithm: .ecdsaWithSHA512,
            validCombination: false
        )
    }

    func testHashFunctionMismatch_rsa_ed25519() throws {
        try self.hashFunctionMismatchTest(
            privateKey: .init(Self.rsaKey),
            signatureAlgorithm: .ed25519,
            validCombination: false
        )
    }

    func testHashFunctionMismatch_rsa_sha1WithRSAEncryption() throws {
        try self.hashFunctionMismatchTest(
            privateKey: .init(Self.rsaKey),
            signatureAlgorithm: .sha1WithRSAEncryption,
            validCombination: true
        )
    }

    func testHashFunctionMismatch_rsa_sha256WithRSAEncryption() throws {
        try self.hashFunctionMismatchTest(
            privateKey: .init(Self.rsaKey),
            signatureAlgorithm: .sha256WithRSAEncryption,
            validCombination: true
        )
    }

    func testHashFunctionMismatch_rsa_sha384WithRSAEncryption() throws {
        try self.hashFunctionMismatchTest(
            privateKey: .init(Self.rsaKey),
            signatureAlgorithm: .sha384WithRSAEncryption,
            validCombination: true
        )
    }

    func testHashFunctionMismatch_rsa_sha512WithRSAEncryption() throws {
        try self.hashFunctionMismatchTest(
            privateKey: .init(Self.rsaKey),
            signatureAlgorithm: .sha512WithRSAEncryption,
            validCombination: true
        )
    }

    #if canImport(Darwin)
    static func generateSecKey(keyType: CFString, keySize: Int, useSEP: Bool) throws -> SecKey {
        let access = SecAccessControlCreateWithFlags(
            kCFAllocatorDefault,
            kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            .privateKeyUsage,
            nil
        )!

        let attributes: NSMutableDictionary = [
            kSecAttrKeyType: keyType,
            kSecAttrKeySizeInBits: keySize,
            kSecPrivateKeyAttrs: [
                kSecAttrIsPermanent: false,
                kSecAttrAccessControl: access,
            ],
        ]

        if useSEP {
            attributes[kSecAttrTokenID] = kSecAttrTokenIDSecureEnclave
        }

        var error: Unmanaged<CFError>? = nil
        guard let secKey = SecKeyCreateRandomKey(attributes, &error) else {
            throw error!.takeRetainedValue() as Error
        }

        return secKey
    }

    func testHashFunctionMismatch_secKeyRSA_sha1WithRSAEncryption() throws {
        guard let secKeyRSA = Self.secKeyRSA else {
            throw XCTSkip("Key Error")
        }
        try self.hashFunctionMismatchTest(
            privateKey: .init(secKeyRSA),
            signatureAlgorithm: .sha1WithRSAEncryption,
            validCombination: true
        )
    }

    func testHashFunctionMismatch_secKeyRSA_sha256WithRSAEncryption() throws {
        guard let secKeyRSA = Self.secKeyRSA else {
            throw XCTSkip("Key Error")
        }
        try self.hashFunctionMismatchTest(
            privateKey: .init(secKeyRSA),
            signatureAlgorithm: .sha256WithRSAEncryption,
            validCombination: true
        )
    }

    func testHashFunctionMismatch_secKeyRSA_sha384WithRSAEncryption() throws {
        guard let secKeyRSA = Self.secKeyRSA else {
            throw XCTSkip("Key Error")
        }
        try self.hashFunctionMismatchTest(
            privateKey: .init(secKeyRSA),
            signatureAlgorithm: .sha384WithRSAEncryption,
            validCombination: true
        )
    }

    func testHashFunctionMismatch_secKeyRSA_sha512WithRSAEncryption() throws {
        guard let secKeyRSA = Self.secKeyRSA else {
            throw XCTSkip("Key Error")
        }
        try self.hashFunctionMismatchTest(
            privateKey: .init(secKeyRSA),
            signatureAlgorithm: .sha512WithRSAEncryption,
            validCombination: true
        )
    }

    func testHashFunctionMismatch_secKeyRSA_ecdsaWithSHA256() throws {
        guard let secKeyRSA = Self.secKeyRSA else {
            throw XCTSkip("Key Error")
        }
        try self.hashFunctionMismatchTest(
            privateKey: .init(secKeyRSA),
            signatureAlgorithm: .ecdsaWithSHA256,
            validCombination: false
        )
    }

    func testHashFunctionMismatch_secKeyEC256_ecdsaWithSHA256() throws {
        guard let secKeyEC256 = Self.secKeyEC256 else {
            throw XCTSkip("Key Error")
        }
        try self.hashFunctionMismatchTest(
            privateKey: .init(secKeyEC256),
            signatureAlgorithm: .ecdsaWithSHA256,
            validCombination: true
        )
    }

    func testHashFunctionMismatch_secKeyEC256_ecdsaWithSHA384() throws {
        guard let secKeyEC256 = Self.secKeyEC256 else {
            throw XCTSkip("Key Error")
        }
        try self.hashFunctionMismatchTest(
            privateKey: .init(secKeyEC256),
            signatureAlgorithm: .ecdsaWithSHA384,
            validCombination: true
        )
    }

    func testHashFunctionMismatch_secKeyEC256_ecdsaWithSHA512() throws {
        guard let secKeyEC256 = Self.secKeyEC256 else {
            throw XCTSkip("Key Error")
        }
        try self.hashFunctionMismatchTest(
            privateKey: .init(secKeyEC256),
            signatureAlgorithm: .ecdsaWithSHA512,
            validCombination: true
        )
    }

    func testHashFunctionMismatch_secKeyEC384_ecdsaWithSHA256() throws {
        guard let secKeyEC384 = Self.secKeyEC384 else {
            throw XCTSkip("Key Error")
        }
        try self.hashFunctionMismatchTest(
            privateKey: .init(secKeyEC384),
            signatureAlgorithm: .ecdsaWithSHA256,
            validCombination: true
        )
    }

    func testHashFunctionMismatch_secKeyEC384_ecdsaWithSHA384() throws {
        guard let secKeyEC384 = Self.secKeyEC384 else {
            throw XCTSkip("Key Error")
        }
        try self.hashFunctionMismatchTest(
            privateKey: .init(secKeyEC384),
            signatureAlgorithm: .ecdsaWithSHA384,
            validCombination: true
        )
    }

    func testHashFunctionMismatch_secKeyEC384_ecdsaWithSHA512() throws {
        guard let secKeyEC384 = Self.secKeyEC384 else {
            throw XCTSkip("Key Error")
        }
        try self.hashFunctionMismatchTest(
            privateKey: .init(secKeyEC384),
            signatureAlgorithm: .ecdsaWithSHA512,
            validCombination: true
        )
    }

    func testHashFunctionMismatch_secKeyEC521_ecdsaWithSHA256() throws {
        guard let secKeyEC521 = Self.secKeyEC521 else {
            throw XCTSkip("Key Error")
        }
        try self.hashFunctionMismatchTest(
            privateKey: .init(secKeyEC521),
            signatureAlgorithm: .ecdsaWithSHA256,
            validCombination: true
        )
    }

    func testHashFunctionMismatch_secKeyEC521_ecdsaWithSHA384() throws {
        guard let secKeyEC521 = Self.secKeyEC521 else {
            throw XCTSkip("Key Error")
        }
        try self.hashFunctionMismatchTest(
            privateKey: .init(secKeyEC521),
            signatureAlgorithm: .ecdsaWithSHA384,
            validCombination: true
        )
    }

    func testHashFunctionMismatch_secKeyEC521_ecdsaWithSHA512() throws {
        guard let secKeyEC521 = Self.secKeyEC521 else {
            throw XCTSkip("Key Error")
        }
        try self.hashFunctionMismatchTest(
            privateKey: .init(secKeyEC521),
            signatureAlgorithm: .ecdsaWithSHA512,
            validCombination: true
        )
    }

    func testHashFunctionMismatch_secKeyEC521_sha512WithRSAEncryption() throws {
        guard let secKeyEC521 = Self.secKeyEC521 else {
            throw XCTSkip("Key Error")
        }
        try self.hashFunctionMismatchTest(
            privateKey: .init(secKeyEC521),
            signatureAlgorithm: .sha512WithRSAEncryption,
            validCombination: false
        )
    }

    func testHashFunctionMismatch_secKeyEC521_ed25519() throws {
        guard let secKeyEC521 = Self.secKeyEC521 else {
            throw XCTSkip("Key Error")
        }
        try self.hashFunctionMismatchTest(
            privateKey: .init(secKeyEC521),
            signatureAlgorithm: .ed25519,
            validCombination: false
        )
    }

    func testHashFunctionMismatch_secKeyEnclaveEC256_ecdsaWithSHA256() throws {
        guard let secKeyEnclaveEC256 = Self.secKeyEnclaveEC256 else {
            throw XCTSkip("No SEP")
        }
        try self.hashFunctionMismatchTest(
            privateKey: .init(secKeyEnclaveEC256),
            signatureAlgorithm: .ecdsaWithSHA256,
            validCombination: true
        )
    }

    func testHashFunctionMismatch_secKeyEnclaveEC256_ecdsaWithSHA384() throws {
        guard let secKeyEnclaveEC256 = Self.secKeyEnclaveEC256 else {
            throw XCTSkip("No SEP")
        }
        try self.hashFunctionMismatchTest(
            privateKey: .init(secKeyEnclaveEC256),
            signatureAlgorithm: .ecdsaWithSHA384,
            validCombination: true
        )
    }

    func testHashFunctionMismatch_secKeyEnclaveEC256_ecdsaWithSHA512() throws {
        guard let secKeyEnclaveEC256 = Self.secKeyEnclaveEC256 else {
            throw XCTSkip("No SEP")
        }
        try self.hashFunctionMismatchTest(
            privateKey: .init(secKeyEnclaveEC256),
            signatureAlgorithm: .ecdsaWithSHA512,
            validCombination: true
        )
    }

    func testHashFunctionMismatch_secKeyEnclaveEC384_ecdsaWithSHA256() throws {
        guard let secKeyEnclaveEC384 = Self.secKeyEnclaveEC384 else {
            throw XCTSkip("No SEP")
        }
        try self.hashFunctionMismatchTest(
            privateKey: .init(secKeyEnclaveEC384),
            signatureAlgorithm: .ecdsaWithSHA256,
            validCombination: true
        )
    }

    func testHashFunctionMismatch_secKeyEnclaveEC384_ecdsaWithSHA384() throws {
        guard let secKeyEnclaveEC384 = Self.secKeyEnclaveEC384 else {
            throw XCTSkip("No SEP")
        }
        try self.hashFunctionMismatchTest(
            privateKey: .init(secKeyEnclaveEC384),
            signatureAlgorithm: .ecdsaWithSHA384,
            validCombination: true
        )
    }

    func testHashFunctionMismatch_secKeyEnclaveEC384_ecdsaWithSHA512() throws {
        guard let secKeyEnclaveEC384 = Self.secKeyEnclaveEC384 else {
            throw XCTSkip("No SEP")
        }
        try self.hashFunctionMismatchTest(
            privateKey: .init(secKeyEnclaveEC384),
            signatureAlgorithm: .ecdsaWithSHA512,
            validCombination: true
        )
    }

    func testHashFunctionMismatch_secKeyEnclaveEC384_sha512WithRSAEncryption() throws {
        guard let secKeyEnclaveEC384 = Self.secKeyEnclaveEC384 else {
            throw XCTSkip("No SEP")
        }
        try self.hashFunctionMismatchTest(
            privateKey: .init(secKeyEnclaveEC384),
            signatureAlgorithm: .sha512WithRSAEncryption,
            validCombination: false
        )
    }

    func testHashFunctionMismatch_secKeyEnclaveEC384_ed25519() throws {
        guard let secKeyEnclaveEC384 = Self.secKeyEnclaveEC384 else {
            throw XCTSkip("No SEP")
        }
        try self.hashFunctionMismatchTest(
            privateKey: .init(secKeyEnclaveEC384),
            signatureAlgorithm: .ed25519,
            validCombination: false
        )
    }

    func testHashFunctionMismatch_secureEnclaveP256_ecdsaWithSHA256() throws {
        guard let secureEnclaveP256 = Self.secureEnclaveP256 else {
            throw XCTSkip("No SEP")
        }
        try self.hashFunctionMismatchTest(
            privateKey: .init(secureEnclaveP256),
            signatureAlgorithm: .ecdsaWithSHA256,
            validCombination: true
        )
    }

    func testHashFunctionMismatch_secureEnclaveP256_ecdsaWithSHA384() throws {
        guard let secureEnclaveP256 = Self.secureEnclaveP256 else {
            throw XCTSkip("No SEP")
        }
        try self.hashFunctionMismatchTest(
            privateKey: .init(secureEnclaveP256),
            signatureAlgorithm: .ecdsaWithSHA384,
            validCombination: true
        )
    }

    func testHashFunctionMismatch_secureEnclaveP256_ecdsaWithSHA512() throws {
        guard let secureEnclaveP256 = Self.secureEnclaveP256 else {
            throw XCTSkip("No SEP")
        }
        try self.hashFunctionMismatchTest(
            privateKey: .init(secureEnclaveP256),
            signatureAlgorithm: .ecdsaWithSHA512,
            validCombination: true
        )
    }

    func testHashFunctionMismatch_secureEnclaveP256_sha1WithRSAEncryption() throws {
        guard let secureEnclaveP256 = Self.secureEnclaveP256 else {
            throw XCTSkip("No SEP")
        }
        try self.hashFunctionMismatchTest(
            privateKey: .init(secureEnclaveP256),
            signatureAlgorithm: .sha1WithRSAEncryption,
            validCombination: false
        )
    }

    func testHashFunctionMismatch_secureEnclaveP256_sha256WithRSAEncryption() throws {
        guard let secureEnclaveP256 = Self.secureEnclaveP256 else {
            throw XCTSkip("No SEP")
        }
        try self.hashFunctionMismatchTest(
            privateKey: .init(secureEnclaveP256),
            signatureAlgorithm: .sha256WithRSAEncryption,
            validCombination: false
        )
    }

    func testHashFunctionMismatch_secureEnclaveP256_sha384WithRSAEncryption() throws {
        guard let secureEnclaveP256 = Self.secureEnclaveP256 else {
            throw XCTSkip("No SEP")
        }
        try self.hashFunctionMismatchTest(
            privateKey: .init(secureEnclaveP256),
            signatureAlgorithm: .sha384WithRSAEncryption,
            validCombination: false
        )
    }

    func testHashFunctionMismatch_secureEnclaveP256_sha512WithRSAEncryption() throws {
        guard let secureEnclaveP256 = Self.secureEnclaveP256 else {
            throw XCTSkip("No SEP")
        }
        try self.hashFunctionMismatchTest(
            privateKey: .init(secureEnclaveP256),
            signatureAlgorithm: .sha512WithRSAEncryption,
            validCombination: false
        )
    }

    func testHashFunctionMismatch_secureEnclaveP256_ed25519() throws {
        guard let secureEnclaveP256 = Self.secureEnclaveP256 else {
            throw XCTSkip("No SEP")
        }
        try self.hashFunctionMismatchTest(
            privateKey: .init(secureEnclaveP256),
            signatureAlgorithm: .ed25519,
            validCombination: false
        )
    }
    #endif

    func testHashFunctionMismatch_ped25519_ecdsaWithSHA256() throws {
        try self.hashFunctionMismatchTest(
            privateKey: .init(Self.ed25519Key),
            signatureAlgorithm: .ecdsaWithSHA256,
            validCombination: false
        )
    }

    func testHashFunctionMismatch_ed25519_ecdsaWithSHA384() throws {
        try self.hashFunctionMismatchTest(
            privateKey: .init(Self.ed25519Key),
            signatureAlgorithm: .ecdsaWithSHA384,
            validCombination: false
        )
    }

    func testHashFunctionMismatch_ed25519_ecdsaWithSHA512() throws {
        try self.hashFunctionMismatchTest(
            privateKey: .init(Self.ed25519Key),
            signatureAlgorithm: .ecdsaWithSHA512,
            validCombination: false
        )
    }

    func testHashFunctionMismatch_ed25519_sha1WithRSAEncryption() throws {
        try self.hashFunctionMismatchTest(
            privateKey: .init(Self.ed25519Key),
            signatureAlgorithm: .sha1WithRSAEncryption,
            validCombination: false
        )
    }

    func testHashFunctionMismatch_ed25519_sha256WithRSAEncryption() throws {
        try self.hashFunctionMismatchTest(
            privateKey: .init(Self.ed25519Key),
            signatureAlgorithm: .sha256WithRSAEncryption,
            validCombination: false
        )
    }

    func testHashFunctionMismatch_ed25519_sha384WithRSAEncryption() throws {
        try self.hashFunctionMismatchTest(
            privateKey: .init(Self.ed25519Key),
            signatureAlgorithm: .sha384WithRSAEncryption,
            validCombination: false
        )
    }

    func testHashFunctionMismatch_ed25519_sha512WithRSAEncryption() throws {
        try self.hashFunctionMismatchTest(
            privateKey: .init(Self.ed25519Key),
            signatureAlgorithm: .sha512WithRSAEncryption,
            validCombination: false
        )
    }

    func testHashFunctionMismatch_ed25519_ed25519() throws {
        try self.hashFunctionMismatchTest(
            privateKey: .init(Self.ed25519Key),
            signatureAlgorithm: .ed25519,
            validCombination: true
        )
    }

    func testECDSASignatureCorrectlyStripsLeadingZerosFromRawByteRepresentation() throws {
        // We're testing a round-trip logic here, ensuring that the ECDSA signature correctly round-trips.
        func testECDSASignatureRoundTrip(rawSignatureBytes: [UInt8]) throws {
            let sig = ECDSASignature(rawSignatureBytes: Data(rawSignatureBytes))

            var serializer = DER.Serializer()
            try serializer.serialize(sig)
            let serializedBytes = serializer.serializedBytes

            let parsed = try ECDSASignature(derEncoded: serializedBytes)
            XCTAssertEqual(sig, parsed)
        }

        try testECDSASignatureRoundTrip(rawSignatureBytes: [
            0x00, 0x00, 0x01, 0x02, 0x03, 0x04,
            0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
        ])
        try testECDSASignatureRoundTrip(rawSignatureBytes: [
            0xFF, 0xFF, 0x01, 0x02, 0x03, 0x04,
            0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
        ])
        try testECDSASignatureRoundTrip(rawSignatureBytes: [
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x05, 0x06, 0x07, 0x08, 0x09, 0x0a,
        ])
    }

    func testSignatureAlgorithmTranslatesToCorrectRFC8446Value() throws {
        // RFC8446 defines the following values for the Signature Schemes ("SignatureAlgorithm" prior to TLS 1.3).
        // Swift Certificates only supports a handful of them.
        //
        // enum {
        //     /* RSASSA-PKCS1-v1_5 algorithms */
        //     rsa_pkcs1_sha256(0x0401),
        //     rsa_pkcs1_sha384(0x0501),
        //     rsa_pkcs1_sha512(0x0601),
        //
        //     /* ECDSA algorithms */
        //     ecdsa_secp256r1_sha256(0x0403),
        //     ecdsa_secp384r1_sha384(0x0503),
        //     ecdsa_secp521r1_sha512(0x0603),
        //
        //     /* RSASSA-PSS algorithms with public key OID rsaEncryption */
        //     rsa_pss_rsae_sha256(0x0804),
        //     rsa_pss_rsae_sha384(0x0805),
        //     rsa_pss_rsae_sha512(0x0806),
        //
        //     /* EdDSA algorithms */
        //     ed25519(0x0807),
        //     ed448(0x0808),
        //
        //     /* RSASSA-PSS algorithms with public key OID RSASSA-PSS */
        //     rsa_pss_pss_sha256(0x0809),
        //     rsa_pss_pss_sha384(0x080a),
        //     rsa_pss_pss_sha512(0x080b),
        //
        //     /* Legacy algorithms */
        //     rsa_pkcs1_sha1(0x0201),
        //     ecdsa_sha1(0x0203),
        //
        //     /* Reserved Code Points */
        //     private_use(0xFE00..0xFFFF),
        //     (0xFFFF)
        // } SignatureScheme;

        // RSASSA-PKCS1-v1_5 algorithms
        XCTAssertEqual(0x0401, try! Certificate.SignatureAlgorithm.sha256WithRSAEncryption.rfc8446SignatureSchemeValue)
        XCTAssertEqual(0x0501, try! Certificate.SignatureAlgorithm.sha384WithRSAEncryption.rfc8446SignatureSchemeValue)
        XCTAssertEqual(0x0601, try! Certificate.SignatureAlgorithm.sha512WithRSAEncryption.rfc8446SignatureSchemeValue)

        // RSASSA-PSS algorithms with public key OID rsaEncryption
        // Currently not supported

        // ECDSA algorithms
        XCTAssertEqual(0x0403, try! Certificate.SignatureAlgorithm.ecdsaWithSHA256.rfc8446SignatureSchemeValue)
        XCTAssertEqual(0x0503, try! Certificate.SignatureAlgorithm.ecdsaWithSHA384.rfc8446SignatureSchemeValue)
        XCTAssertEqual(0x0603, try! Certificate.SignatureAlgorithm.ecdsaWithSHA512.rfc8446SignatureSchemeValue)

        // EdDSA algorithms
        XCTAssertEqual(0x0807, try! Certificate.SignatureAlgorithm.ed25519.rfc8446SignatureSchemeValue)
        // ed448 is currenlty not supported

        // RSASSA-PSS algorithms with public key OID RSASSA-PSS
        // Currently not supported

        // Legacy algorithms
        XCTAssertEqual(0x0201, try! Certificate.SignatureAlgorithm.sha1WithRSAEncryption.rfc8446SignatureSchemeValue)
        // ecdsa_sha1 is currenlty not supported
    }

    func supportedSignatureAlgorithmsMatch(
        ofKey key: Certificate.PrivateKey,
        match expected: Set<Certificate.SignatureAlgorithm>,
        withLegacyAlgorithms expectedLegacy: Set<Certificate.SignatureAlgorithm>
    ) {
        // Check non-legacy set
        let supportedAlgorithms = Set(key.supportedSignatureAlgorithms(includeLegacyAlgorithms: false))
        XCTAssertEqual(supportedAlgorithms, expected)

        // Check legacy set
        let supportedAlgorithmsWithLegacy = Set(key.supportedSignatureAlgorithms(includeLegacyAlgorithms: true))
        XCTAssertEqual(supportedAlgorithmsWithLegacy, expectedLegacy)
    }

    func testMapPrivateKeyToSupportedSignatureAlgorithmRSA() throws {
        supportedSignatureAlgorithmsMatch(
            ofKey: try! _RSA.Signing.PrivateKey(keySize: .bits2048).wrapped,
            match: [.sha256WithRSAEncryption, .sha384WithRSAEncryption, .sha512WithRSAEncryption],
            withLegacyAlgorithms: [.sha256WithRSAEncryption, .sha384WithRSAEncryption, .sha512WithRSAEncryption, .sha1WithRSAEncryption]
        )
        supportedSignatureAlgorithmsMatch(
            ofKey: try! _RSA.Signing.PrivateKey(keySize: .bits3072).wrapped,
            match: [.sha256WithRSAEncryption, .sha384WithRSAEncryption, .sha512WithRSAEncryption],
            withLegacyAlgorithms: [.sha256WithRSAEncryption, .sha384WithRSAEncryption, .sha512WithRSAEncryption, .sha1WithRSAEncryption]
        )
        supportedSignatureAlgorithmsMatch(
            ofKey: try! _RSA.Signing.PrivateKey(keySize: .bits4096).wrapped,
            match: [.sha256WithRSAEncryption, .sha384WithRSAEncryption, .sha512WithRSAEncryption],
            withLegacyAlgorithms: [.sha256WithRSAEncryption, .sha384WithRSAEncryption, .sha512WithRSAEncryption, .sha1WithRSAEncryption]
        )
    }

    func testMapPrivateKeyToSupportedSignatureAlgorithmECDSA() throws {
        supportedSignatureAlgorithmsMatch(
            ofKey: P256.Signing.PrivateKey().wrapped,
            match: [.ecdsaWithSHA256, .ecdsaWithSHA384, .ecdsaWithSHA512],
            withLegacyAlgorithms: [.ecdsaWithSHA256, .ecdsaWithSHA384, .ecdsaWithSHA512]
        )
        supportedSignatureAlgorithmsMatch(
            ofKey: P384.Signing.PrivateKey().wrapped,
            match: [.ecdsaWithSHA256, .ecdsaWithSHA384, .ecdsaWithSHA512],
            withLegacyAlgorithms: [.ecdsaWithSHA256, .ecdsaWithSHA384, .ecdsaWithSHA512]
        )
        supportedSignatureAlgorithmsMatch(
            ofKey: P521.Signing.PrivateKey().wrapped,
            match: [.ecdsaWithSHA256, .ecdsaWithSHA384, .ecdsaWithSHA512],
            withLegacyAlgorithms: [.ecdsaWithSHA256, .ecdsaWithSHA384, .ecdsaWithSHA512]
        )
    }

    func testMapPrivateKeyToSupportedSignatureAlgorithmEdDSA() throws {
        supportedSignatureAlgorithmsMatch(
            ofKey: try Certificate.PrivateKey(pemEncoded: Curve25519.Signing.PrivateKey().pemRepresentation.pemString),
            match: [.ed25519],
            withLegacyAlgorithms: [.ed25519]
        )
    }

#if canImport(Darwin)
    func testMapPrivateKeyToSupportedSignatureAlgorithmSecureEncalve() throws {
        supportedSignatureAlgorithmsMatch(
            ofKey: Certificate.PrivateKey(try SecureEnclave.P256.Signing.PrivateKey()),
            match: [.ecdsaWithSHA512, .ecdsaWithSHA384, .ecdsaWithSHA256],
            withLegacyAlgorithms: [.ecdsaWithSHA512, .ecdsaWithSHA384, .ecdsaWithSHA256]
        )
    }
#endif
}
