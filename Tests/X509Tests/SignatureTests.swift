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

final class SignatureTests: XCTestCase {
    static let now = Date()
    static let oneYearFromNow = {
        now + (60 * 60 * 24 * 365)
    }()
    static let p256Key = P256.Signing.PrivateKey()
    static let p384Key = P384.Signing.PrivateKey()
    static let p521Key = P521.Signing.PrivateKey()
    static let rsaKey = try! _RSA.Signing.PrivateKey(keySize: .bits2048)

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
            0x3D, 0x2F, 0xCB, 0x82, 0xE9, 0x7F
        ]
        let signature = try Certificate.Signature(
            signatureAlgorithm: .ecdsaWithSHA384,
            signatureBytes: ASN1BitString(bytes: signatureBytes[...])
        )
        guard case .p384 = signature.backing else {
            XCTFail("Invalid signature decode")
            return
        }

        // TODO: test that the signature is valid over the TBSCertificate.
    }

    // The base test implementation for the hash function mismatch tests. This test case validates that, if the combination is valid, we can
    // create and then verify a certificate signature using this pair of key and algorithm. If it's invalid, it confirms that we can't create
    // a signature of this combination, and that attempting to validate a signature would also fail.
    private func hashFunctionMismatchTest(privateKey: Certificate.PrivateKey, signatureAlgorithm: Certificate.SignatureAlgorithm, validCombination: Bool) throws {
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
            XCTAssertTrue(validCombination, "Incorrectly able to create cert combining \(privateKey) and \(signatureAlgorithm)")
            XCTAssertTrue(privateKey.publicKey.isValidSignature(certificate.signature, for: certificate), "Unable to validate signature combining \(privateKey) and \(signatureAlgorithm)")
        } catch {
            XCTAssertFalse(validCombination, "Unable to create cert combining \(privateKey) and \(signatureAlgorithm)")
        }
    }

    func testHashFunctionMismatch_p256_ecdsaWithSHA256() throws {
        try self.hashFunctionMismatchTest(privateKey: .init(Self.p256Key), signatureAlgorithm: .ecdsaWithSHA256, validCombination: true)
    }

    func testHashFunctionMismatch_p256_ecdsaWithSHA384() throws {
        try self.hashFunctionMismatchTest(privateKey: .init(Self.p256Key), signatureAlgorithm: .ecdsaWithSHA384, validCombination: true)
    }

    func testHashFunctionMismatch_p256_ecdsaWithSHA512() throws {
        try self.hashFunctionMismatchTest(privateKey: .init(Self.p256Key), signatureAlgorithm: .ecdsaWithSHA512, validCombination: true)
    }

    func testHashFunctionMismatch_p256_sha1WithRSAEncryption() throws {
        try self.hashFunctionMismatchTest(privateKey: .init(Self.p256Key), signatureAlgorithm: .sha1WithRSAEncryption, validCombination: false)
    }

    func testHashFunctionMismatch_p256_sha256WithRSAEncryption() throws {
        try self.hashFunctionMismatchTest(privateKey: .init(Self.p256Key), signatureAlgorithm: .sha256WithRSAEncryption, validCombination: false)
    }

    func testHashFunctionMismatch_p256_sha384WithRSAEncryption() throws {
        try self.hashFunctionMismatchTest(privateKey: .init(Self.p256Key), signatureAlgorithm: .sha384WithRSAEncryption, validCombination: false)
    }

    func testHashFunctionMismatch_p256_sha512WithRSAEncryption() throws {
        try self.hashFunctionMismatchTest(privateKey: .init(Self.p256Key), signatureAlgorithm: .sha512WithRSAEncryption, validCombination: false)
    }

    func testHashFunctionMismatch_p384_ecdsaWithSHA256() throws {
        try self.hashFunctionMismatchTest(privateKey: .init(Self.p384Key), signatureAlgorithm: .ecdsaWithSHA256, validCombination: true)
    }

    func testHashFunctionMismatch_p384_ecdsaWithSHA384() throws {
        try self.hashFunctionMismatchTest(privateKey: .init(Self.p384Key), signatureAlgorithm: .ecdsaWithSHA384, validCombination: true)
    }

    func testHashFunctionMismatch_p384_ecdsaWithSHA512() throws {
        try self.hashFunctionMismatchTest(privateKey: .init(Self.p384Key), signatureAlgorithm: .ecdsaWithSHA512, validCombination: true)
    }

    func testHashFunctionMismatch_p384_sha1WithRSAEncryption() throws {
        try self.hashFunctionMismatchTest(privateKey: .init(Self.p384Key), signatureAlgorithm: .sha1WithRSAEncryption, validCombination: false)
    }

    func testHashFunctionMismatch_p384_sha256WithRSAEncryption() throws {
        try self.hashFunctionMismatchTest(privateKey: .init(Self.p384Key), signatureAlgorithm: .sha256WithRSAEncryption, validCombination: false)
    }

    func testHashFunctionMismatch_p384_sha384WithRSAEncryption() throws {
        try self.hashFunctionMismatchTest(privateKey: .init(Self.p384Key), signatureAlgorithm: .sha384WithRSAEncryption, validCombination: false)
    }

    func testHashFunctionMismatch_p384_sha512WithRSAEncryption() throws {
        try self.hashFunctionMismatchTest(privateKey: .init(Self.p384Key), signatureAlgorithm: .sha512WithRSAEncryption, validCombination: false)
    }

    func testHashFunctionMismatch_p521_ecdsaWithSHA256() throws {
        try self.hashFunctionMismatchTest(privateKey: .init(Self.p521Key), signatureAlgorithm: .ecdsaWithSHA256, validCombination: true)
    }

    func testHashFunctionMismatch_p521_ecdsaWithSHA384() throws {
        try self.hashFunctionMismatchTest(privateKey: .init(Self.p521Key), signatureAlgorithm: .ecdsaWithSHA384, validCombination: true)
    }

    func testHashFunctionMismatch_p521_ecdsaWithSHA512() throws {
        try self.hashFunctionMismatchTest(privateKey: .init(Self.p521Key), signatureAlgorithm: .ecdsaWithSHA512, validCombination: true)
    }

    func testHashFunctionMismatch_p521_sha1WithRSAEncryption() throws {
        try self.hashFunctionMismatchTest(privateKey: .init(Self.p521Key), signatureAlgorithm: .sha1WithRSAEncryption, validCombination: false)
    }

    func testHashFunctionMismatch_p521_sha256WithRSAEncryption() throws {
        try self.hashFunctionMismatchTest(privateKey: .init(Self.p521Key), signatureAlgorithm: .sha256WithRSAEncryption, validCombination: false)
    }

    func testHashFunctionMismatch_p521_sha384WithRSAEncryption() throws {
        try self.hashFunctionMismatchTest(privateKey: .init(Self.p521Key), signatureAlgorithm: .sha384WithRSAEncryption, validCombination: false)
    }

    func testHashFunctionMismatch_p521_sha512WithRSAEncryption() throws {
        try self.hashFunctionMismatchTest(privateKey: .init(Self.p521Key), signatureAlgorithm: .sha512WithRSAEncryption, validCombination: false)
    }

    func testHashFunctionMismatch_rsa_ecdsaWithSHA256() throws {
        try self.hashFunctionMismatchTest(privateKey: .init(Self.rsaKey), signatureAlgorithm: .ecdsaWithSHA256, validCombination: false)
    }

    func testHashFunctionMismatch_rsa_ecdsaWithSHA384() throws {
        try self.hashFunctionMismatchTest(privateKey: .init(Self.rsaKey), signatureAlgorithm: .ecdsaWithSHA384, validCombination: false)
    }

    func testHashFunctionMismatch_rsa_ecdsaWithSHA512() throws {
        try self.hashFunctionMismatchTest(privateKey: .init(Self.rsaKey), signatureAlgorithm: .ecdsaWithSHA512, validCombination: false)
    }

    func testHashFunctionMismatch_rsa_sha1WithRSAEncryption() throws {
        try self.hashFunctionMismatchTest(privateKey: .init(Self.rsaKey), signatureAlgorithm: .sha1WithRSAEncryption, validCombination: true)
    }

    func testHashFunctionMismatch_rsa_sha256WithRSAEncryption() throws {
        try self.hashFunctionMismatchTest(privateKey: .init(Self.rsaKey), signatureAlgorithm: .sha256WithRSAEncryption, validCombination: true)
    }

    func testHashFunctionMismatch_rsa_sha384WithRSAEncryption() throws {
        try self.hashFunctionMismatchTest(privateKey: .init(Self.rsaKey), signatureAlgorithm: .sha384WithRSAEncryption, validCombination: true)
    }

    func testHashFunctionMismatch_rsa_sha512WithRSAEncryption() throws {
        try self.hashFunctionMismatchTest(privateKey: .init(Self.rsaKey), signatureAlgorithm: .sha512WithRSAEncryption, validCombination: true)
    }
}
