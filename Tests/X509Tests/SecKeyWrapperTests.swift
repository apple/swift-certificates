//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCertificates open source project
//
// Copyright (c) 2024 Apple Inc. and the SwiftCertificates project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCertificates project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import XCTest
@_spi(Testing) @testable import X509
import Crypto
import _CryptoExtras
#if canImport(Darwin)
@preconcurrency import Security
#endif

#if canImport(Darwin)
final class SecKeyWrapperTests: XCTestCase {
    struct CandidateKey {
        let key: SecKey
        let type: String
        let keySize: Int
        let sep: Bool
    }

    func generateCandidateKeys() throws -> [CandidateKey] {
        do {
            var keys: [CandidateKey] = []

            // RSA
            keys.append(
                CandidateKey(
                    key: try SignatureTests.generateSecKey(keyType: kSecAttrKeyTypeRSA, keySize: 2048, useSEP: false),
                    type: "RSA",
                    keySize: 2048,
                    sep: false
                )
            )

            // eliptic curves
            var keyTypes = [kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyTypeEC]
            #if os(macOS)
            keyTypes.append(kSecAttrKeyTypeECDSA)
            #endif

            for keyType in keyTypes {
                for keySize in [256, 384] {
                    for useSEP in [true, false] {
                        keys.append(
                            CandidateKey(
                                key: try SignatureTests.generateSecKey(
                                    keyType: keyType,
                                    keySize: keySize,
                                    useSEP: useSEP
                                ),
                                type: "EC-\(keyType)",
                                keySize: keySize,
                                sep: useSEP
                            )
                        )
                    }
                }
            }

            return keys
        } catch let err as NSError {
            if err.domain == NSOSStatusErrorDomain && err.code == errSecInteractionNotAllowed {
                // Suppress this error
                throw XCTSkip("Unable to run this test without interactive prompting")
            }
            throw err
        }
    }

    @available(macOS 11.0, iOS 14, tvOS 14, watchOS 7, macCatalyst 14, visionOS 1.0, *)
    func testPEMExport() async throws {
        for candidate in try generateCandidateKeys() {
            try await XCTContext.runActivity(named: "Testing \(candidate.type) key (size: \(candidate.keySize))") { _ in
                let secKeyWrapper = try Certificate.PrivateKey.SecKeyWrapper(key: candidate.key)

                if !candidate.sep {
                    let pemString = try secKeyWrapper.pemDocument()
                    XCTAssertNotNil(pemString)
                } else {
                    XCTAssertThrowsError(try secKeyWrapper.pemDocument())
                }
            }
        }
    }

    func testMakeWithPrivateKey() throws {
        let keys: [(Certificate.PrivateKey, Certificate.SignatureAlgorithm)] = [
            (Certificate.PrivateKey(P256.Signing.PrivateKey()), .ecdsaWithSHA256),
            (Certificate.PrivateKey(P384.Signing.PrivateKey()), .ecdsaWithSHA384),
            (Certificate.PrivateKey(P521.Signing.PrivateKey()), .ecdsaWithSHA512),
            (Certificate.PrivateKey(try _RSA.Signing.PrivateKey(keySize: .bits2048)), .sha256WithRSAEncryption),
        ]
        let message = Array("hello, world".utf8)

        for (privateKey, signatureAlgorithm) in keys {
            let secKey = try SecKey.makeWithPrivateKey(privateKey)

            // Wrapping the SecKey back up yields the same key, and signatures made through Security
            // verify against the original public key.
            let roundTripped = try Certificate.PrivateKey(secKey)
            XCTAssertEqual(roundTripped.publicKey, privateKey.publicKey, "\(privateKey)")

            let signature = try roundTripped.sign(bytes: message, signatureAlgorithm: signatureAlgorithm)
            XCTAssertTrue(
                privateKey.publicKey.isValidSignature(signature, for: message, signatureAlgorithm: signatureAlgorithm),
                "\(privateKey)"
            )
        }
    }

    func testMakeWithPrivateKeyReturnsWrappedSecKey() throws {
        for candidate in try generateCandidateKeys() {
            let privateKey = try Certificate.PrivateKey(candidate.key)
            XCTAssertTrue(try SecKey.makeWithPrivateKey(privateKey) === candidate.key)
        }
    }

    func testMakeWithPrivateKeyRejectsUnrepresentableKeys() throws {
        XCTAssertThrowsError(try SecKey.makeWithPrivateKey(Certificate.PrivateKey(Curve25519.Signing.PrivateKey())))
        if SecureEnclave.isAvailable {
            let secureEnclaveKey = try SecureEnclave.P256.Signing.PrivateKey()
            XCTAssertThrowsError(try SecKey.makeWithPrivateKey(Certificate.PrivateKey(secureEnclaveKey)))
        }
    }
}
#endif
