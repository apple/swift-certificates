//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCertificates open source project
//
// Copyright (c) 2026 Apple Inc. and the SwiftCertificates project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCertificates project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Crypto
import Foundation
import SwiftASN1
import Testing
@testable import X509

@Suite
struct ClosureBackedPrivateKeyTests {

    /// Stands in for a signing backend that hands back a raw `r || s` ECDSA signature.
    static let backingKey = P256.Signing.PrivateKey()

    static func makeSynchronous(
        defaultSignatureAlgorithm: Certificate.SignatureAlgorithm = .ecdsaWithSHA256,
        additionalSupportedSignatureAlgorithms: [Certificate.SignatureAlgorithm] = []
    ) throws -> ClosureBackedPrivateKey {
        try ClosureBackedPrivateKey(
            publicKey: Certificate.PublicKey(backingKey.publicKey),
            defaultSignatureAlgorithm: defaultSignatureAlgorithm,
            additionalSupportedSignatureAlgorithms: additionalSupportedSignatureAlgorithms
        ) { bytes, algorithm in
            try Certificate.Signature(
                signatureAlgorithm: algorithm,
                rawECDSASignatureBytes: backingKey.signature(for: SHA256.hash(data: bytes)).rawRepresentation
            )
        }
    }

    @Test("Synchronous signing produces a verifiable signature")
    func synchronousSigning() throws {
        let key = Certificate.PrivateKey(try Self.makeSynchronous())
        let bytes = Array("Hello World".utf8)

        let signature = try key.sign(bytes: bytes, signatureAlgorithm: .ecdsaWithSHA256)
        #expect(key.publicKey.isValidSignature(signature, for: bytes, signatureAlgorithm: .ecdsaWithSHA256))
    }

    @Test("Asynchronous signing falls through to the synchronous closure")
    func synchronousKeySignsAsynchronously() async throws {
        let key = Certificate.PrivateKey(try Self.makeSynchronous())
        let bytes = Array("Hello World".utf8)

        let signature = try await key.signAsynchronously(bytes: bytes, signatureAlgorithm: .ecdsaWithSHA256)
        #expect(key.publicKey.isValidSignature(signature, for: bytes, signatureAlgorithm: .ecdsaWithSHA256))
    }

    @Test("An async-only key refuses to sign synchronously")
    func asyncOnlyKey() async throws {
        let backingKey = Self.backingKey
        let asyncKey = try ClosureBackedPrivateKey(
            publicKey: Certificate.PublicKey(backingKey.publicKey),
            defaultSignatureAlgorithm: .ecdsaWithSHA256,
            signAsynchronously: { bytes, algorithm in
                try Certificate.Signature(
                    signatureAlgorithm: algorithm,
                    rawECDSASignatureBytes: backingKey.signature(for: SHA256.hash(data: bytes)).rawRepresentation
                )
            }
        )
        let key = Certificate.PrivateKey(asyncKey)
        let bytes = Array("Hello World".utf8)

        let signature = try await key.signAsynchronously(bytes: bytes, signatureAlgorithm: .ecdsaWithSHA256)
        #expect(key.publicKey.isValidSignature(signature, for: bytes, signatureAlgorithm: .ecdsaWithSHA256))

        #expect(throws: CertificateError.self) {
            try key.sign(bytes: bytes, signatureAlgorithm: .ecdsaWithSHA256)
        }
    }

    @Test("The default signature algorithm leads the supported list without duplicating")
    func supportedSignatureAlgorithms() throws {
        let key = try Self.makeSynchronous(
            additionalSupportedSignatureAlgorithms: [.ecdsaWithSHA384, .ecdsaWithSHA256, .ecdsaWithSHA384]
        )
        #expect(key.supportedSignatureAlgorithms == [.ecdsaWithSHA256, .ecdsaWithSHA384])

        let privateKey = Certificate.PrivateKey(key)
        #expect(privateKey.defaultSignatureAlgorithm == .ecdsaWithSHA256)
        #expect(privateKey.supportedSignatureAlgorithms == [.ecdsaWithSHA256, .ecdsaWithSHA384])
    }

    @Test("Unsupported algorithms are rejected before the closure runs")
    func unsupportedAlgorithm() throws {
        let key = Certificate.PrivateKey(try Self.makeSynchronous())

        #expect(throws: CertificateError.self) {
            try key.sign(bytes: Array("Hello World".utf8), signatureAlgorithm: .ecdsaWithSHA384)
        }
    }

    @Test("Signing a CSR")
    func certificateSigningRequest() throws {
        let key = Certificate.PrivateKey(try Self.makeSynchronous())
        let name = try DistinguishedName {
            CommonName("closure-backed")
        }

        let csr = try CertificateSigningRequest(
            version: .v1,
            subject: name,
            privateKey: key,
            attributes: CertificateSigningRequest.Attributes()
        )

        #expect(csr.publicKey.isValidSignature(csr.signature, for: csr))
    }

    @Test("Equality ignores the closure")
    func equality() throws {
        #expect(try Self.makeSynchronous() == Self.makeSynchronous())
        #expect(try Self.makeSynchronous().hashValue == Self.makeSynchronous().hashValue)
        #expect(
            try Self.makeSynchronous() != Self.makeSynchronous(defaultSignatureAlgorithm: .ecdsaWithSHA384)
        )
    }

    @Test("PEM serialization is unsupported")
    func pemSerialization() throws {
        let key = Certificate.PrivateKey(try Self.makeSynchronous())

        #expect(throws: CertificateError.self) {
            try key.serializeAsPEM()
        }
    }

    @Test("Algorithms that do not suit the public key are rejected at construction")
    func algorithmMustSuitPublicKey() {
        #expect(throws: CertificateError.self) {
            try Self.makeSynchronous(defaultSignatureAlgorithm: .sha256WithRSAEncryption)
        }
        #expect(throws: CertificateError.self) {
            try Self.makeSynchronous(additionalSupportedSignatureAlgorithms: [.ed25519])
        }
    }

    @Test("A signature of the wrong kind from the closure is rejected")
    func closureReturnsWrongKindOfSignature() throws {
        let ed25519Key = Curve25519.Signing.PrivateKey()
        let key = Certificate.PrivateKey(
            try ClosureBackedPrivateKey(
                publicKey: Certificate.PublicKey(Self.backingKey.publicKey),
                defaultSignatureAlgorithm: .ecdsaWithSHA256
            ) { bytes, _ in
                try Certificate.Signature(
                    signatureAlgorithm: .ed25519,
                    signatureBytes: ASN1BitString(bytes: ArraySlice(ed25519Key.signature(for: bytes)))
                )
            }
        )

        #expect(throws: CertificateError.self) {
            try key.sign(bytes: Array("Hello World".utf8), signatureAlgorithm: .ecdsaWithSHA256)
        }
    }
}
