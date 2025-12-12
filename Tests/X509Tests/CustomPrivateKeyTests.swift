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

import CryptoKit
import Foundation
import SwiftASN1
import Testing
@testable import X509

@Suite
final class CustomPrivateKeyTests {

    @Test("CustomPrivateKey Backing Properties")
    func testCustomPrivateKeyBackingProperties() {
        let keyBacking = TestAsyncKey()
        let privateKey = Certificate.PrivateKey(keyBacking)
        #expect(privateKey.publicKey == keyBacking.publicKey)
        #expect(privateKey.description == "CustomPrivateKey")
        #expect(keyBacking.hashValue == privateKey.hashValue)
        #expect(keyBacking.defaultSignatureAlgorithm == privateKey.defaultSignatureAlgorithm)
        #expect(keyBacking.supportedSignatureAlgorithms == privateKey.supportedSignatureAlgorithms)
    }

    func testCustomPrivateKeySigning() async throws {
        let privateKey = Certificate.PrivateKey(TestAsyncKey())

        _ = try await privateKey.signAsynchronously(
            bytes: Data(),
            signatureAlgorithm: .ecdsaWithSHA256
        )
        #expect(throws: TestAsyncKey.MyError.self) {
            try privateKey.sign(
                bytes: Data(),
                signatureAlgorithm: .ecdsaWithSHA256
            )
        }
    }

    func testCustomPrivateKeyBackingEquality() {
        let keyBacking = TestAsyncKey()
        let leftKey = Certificate.PrivateKey(keyBacking)
        let rightKey = Certificate.PrivateKey(keyBacking)
        #expect(leftKey == rightKey)
    }

    func testCustomPrivateKeySerialization() {
        let privateKey = Certificate.PrivateKey(TestAsyncKey())
        #expect(throws: TestAsyncKey.MyError.self) {
            try privateKey.serializeAsPEM()
        }
    }

}

/// A theoretical private key which only supports asynchronous signing.
private struct TestAsyncKey: CustomPrivateKey {

    var publicKey: Certificate.PublicKey { privateKey.publicKey }

    // Not required for CustomPrivateKey protocol.
    private let privateKey = Certificate.PrivateKey(P256.Signing.PrivateKey())

    let defaultSignatureAlgorithm: Certificate.SignatureAlgorithm = .sha256WithRSAEncryption

    var supportedSignatureAlgorithms: [Certificate.SignatureAlgorithm] = [.sha256WithRSAEncryption]

    func signSynchronously(
        bytes: some DataProtocol,
        signatureAlgorithm: Certificate.SignatureAlgorithm
    ) throws -> Certificate.Signature {
        throw MyError()
    }

    func signAsynchronously(
        bytes: some DataProtocol & Sendable,
        signatureAlgorithm: Certificate.SignatureAlgorithm
    ) async throws -> Certificate.Signature {
        try await Task {
            try privateKey.sign(bytes: bytes, signatureAlgorithm: signatureAlgorithm)
        }
        .value
    }

    static let defaultPEMDiscriminator: String = "TestKey"

    func serializeAsPEM(discriminator: String) throws -> PEMDocument {
        throw MyError()
    }

    func serialize(into coder: inout DER.Serializer) throws {
        throw MyError()
    }

    struct MyError: Error {}

}
