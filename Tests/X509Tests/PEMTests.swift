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

import SwiftASN1
import Crypto
import _CryptoExtras
@testable import X509

private protocol Key {
    associatedtype Wrapped: WrappedKey
    init(derRepresentation: some DataProtocol) throws
    init(pemRepresentation: String) throws
    var pemRepresentation: String { get }
    var wrapped: Wrapped { get }
}

extension Key {
    var pemDiscriminator: String {
        get throws {
            try PEMDocument(pemString: pemRepresentation).discriminator
        }
    }
}

// MARK: Private Keys

@available(macOS 11.0, iOS 14, tvOS 14, watchOS 7, macCatalyst 14, visionOS 1.0, *)
extension Crypto.P256.Signing.PrivateKey: Key {
    var wrapped: Certificate.PrivateKey { .init(self) }
}
@available(macOS 11.0, iOS 14, tvOS 14, watchOS 7, macCatalyst 14, visionOS 1.0, *)
extension Crypto.P384.Signing.PrivateKey: Key {
    var wrapped: Certificate.PrivateKey { .init(self) }
}
@available(macOS 11.0, iOS 14, tvOS 14, watchOS 7, macCatalyst 14, visionOS 1.0, *)
extension Crypto.P521.Signing.PrivateKey: Key {
    var wrapped: Certificate.PrivateKey { .init(self) }
}
@available(macOS 11.0, iOS 14, tvOS 14, watchOS 7, macCatalyst 14, visionOS 1.0, *)
extension _CryptoExtras._RSA.Signing.PrivateKey: Key {
    var wrapped: Certificate.PrivateKey { .init(self) }
}

// MARK: Public Keys

@available(macOS 11.0, iOS 14, tvOS 14, watchOS 7, macCatalyst 14, visionOS 1.0, *)
extension Crypto.P256.Signing.PublicKey: Key {
    var wrapped: Certificate.PublicKey { .init(self) }
}
@available(macOS 11.0, iOS 14, tvOS 14, watchOS 7, macCatalyst 14, visionOS 1.0, *)
extension Crypto.P384.Signing.PublicKey: Key {
    var wrapped: Certificate.PublicKey { .init(self) }
}
@available(macOS 11.0, iOS 14, tvOS 14, watchOS 7, macCatalyst 14, visionOS 1.0, *)
extension Crypto.P521.Signing.PublicKey: Key {
    var wrapped: Certificate.PublicKey { .init(self) }
}
extension _CryptoExtras._RSA.Signing.PublicKey: Key {
    var wrapped: Certificate.PublicKey { .init(self) }
}

private protocol WrappedKey: Equatable {
    init(pemEncoded: String) throws
    func serializeAsPEM() throws -> PEMDocument
}

extension Certificate.PublicKey: WrappedKey {}
@available(macOS 11.0, iOS 14, tvOS 14, watchOS 7, macCatalyst 14, visionOS 1.0, *)
extension Certificate.PrivateKey: WrappedKey {}

final class PEMTests: XCTestCase {
    fileprivate func assertPEMRoundtrip(key: some Key, file: StaticString = #filePath, line: UInt = #line) throws {
        let initialPEMString = key.pemRepresentation
        let wrapped = try type(of: key).Wrapped(pemEncoded: initialPEMString)
        XCTAssertEqual(key.wrapped, wrapped, "Wrapper mismatch after one roundtrip for \(key)", file: file, line: line)
        let pemDocument = try key.wrapped.serializeAsPEM()
        let initialPEMDocument = try PEMDocument(pemString: initialPEMString)
        XCTAssertEqual(
            pemDocument.discriminator,
            initialPEMDocument.discriminator,
            "PEM discriminator mismatch after one roundtrip for \(key)",
            file: file,
            line: line
        )
        XCTAssertEqual(
            pemDocument.pemString,
            initialPEMDocument.pemString,
            "PEM string mismatch after one roundtrip for \(key)",
            file: file,
            line: line
        )
    }

    func testPublicKeys() throws {
        try assertPEMRoundtrip(key: P256.Signing.PrivateKey().publicKey)
        try assertPEMRoundtrip(key: P384.Signing.PrivateKey().publicKey)
        try assertPEMRoundtrip(key: P521.Signing.PrivateKey().publicKey)
        try assertPEMRoundtrip(key: _RSA.Signing.PrivateKey(keySize: .bits2048).publicKey)
    }

    func testPrivateKeys() throws {
        try assertPEMRoundtrip(key: P256.Signing.PrivateKey())
        try assertPEMRoundtrip(key: P384.Signing.PrivateKey())
        try assertPEMRoundtrip(key: P521.Signing.PrivateKey())
        try assertPEMRoundtrip(key: _RSA.Signing.PrivateKey(keySize: .bits2048))
    }

    @available(macOS 11.0, iOS 14, tvOS 14, watchOS 7, macCatalyst 14, visionOS 1.0, *)
    func testRSAPrivateKey() throws {
        // generated with "openssl genpkey -algorithm rsa"
        let rsaKey = try String(
            contentsOf: XCTUnwrap(Bundle.module.url(forResource: "PEMTestRSACertificate", withExtension: "pem")),
            encoding: .ascii
        )
        let privateKey = try Certificate.PrivateKey(pemEncoded: rsaKey)
        guard case .rsa = privateKey.backing else {
            XCTFail("parsed as wrong key type \(privateKey)")
            return
        }
        let privateKeyAfterRoundtrip = try Certificate.PrivateKey(pemDocument: privateKey.serializeAsPEM())
        XCTAssertEqual(privateKey, privateKeyAfterRoundtrip)
    }
}
