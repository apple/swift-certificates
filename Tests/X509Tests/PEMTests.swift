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

fileprivate protocol Key {
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

extension Crypto.P256.Signing.PrivateKey: Key {
    var wrapped: Certificate.PrivateKey { .init(self) }
}
extension Crypto.P384.Signing.PrivateKey: Key {
    var wrapped: Certificate.PrivateKey { .init(self) }
}
extension Crypto.P521.Signing.PrivateKey: Key {
    var wrapped: Certificate.PrivateKey { .init(self) }
}
extension _CryptoExtras._RSA.Signing.PrivateKey: Key {
    var wrapped: Certificate.PrivateKey { .init(self) }
}

// MARK: Public Keys

extension Crypto.P256.Signing.PublicKey: Key {
    var wrapped: Certificate.PublicKey { .init(self) }
}
extension Crypto.P384.Signing.PublicKey: Key  {
    var wrapped: Certificate.PublicKey { .init(self) }
}
extension Crypto.P521.Signing.PublicKey: Key  {
    var wrapped: Certificate.PublicKey { .init(self) }
}
extension _CryptoExtras._RSA.Signing.PublicKey: Key  {
    var wrapped: Certificate.PublicKey { .init(self) }
}



fileprivate protocol WrappedKey: Equatable {
    init(pemEncoded: String) throws
    func serializeAsPEM() throws -> PEMDocument
}

extension Certificate.PublicKey: WrappedKey {}
extension Certificate.PrivateKey: WrappedKey {}


final class PEMTests: XCTestCase {
    fileprivate func assertPEMRoundtrip(key: some Key, file: StaticString = #filePath, line: UInt = #line) throws {
        let expectedPEMString = key.pemRepresentation
        let wrapped = try type(of: key).Wrapped(pemEncoded: expectedPEMString)
        XCTAssertEqual(key.wrapped, wrapped, file: file, line: line)
        let pemDocument = try key.wrapped.serializeAsPEM()
        XCTAssertEqual(pemDocument.discriminator, try key.pemDiscriminator, file: file, line: line)
        XCTAssertEqual(pemDocument.pemString, expectedPEMString, file: file, line: line)
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
}
