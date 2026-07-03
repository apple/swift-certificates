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

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import Testing
import Crypto
import _CryptoExtras
import SwiftASN1
@testable @_spi(CMS) import X509

@Suite
final class CMSEncryptedDataTests {
    @Test("Symmetric key encrypt/decrypt round trip")
    func symmetricKeyEncryptDecryptRoundTrip() throws {
        let key = SymmetricKey(size: .bits256)
        let plaintext = Array("encrypted data test".utf8)
        let encrypted = try CMS.encrypt(plaintext, usingKey: key)
        let decrypted = try CMS.decrypt(encrypted, usingKey: key)
        #expect(decrypted == plaintext)
    }

    @Test("Wrong key fails decryption")
    func wrongKeyFailsDecryption() throws {
        let key1 = SymmetricKey(size: .bits256)
        let key2 = SymmetricKey(size: .bits256)
        let plaintext = Array("test data for wrong key".utf8)
        let encrypted = try CMS.encrypt(plaintext, usingKey: key1)
        do {
            let decrypted = try CMS.decrypt(encrypted, usingKey: key2)
            // If decryption doesn't throw (valid padding by chance), output must differ
            #expect(decrypted != plaintext)
        } catch is CryptoKitError {
            // Expected: CryptoKit padding validation fails with wrong key
        } catch {
            Issue.record("Expected CryptoKitError from wrong-key CBC decrypt, got \(type(of: error)): \(error)")
        }
    }
    @Test("Decrypt rejects key-size mismatch")
    func decryptRejectsKeySizeMismatch() throws {
        let key256 = SymmetricKey(size: .bits256)
        let encrypted = try CMS.encrypt(Array("test".utf8), usingKey: key256)
        // Try decrypting AES-256-CBC content with a 128-bit key
        let key128 = SymmetricKey(size: .bits128)
        #expect(throws: CMS.EncryptionError.invalidContentEncryptionKeySize(expected: 32, actual: 16)) {
            try CMS.decrypt(encrypted, usingKey: key128)
        }
    }

    @Test("EncryptedData ContentInfo structure")
    func encryptedDataContentInfoStructure() throws {
        let key = SymmetricKey(size: .bits256)
        let encrypted = try CMS.encrypt(Array("test".utf8), usingKey: key)
        let contentInfo = try CMSContentInfo(berEncoded: ArraySlice(encrypted))
        #expect(contentInfo.contentType == .cmsEncryptedData)
        let encryptedData = try #require(try contentInfo.encryptedData)
        #expect(encryptedData.version == .v0)
        #expect(encryptedData.encryptedContentInfo.contentType == .cmsData)
    }

    @Test("Empty content round trip")
    func emptyContentRoundTrip() throws {
        let key = SymmetricKey(size: .bits256)
        let plaintext: [UInt8] = []
        let encrypted = try CMS.encrypt(plaintext, usingKey: key)
        let decrypted = try CMS.decrypt(encrypted, usingKey: key)
        #expect(decrypted == plaintext)
    }

    @Test("128-bit key encrypt/decrypt round trip")
    func symmetricKey128BitRoundTrip() throws {
        let key = SymmetricKey(size: .bits128)
        let plaintext = Array("128-bit test".utf8)
        let encrypted = try CMS.encrypt(plaintext, usingKey: key)
        let contentInfo = try CMSContentInfo(berEncoded: ArraySlice(encrypted))
        let encryptedData = try #require(try contentInfo.encryptedData)
        #expect(
            encryptedData.encryptedContentInfo.contentEncryptionAlgorithm.algorithm
                == .AlgorithmIdentifier.aes128CBC
        )
        let decrypted = try CMS.decrypt(encrypted, usingKey: key)
        #expect(decrypted == plaintext)
    }

    @Test("192-bit key encrypt/decrypt round trip")
    func symmetricKey192BitRoundTrip() throws {
        let key = SymmetricKey(size: .init(bitCount: 192))
        let plaintext = Array("192-bit test".utf8)
        let encrypted = try CMS.encrypt(plaintext, usingKey: key)
        let contentInfo = try CMSContentInfo(berEncoded: ArraySlice(encrypted))
        let encryptedData = try #require(try contentInfo.encryptedData)
        #expect(
            encryptedData.encryptedContentInfo.contentEncryptionAlgorithm.algorithm
                == .AlgorithmIdentifier.aes192CBC
        )
        let decrypted = try CMS.decrypt(encrypted, usingKey: key)
        #expect(decrypted == plaintext)
    }

    @Test("Unsupported key size throws")
    func unsupportedKeySizeThrows() throws {
        let key = SymmetricKey(size: .init(bitCount: 64))
        #expect(throws: CMS.EncryptionError.invalidCMSBlock("Unsupported symmetric key size 64 bits; expected 128, 192, or 256")) {
            try CMS.encrypt(Array("test".utf8), usingKey: key)
        }
    }

    @Test("AES-256-GCM direct-key encrypt/decrypt round trip")
    func aes256GCMEncryptDecryptRoundTrip() throws {
        let key = SymmetricKey(size: .bits256)
        let plaintext = Array("GCM encrypted data test".utf8)
        let encrypted = try CMS.encrypt(plaintext, usingKey: key, contentEncryptionAlgorithm: .aes256GCM)

        let contentInfo = try CMSContentInfo(berEncoded: ArraySlice(encrypted))
        #expect(contentInfo.contentType == .cmsEncryptedData)
        let encryptedData = try #require(try contentInfo.encryptedData)
        #expect(
            encryptedData.encryptedContentInfo.contentEncryptionAlgorithm.algorithm
                == .AlgorithmIdentifier.aes256GCM
        )

        let decrypted = try CMS.decrypt(encrypted, usingKey: key)
        #expect(decrypted == plaintext)
    }

    @Test("AES-256-GCM encrypt rejects 128-bit key")
    func aes256GCMRejects128BitKey() throws {
        let key = SymmetricKey(size: .bits128)
        #expect(throws: CMS.EncryptionError.invalidContentEncryptionKeySize(expected: 32, actual: 16)) {
            try CMS.encrypt(Array("test".utf8), usingKey: key, contentEncryptionAlgorithm: .aes256GCM)
        }
    }
}
