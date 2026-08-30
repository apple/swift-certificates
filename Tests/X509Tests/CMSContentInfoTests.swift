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
final class CMSContentInfoTests {
    static let rsaCertKey = try! Certificate.PrivateKey(_RSA.Signing.PrivateKey(keySize: .bits2048))
    static let rsaCertName = try! DistinguishedName { CommonName("ContentInfo RSA") }
    static let rsaCert = try! Certificate(
        version: .v3, serialNumber: .init(), publicKey: rsaCertKey.publicKey,
        notValidBefore: Date(), notValidAfter: Date().advanced(by: 60*60*24*360),
        issuer: rsaCertName, subject: rsaCertName, signatureAlgorithm: .sha256WithRSAEncryption,
        extensions: try! Certificate.Extensions { Critical(BasicConstraints.isCertificateAuthority(maxPathLength: nil)) },
        issuerPrivateKey: rsaCertKey
    )

    @Test("EnvelopedData content type")
    func envelopedDataContentType() throws {
        let encrypted = try CMS.encrypt(Array("test".utf8), recipientCertificates: [Self.rsaCert])
        let contentInfo = try CMSContentInfo(berEncoded: ArraySlice(encrypted))
        #expect(contentInfo.contentType == .cmsEnvelopedData)
        #expect(try contentInfo.envelopedData != nil)
        #expect(try contentInfo.signedData == nil)
        #expect(try contentInfo.encryptedData == nil)
        #expect(try contentInfo.digestedData == nil)
        #expect(try contentInfo.authenticatedData == nil)
    }

    @Test("DigestedData content type")
    func digestedDataContentType() throws {
        let digested = try CMS.digest(Array("test".utf8))
        let contentInfo = try CMSContentInfo(berEncoded: ArraySlice(digested))
        #expect(contentInfo.contentType == .cmsDigestedData)
        #expect(try contentInfo.digestedData != nil)
        #expect(try contentInfo.envelopedData == nil)
        #expect(try contentInfo.signedData == nil)
        #expect(try contentInfo.encryptedData == nil)
        #expect(try contentInfo.authenticatedData == nil)
    }

    @Test("BER content accessor uses BER parser")
    func berContentAccessorUsesBERParser() throws {
        let contentInfoBytes: [UInt8] = [
            0x30, 0x3c,  // ContentInfo SEQUENCE
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x05,  // id-digestedData
            0xa0, 0x2f,  // [0] EXPLICIT content
            0x30, 0x2d,  // DigestedData SEQUENCE
            0x02, 0x01, 0x00,  // version
            0x30, 0x0b,  // digestAlgorithm
            0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01,  // sha256
            0x30, 0x18,  // encapContentInfo
            0x06, 0x09, 0x2a, 0x86, 0x48, 0x86, 0xf7, 0x0d, 0x01, 0x07, 0x01,  // id-data
            0xa0, 0x0b,  // eContent [0] EXPLICIT
            0x24, 0x09,  // constructed OCTET STRING
            0x04, 0x02, 0x68, 0x65,  // "he"
            0x04, 0x03, 0x6c, 0x6c, 0x6f,  // "llo"
            0x04, 0x01, 0x00,  // digest
        ]
        let contentInfo = try CMSContentInfo(berEncoded: ArraySlice(contentInfoBytes))
        let digestedData = try #require(try contentInfo.digestedData)
        let content = try #require(digestedData.encapContentInfo.eContent)

        #expect(Array(content.bytes) == Array("hello".utf8))
    }

    @Test("EncryptedData content type")
    func encryptedDataContentType() throws {
        let key = SymmetricKey(size: .bits256)
        let encrypted = try CMS.encrypt(Array("test".utf8), usingKey: key)
        let contentInfo = try CMSContentInfo(berEncoded: ArraySlice(encrypted))
        #expect(contentInfo.contentType == .cmsEncryptedData)
        #expect(try contentInfo.encryptedData != nil)
        #expect(try contentInfo.envelopedData == nil)
        #expect(try contentInfo.signedData == nil)
        #expect(try contentInfo.digestedData == nil)
        #expect(try contentInfo.authenticatedData == nil)
    }

    @Test("AuthenticatedData content type")
    func authenticatedDataContentType() throws {
        let authBytes = try CMS.authenticate(Array("test".utf8), recipientCertificates: [Self.rsaCert])
        let contentInfo = try CMSContentInfo(berEncoded: ArraySlice(authBytes))
        #expect(contentInfo.contentType == .cmsAuthenticatedData)
        #expect(try contentInfo.authenticatedData != nil)
        #expect(try contentInfo.envelopedData == nil)
        #expect(try contentInfo.signedData == nil)
        #expect(try contentInfo.encryptedData == nil)
        #expect(try contentInfo.digestedData == nil)
    }

    @Test("SignedData content type")
    func signedDataContentType() throws {
        let signed = try CMS.sign(
            Array("test".utf8),
            certificate: Self.rsaCert,
            privateKey: Self.rsaCertKey
        )
        let contentInfo = try CMSContentInfo(berEncoded: ArraySlice(signed))
        #expect(contentInfo.contentType == .cmsSignedData)
        #expect(try contentInfo.signedData != nil)
        #expect(try contentInfo.envelopedData == nil)
        #expect(try contentInfo.encryptedData == nil)
        #expect(try contentInfo.digestedData == nil)
        #expect(try contentInfo.authenticatedData == nil)
    }
}
