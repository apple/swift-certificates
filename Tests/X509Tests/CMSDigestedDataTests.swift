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
final class CMSDigestedDataTests {
    @Test("Digest and verify round trip")
    func digestAndVerifyRoundTrip() throws {
        let data = Array("test digest data".utf8)
        let digestedBytes = try CMS.digest(data)
        let isValid = try CMS.verifyDigest(digestedBytes)
        #expect(isValid)
    }

    @Test("Tampered digest fails verification")
    func tamperedDigestFailsVerification() throws {
        let data = Array("test digest data".utf8)
        var digestedBytes = try CMS.digest(data)
        // Tamper with a byte in the digest (last byte is inside the OCTET STRING digest value)
        digestedBytes[digestedBytes.count - 2] ^= 0xFF
        let isValid = try CMS.verifyDigest(digestedBytes)
        #expect(!isValid)
    }

    @Test("DigestedData ContentInfo parsing")
    func digestedDataContentInfoParsing() throws {
        let data = Array("test".utf8)
        let digestedBytes = try CMS.digest(data)
        let contentInfo = try CMSContentInfo(berEncoded: ArraySlice(digestedBytes))
        #expect(contentInfo.contentType == .cmsDigestedData)
        let digestedData = try #require(try contentInfo.digestedData)
        #expect(digestedData.version == .v0)
        #expect(digestedData.digestAlgorithm == .sha256)
    }

    @Test("DigestedData ContentInfo parsing - SHA-384")
    func digestedDataContentInfoParsingSHA384() throws {
        let data = Array("test".utf8)
        let digestedBytes = try CMS.digest(data, digestAlgorithm: .sha384)
        let contentInfo = try CMSContentInfo(berEncoded: ArraySlice(digestedBytes))
        #expect(contentInfo.contentType == .cmsDigestedData)
        let digestedData = try #require(try contentInfo.digestedData)
        #expect(digestedData.version == .v0)
        #expect(digestedData.digestAlgorithm == .sha384)
    }

    @Test("DigestedData ContentInfo parsing - SHA-512")
    func digestedDataContentInfoParsingSHA512() throws {
        let data = Array("test".utf8)
        let digestedBytes = try CMS.digest(data, digestAlgorithm: .sha512)
        let contentInfo = try CMSContentInfo(berEncoded: ArraySlice(digestedBytes))
        #expect(contentInfo.contentType == .cmsDigestedData)
        let digestedData = try #require(try contentInfo.digestedData)
        #expect(digestedData.version == .v0)
        #expect(digestedData.digestAlgorithm == .sha512)
    }

    @Test("Digest and verify round trip - SHA-384")
    func digestAndVerifyRoundTripSHA384() throws {
        let data = Array("test digest data".utf8)
        let digestedBytes = try CMS.digest(data, digestAlgorithm: .sha384)
        let isValid = try CMS.verifyDigest(digestedBytes)
        #expect(isValid)
    }

    @Test("Digest and verify round trip - SHA-512")
    func digestAndVerifyRoundTripSHA512() throws {
        let data = Array("test digest data".utf8)
        let digestedBytes = try CMS.digest(data, digestAlgorithm: .sha512)
        let isValid = try CMS.verifyDigest(digestedBytes)
        #expect(isValid)
    }

    @Test("Empty content round trip")
    func emptyContentRoundTrip() throws {
        let data: [UInt8] = []
        let digestedBytes = try CMS.digest(data)
        let isValid = try CMS.verifyDigest(digestedBytes)
        #expect(isValid)
    }

    @Test("verifyDigest rejects non-cmsData content type")
    func verifyDigestRejectsNonCMSDataContentType() throws {
        let data = Array("test".utf8)
        let digestedBytes = try CMS.digest(data)
        // Parse, mutate eContentType, re-serialize
        let contentInfo = try CMSContentInfo(berEncoded: ArraySlice(digestedBytes))
        var digestedData = try #require(try contentInfo.digestedData)
        digestedData.encapContentInfo = CMSEncapsulatedContentInfo(
            eContentType: .cmsSignedData,  // anything != .cmsData
            eContent: digestedData.encapContentInfo.eContent
        )
        let mutated = try DER.Serializer.serialized(element: CMSContentInfo(digestedData))

        #expect(throws: CMS.EncryptionError.invalidCMSBlock("Unsupported digested content type \(ASN1ObjectIdentifier.cmsSignedData)")) {
            try CMS.verifyDigest(mutated)
        }
    }
    @Test("verifyDigest rejects SHA-1 digest algorithm")
    func verifyDigestRejectsSHA1DigestAlgorithm() throws {
        let data = Array("test".utf8)
        let digest = Array(Insecure.SHA1.hash(data: data))
        let digestedData = CMSDigestedData(
            version: .v0,
            digestAlgorithm: .sha1,
            encapContentInfo: CMSEncapsulatedContentInfo(
                eContentType: .cmsData,
                eContent: ASN1OctetString(contentBytes: data[...])
            ),
            digest: ASN1OctetString(contentBytes: digest[...])
        )
        let encoded = try DER.Serializer.serialized(element: CMSContentInfo(digestedData))

        #expect {
            try CMS.verifyDigest(encoded)
        } throws: { error in
            guard case CMS.EncryptionError.unsupportedAlgorithm = error else { return false }
            return true
        }
    }

}
