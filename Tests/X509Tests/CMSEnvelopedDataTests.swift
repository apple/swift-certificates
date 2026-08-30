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
final class CMSEnvelopedDataTests {
    static let plaintext = Array("swift-certificates cms enveloped data".utf8)

    static let rsaCertKey = try! Certificate.PrivateKey(_RSA.Signing.PrivateKey(keySize: .bits2048))
    static let rsaCertName = try! DistinguishedName {
        CommonName("Test RSA")
    }
    static let rsaCert = try! Certificate(
        version: .v3,
        serialNumber: .init(),
        publicKey: rsaCertKey.publicKey,
        notValidBefore: Date(),
        notValidAfter: Date().advanced(by: 60 * 60 * 24 * 360),
        issuer: rsaCertName,
        subject: rsaCertName,
        signatureAlgorithm: .sha256WithRSAEncryption,
        extensions: try! Certificate.Extensions {
            Critical(BasicConstraints.isCertificateAuthority(maxPathLength: nil))
        },
        issuerPrivateKey: rsaCertKey
    )

    static let rsaCert2Key = try! Certificate.PrivateKey(_RSA.Signing.PrivateKey(keySize: .bits2048))
    static let rsaCert2Name = try! DistinguishedName {
        CommonName("Test RSA 2")
    }
    static let rsaCert2 = try! Certificate(
        version: .v3,
        serialNumber: .init(),
        publicKey: rsaCert2Key.publicKey,
        notValidBefore: Date(),
        notValidAfter: Date().advanced(by: 60 * 60 * 24 * 360),
        issuer: rsaCert2Name,
        subject: rsaCert2Name,
        signatureAlgorithm: .sha256WithRSAEncryption,
        extensions: try! Certificate.Extensions {
            Critical(BasicConstraints.isCertificateAuthority(maxPathLength: nil))
        },
        issuerPrivateKey: rsaCert2Key
    )

    static let rsaCertWithSKIKey = try! Certificate.PrivateKey(_RSA.Signing.PrivateKey(keySize: .bits2048))
    static let rsaCertWithSKIName = try! DistinguishedName {
        CommonName("Test RSA SKI")
    }
    static let rsaCertWithSKI = try! Certificate(
        version: .v3,
        serialNumber: .init(),
        publicKey: rsaCertWithSKIKey.publicKey,
        notValidBefore: Date(),
        notValidAfter: Date().advanced(by: 60 * 60 * 24 * 360),
        issuer: rsaCertWithSKIName,
        subject: rsaCertWithSKIName,
        signatureAlgorithm: .sha256WithRSAEncryption,
        extensions: try! Certificate.Extensions {
            Critical(BasicConstraints.isCertificateAuthority(maxPathLength: nil))
            SubjectKeyIdentifier(keyIdentifier: [0xAA, 0xBB, 0xCC, 0xDD])
        },
        issuerPrivateKey: rsaCertWithSKIKey
    )

    static let rsaCertSignatureOnlyKeyUsageKey = try! Certificate.PrivateKey(_RSA.Signing.PrivateKey(keySize: .bits2048))
    static let rsaCertSignatureOnlyKeyUsageName = try! DistinguishedName {
        CommonName("Test RSA Signature Only")
    }
    static let rsaCertSignatureOnlyKeyUsage = try! Certificate(
        version: .v3,
        serialNumber: .init(),
        publicKey: rsaCertSignatureOnlyKeyUsageKey.publicKey,
        notValidBefore: Date(),
        notValidAfter: Date().advanced(by: 60 * 60 * 24 * 360),
        issuer: rsaCertSignatureOnlyKeyUsageName,
        subject: rsaCertSignatureOnlyKeyUsageName,
        signatureAlgorithm: .sha256WithRSAEncryption,
        extensions: try! Certificate.Extensions {
            Critical(BasicConstraints.isCertificateAuthority(maxPathLength: nil))
            KeyUsage(digitalSignature: true, keyCertSign: true)
        },
        issuerPrivateKey: rsaCertSignatureOnlyKeyUsageKey
    )

    static let kek = SymmetricKey(size: .bits256)
    static let kekKeyIdentifier: [UInt8] = [0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08]
    static let password = "cms-test-password"

    static let opensslFixtureCertificateDER = try! decodeBase64(
        """
        MIICtDCCAZwCCQDNVqbHGgw8GDANBgkqhkiG9w0BAQsFADAcMRowGAYDVQQDDBFDTVNPcGVuU1NMRml4dHVyZTAeFw0yNjA2MTIwNTU1NDJaFw0zNjA2MDkwNTU1NDJaMBwxGjAYBgNVBAMMEUNNU09wZW5TU0xGaXh0dXJlMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAxoTabhe1qVR62CFH0BzjzVg7jVy5z6keOZ/NNLVwNaj6g3fMfye1+Br3BeGbsrkI6TkijUy/4iJGrZcPg/2tvEBXQ07G18mZLxLbe19V9slGOuSAb+oo+LA+6JJGSSaUqFHy+fBhfkNNk4+Y3vSO+GLLGllUbBspnb7fzCSe++cj3rfLYTnU2NlQ/W+kLMMDFWbKi2BM9uhlmX7vqf/4X55UMFKYLCSsjGEl5ZY4APsFFJKlF7T13EgAmPXUY+yuVOu27aUiI0TP9zaSUv9jZAYTygGWtY/syFRMyhcmHtqVyb3Gr2HhnkAR8+OKCUXEdcD9l3CkZuak5umHGMLF1wIDAQABMA0GCSqGSIb3DQEBCwUAA4IBAQCSEN2jibY3zSiWo0XL5KKVnXhzJspi6XqHcUopHwuWyuxwLO+SJdWWCS2hCVFGAcEcSLaPp7KTIDUzCYlB7+Q1udEu/BwtrwUmGJtk/2zQQcbM+3BvbvDyw0AFfENZyCBFH8HBs2uVqE3SsrRDHtbvxR/PI7FWFHgd9rGtAH67Tp8gV4s8kw7CxYklwRzekbP8qSqkG98z5fgzzdx1vbRb8cenewi1ulQVqQgw2OGhwdkQySQgM9G1sp80zS5mZDayumtwGjfs7+dPKY9S2Xi4XWHWAMXAou01Fbw59CEXWG41meig+9teOhgXHypc9Pkyh0voAL2TSEgVFZ205Fx2
        """
    )

    static let opensslFixturePrivateKeyDER = try! decodeBase64(
        """
        MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDGhNpuF7WpVHrYIUfQHOPNWDuNXLnPqR45n800tXA1qPqDd8x/J7X4GvcF4ZuyuQjpOSKNTL/iIkatlw+D/a28QFdDTsbXyZkvEtt7X1X2yUY65IBv6ij4sD7okkZJJpSoUfL58GF+Q02Tj5je9I74YssaWVRsGymdvt/MJJ775yPet8thOdTY2VD9b6QswwMVZsqLYEz26GWZfu+p//hfnlQwUpgsJKyMYSXlljgA+wUUkqUXtPXcSACY9dRj7K5U67btpSIjRM/3NpJS/2NkBhPKAZa1j+zIVEzKFyYe2pXJvcavYeGeQBHz44oJRcR1wP2XcKRm5qTm6YcYwsXXAgMBAAECggEBAJcLLkbls0qLBIy9ha5KzOjIYUdFbfsaaezeMXwRMLcjQrgUxntY85M6sQjAh36MWsNYvXlVFAoymiQp85wxv6akLcEAhzpYIT0309ciyn1i1xSoFzEPsOzG7JZ39RJjUGhhMcYJp6QyASxs7Zt15/IE+ROrNBis8hUbzZu9oVl3RChfYKWo1bDHCfe2u1A/zmSGjesjwS9wOyz6VTCSRSU9jigToMTwPBD6PwrLvdPTDW4SobWuxRVayPsqf9GBPoequhsohh6uOl85wdwU9DDbs6i6a7qs/KluylbbeAQsmZwPAkZlXOjgtc2RKBqhCGnVpXhgCYROMmGReA9I9sECgYEA9BuGi7eCxODC7WG/tsDC10FN6MSmQyxpv3ihmM8bvGDrUjwi/gKghjUzPQgvri+zSjt+bBAlqI3bPG3QZdaT7u1DJgceOFoGef1jfdIm1rsVxfGF0FcQniTdZ8LFMbHQTM10qU/fKxAhTCpi1XUHWWpclX0AtxNWNiakQhE3h20CgYEA0DDA6Yz/k+yaqsAyRgTQAEUu7MZZNcMtOzun+dqQ1FUZq2MHgwkwB5zYevjc/GjplknSDq7Xp/i1eMV50aM7gSKxTiD1Y7try/zsvo0h5vJgHoIemfHG24XK/Xp0lYLTV6+PeqkH5EbqAJHQmhGBuBSPqKMYecT29FFGaUq7Y9MCgYEAxPawyWt5CIKSxhdpKXy/ug/nXTnPLcRYTzZ2rWXva0CIoAIF+g8El0W14jkIv/OdJvh6OZeNy0Mq8sdor8ND+jVXSQfVSoLZVvUtogg/bmPmXaFT55dYwUHdpCt0EXT4LgBZcYQQ/h41v88zkCitlWhM7BHA0fe4SFlFkEl0FMECgYAQqJYHGh0pPPlzSEW9jI0IOID0uTpSLvfjkXZza6XDF7wiFp53QbjyIv6/eEJWgB6Qw/9m5V6kNiZvL3375E/SmXAOjFyWSlzpyac36BsaW7KNPmQsdUgwMJh5h97kR7+ZeJbGfdf/0BzRRtmmOlhi3mJQYByJQdVw3z//FNfBuQKBgQC7SFowYLHtRuxhLJcXB65a247rD9YGg0C0FwOfyIw6DyIizfEU2z7zK1jrjn8a2AxclDXLk/IbbrDb81zhtu0+XZIppF6Ykl5jLKOCraHprl1shfBEb0EdP0BOz9FyiN+uRotwDl3ql8W1HHAQUaKNydjC0qFfjDscmP+2IJhxWA==
        """
    )

    static let opensslFixtureCMSDER = try! decodeBase64(
        """
        MIIBrQYJKoZIhvcNAQcDoIIBnjCCAZoCAQAxggFFMIIBQQIBADApMBwxGjAYBgNVBAMMEUNNU09wZW5TU0xGaXh0dXJlAgkAzVamxxoMPBgwDQYJKoZIhvcNAQEBBQAEggEAwyAQLkg4FiXOwJPRTvQYrU3ugqZNx0UgX5vpos4/QmpVryqDCL7FRqpW+Xhr8fUIPF4BJSDLOVm99BUAf4OIx5MGP5JIvLKdEdfzVHm+THct131xv/b7ODTAHu+ZzUzGsPBA5kD6Y7fvDPiTSFnweIORIcN5RLwnQlPKLar549TxmT6OVDqpirB2kcIRC+H+bOWuVnRDzUkn8uczX8CShrLDtvgUMuN8YEocjME1EbP5Ep7g8eXImtiz0/KkV0x+EliJYwjHPAl8C0Ory7Hz+VL6Q1a+3XOWZf00/cr4ol7aSgdbS7Ao6x8sDHhdes/1xwswU+EFcUMqamMdXswBXTBMBgkqhkiG9w0BBwEwHQYJYIZIAWUDBAEqBBDFm79qKKr+hSkmh+9WnAsFgCDW71IDPUxnJV5xfV1sMWcyDjHEz6S3hMHqKm6fEVUxhA==
        """
    )

    private func envelopedData(from bytes: [UInt8]) throws -> CMSEnvelopedData {
        let contentInfo = try CMSContentInfo(berEncoded: ArraySlice(bytes))
        return try #require(try contentInfo.envelopedData)
    }

    private func firstKEKRecipient(in bytes: [UInt8]) throws -> CMSKEKRecipientInfo {
        let envelopedData = try self.envelopedData(from: bytes)
        return try #require(
            envelopedData.recipientInfos.lazy.compactMap { recipientInfo -> CMSKEKRecipientInfo? in
                if case .kekRecipientInfo(let kekRecipientInfo) = recipientInfo {
                    return kekRecipientInfo
                }
                return nil
            }.first
        )
    }

    private func firstPasswordRecipient(in bytes: [UInt8]) throws -> CMSPasswordRecipientInfo {
        let envelopedData = try self.envelopedData(from: bytes)
        return try #require(
            envelopedData.recipientInfos.lazy.compactMap { recipientInfo -> CMSPasswordRecipientInfo? in
                if case .passwordRecipientInfo(let passwordRecipientInfo) = recipientInfo {
                    return passwordRecipientInfo
                }
                return nil
            }.first
        )
    }

    private func assertRoundTrip(
        contentEncryptionAlgorithm: CMS.ContentEncryptionAlgorithm = .aes256CBC,
        keyEncryptionAlgorithm: CMS.KeyEncryptionAlgorithm = .rsaOAEPWithSHA256,
        allowLegacyKeyEncryption: Bool = false,
        sourceLocation: SourceLocation = #_sourceLocation
    ) throws {
        let encrypted = try CMS.encrypt(
            Self.plaintext,
            recipientCertificates: [Self.rsaCert],
            contentEncryptionAlgorithm: contentEncryptionAlgorithm,
            keyEncryptionAlgorithm: keyEncryptionAlgorithm
        )
        let decrypted = try CMS.decrypt(
            encrypted,
            recipientCertificate: Self.rsaCert,
            privateKey: Self.rsaCertKey,
            allowLegacyKeyEncryption: allowLegacyKeyEncryption
        )
        #expect(decrypted == Self.plaintext, sourceLocation: sourceLocation)
    }

    // MARK: - Algorithm combination tests

    @Test("Encrypt/decrypt AES-256-CBC with RSA-OAEP-SHA256")
    func encryptDecryptAES256CBCWithRSAOAEPSHA256() throws {
        try assertRoundTrip()
    }

    @Test("Encrypt/decrypt AES-128-CBC with RSA-OAEP-SHA256")
    func encryptDecryptAES128CBCWithRSAOAEPSHA256() throws {
        try assertRoundTrip(contentEncryptionAlgorithm: .aes128CBC)
    }

    @Test("Encrypt/decrypt AES-192-CBC with RSA-OAEP-SHA256")
    func encryptDecryptAES192CBCWithRSAOAEPSHA256() throws {
        try assertRoundTrip(contentEncryptionAlgorithm: .aes192CBC)
    }

    @Test("Encrypt/decrypt AES-128-GCM with RSA-OAEP-SHA256")
    func encryptDecryptAES128GCMWithRSAOAEPSHA256() throws {
        try assertRoundTrip(contentEncryptionAlgorithm: .aes128GCM)
    }

    @Test("Encrypt/decrypt AES-192-GCM with RSA-OAEP-SHA256")
    func encryptDecryptAES192GCMWithRSAOAEPSHA256() throws {
        try assertRoundTrip(contentEncryptionAlgorithm: .aes192GCM)
    }

    @Test("Encrypt/decrypt AES-256-GCM with RSA-OAEP-SHA256")
    func encryptDecryptAES256GCMWithRSAOAEPSHA256() throws {
        try assertRoundTrip(contentEncryptionAlgorithm: .aes256GCM)
    }


    @Test("Encrypt/decrypt AES-256-CBC with RSA-OAEP-SHA1")
    func encryptDecryptAES256CBCWithRSAOAEPSHA1() throws {
        try assertRoundTrip(keyEncryptionAlgorithm: .rsaOAEPWithSHA1)
    }

    @Test("Encrypt/decrypt AES-256-CBC with RSA-PKCS1v15")
    func encryptDecryptAES256CBCWithRSAPKCS1v15() throws {
        try assertRoundTrip(keyEncryptionAlgorithm: .rsaPKCS1v15, allowLegacyKeyEncryption: true)
    }

    // MARK: - Version tests

    @Test("Expected version is v0 for key transport recipient")
    func expectedVersionV0ForKeyTrans() throws {
        let encrypted = try CMS.encrypt(Self.plaintext, recipientCertificates: [Self.rsaCert])
        let envelopedData = try self.envelopedData(from: encrypted)
        #expect(envelopedData.expectedVersion == .v0)
        let recipientInfo = try #require(
            (envelopedData.recipientInfos.first).flatMap({ info -> CMSKeyTransRecipientInfo? in
                if case .keyTransRecipientInfo(let keyTransRecipientInfo) = info { return keyTransRecipientInfo }
                return nil
            })
        )
        #expect(recipientInfo.version == .v0)
        #expect(
            (recipientInfo.recipientIdentifier).matches(certificate: Self.rsaCert),
            "Expected recipient identifier to match the certificate"
        )
        if case .issuerAndSerialNumber = recipientInfo.recipientIdentifier {
            // expected
        } else {
            Issue.record("Expected issuerAndSerialNumber recipient identifier")
        }
    }

    @Test("Expected version is v2 when subject key identifier is used")
    func expectedVersionV2ForSKI() throws {
        let encrypted = try CMS.encrypt(Self.plaintext, recipientCertificates: [Self.rsaCertWithSKI])
        let envelopedData = try self.envelopedData(from: encrypted)
        #expect(envelopedData.expectedVersion == .v2)
        let recipientInfo = try #require(
            (envelopedData.recipientInfos.first).flatMap({ info -> CMSKeyTransRecipientInfo? in
                if case .keyTransRecipientInfo(let keyTransRecipientInfo) = info { return keyTransRecipientInfo }
                return nil
            })
        )
        #expect(recipientInfo.version == .v2)
        if case .subjectKeyIdentifier = recipientInfo.recipientIdentifier {
            // expected
        } else {
            Issue.record("Expected subjectKeyIdentifier recipient identifier")
        }
    }

    @Test("Expected version is v2 for key agreement recipient")
    func expectedVersionV2ForKeyAgree() throws {
        let envelopedData = try CMSEnvelopedData(
            version: .v0,
            originatorInfo: nil,
            recipientInfos: [
                .keyAgreeRecipientInfo(
                    CMSKeyAgreeRecipientInfo(
                        originator: .subjectKeyIdentifier(SubjectKeyIdentifier(keyIdentifier: [1])),
                        keyEncryptionAlgorithm: AlgorithmIdentifier(algorithm: [1, 2, 3], parameters: nil),
                        recipientEncryptedKeys: [
                            CMSRecipientEncryptedKey(
                                recipientIdentifier: .recipientKeyIdentifier(
                                    CMSRecipientKeyIdentifier(
                                        subjectKeyIdentifier: SubjectKeyIdentifier(keyIdentifier: [9])
                                    )
                                ),
                                encryptedKey: ASN1OctetString(contentBytes: [8])
                            )
                        ]
                    )
                )
            ],
            encryptedContentInfo: CMSEncryptedContentInfo(
                contentType: .cmsData,
                contentEncryptionAlgorithm: .cmsAES256CBC(
                    iv: ASN1OctetString(contentBytes: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
                ),
                encryptedContent: ASN1OctetString(contentBytes: [1, 2, 3])
            ),
            unprotectedAttrs: nil
        )
        #expect(envelopedData.expectedVersion == .v2)
    }

    @Test("Decrypt succeeds when key-agree recipient precedes key-trans recipient")
    func decryptSkipsKeyAgreeBeforeKeyTrans() throws {
        // Create EnvelopedData with RSA key-trans recipient
        let encrypted = try CMS.encrypt(Self.plaintext, recipientCertificates: [Self.rsaCert])
        let envelopedData = try self.envelopedData(from: encrypted)

        // Extract the keyTrans recipientInfo
        let keyTransRecipient = try #require(
            envelopedData.recipientInfos.first
        )
        guard case .keyTransRecipientInfo = keyTransRecipient else {
            Issue.record("Expected keyTransRecipientInfo")
            return
        }

        // Build a synthetic key-agreement recipient
        let keyAgreeRecipient: CMSRecipientInfo = .keyAgreeRecipientInfo(
            CMSKeyAgreeRecipientInfo(
                originator: .subjectKeyIdentifier(SubjectKeyIdentifier(keyIdentifier: [1])),
                keyEncryptionAlgorithm: AlgorithmIdentifier(algorithm: [1, 2, 3], parameters: nil),
                recipientEncryptedKeys: [
                    CMSRecipientEncryptedKey(
                        recipientIdentifier: .recipientKeyIdentifier(
                            CMSRecipientKeyIdentifier(
                                subjectKeyIdentifier: SubjectKeyIdentifier(keyIdentifier: [9])
                            )
                        ),
                        encryptedKey: ASN1OctetString(contentBytes: [8])
                    )
                ]
            )
        )

        // Construct new EnvelopedData with keyAgree before keyTrans
        var newEnvelopedData = CMSEnvelopedData(
            version: .v0,
            originatorInfo: nil,
            recipientInfos: [keyAgreeRecipient, keyTransRecipient],
            encryptedContentInfo: envelopedData.encryptedContentInfo,
            unprotectedAttrs: nil
        )
        newEnvelopedData.version = newEnvelopedData.expectedVersion

        // Serialize and decrypt — must NOT throw unsupportedAlgorithm
        let newBytes = try CMS.serializeCMSContentInfo(CMSContentInfo(newEnvelopedData))
        let decrypted = try CMS.decrypt(
            newBytes,
            recipientCertificate: Self.rsaCert,
            privateKey: Self.rsaCertKey
        )
        #expect(decrypted == Self.plaintext)
    }

    @Test("Expected version is v4 for KEK recipient")
    func expectedVersionV4ForKEK() throws {
        let envelopedData = try CMSEnvelopedData(
            version: .v0,
            originatorInfo: nil,
            recipientInfos: [
                .kekRecipientInfo(
                    CMSKEKRecipientInfo(
                        kekIdentifier: CMSKEKIdentifier(
                            keyIdentifier: ASN1OctetString(contentBytes: Self.kekKeyIdentifier[...])
                        ),
                        keyEncryptionAlgorithm: .cmsAESKeyWrap256,
                        encryptedKey: ASN1OctetString(contentBytes: [4, 5, 6])
                    )
                )
            ],
            encryptedContentInfo: CMSEncryptedContentInfo(
                contentType: .cmsData,
                contentEncryptionAlgorithm: .cmsAES256CBC(
                    iv: ASN1OctetString(contentBytes: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
                ),
                encryptedContent: ASN1OctetString(contentBytes: [1, 2, 3])
            ),
            unprotectedAttrs: nil
        )
        #expect(envelopedData.expectedVersion == .v4)
    }

    // MARK: - KEK tests

    @Test("Encrypt/decrypt with KEK")
    func encryptDecryptWithKEK() throws {
        let encrypted = try CMS.encrypt(
            Self.plaintext,
            usingKEK: Self.kek,
            keyIdentifier: Self.kekKeyIdentifier[...]
        )
        let envelopedData = try self.envelopedData(from: encrypted)
        #expect(envelopedData.expectedVersion == .v4)

        let decrypted = try CMS.decrypt(encrypted, usingKEK: Self.kek)
        #expect(decrypted == Self.plaintext)
    }

    @Test("Encrypt/decrypt with KEK using AES-256-GCM")
    func encryptDecryptWithKEKUsingAES256GCM() throws {
        let encrypted = try CMS.encrypt(
            Self.plaintext,
            usingKEK: Self.kek,
            keyIdentifier: Self.kekKeyIdentifier[...],
            contentEncryptionAlgorithm: .aes256GCM
        )
        let envelopedData = try self.envelopedData(from: encrypted)
        #expect(envelopedData.expectedVersion == .v4)
        #expect(
            envelopedData.encryptedContentInfo.contentEncryptionAlgorithm.algorithm
            == .AlgorithmIdentifier.aes256GCM
        )

        let decrypted = try CMS.decrypt(encrypted, usingKEK: Self.kek)
        #expect(decrypted == Self.plaintext)
    }

    @Test("Decrypt with wrong KEK fails")
    func decryptWithWrongKEKFails() throws {
        let encrypted = try CMS.encrypt(
            Self.plaintext,
            usingKEK: Self.kek,
            keyIdentifier: Self.kekKeyIdentifier[...]
        )
        let wrongKEK = SymmetricKey(size: .bits256)

        #expect(throws: CryptoKitError.self) {
            try CMS.decrypt(encrypted, usingKEK: wrongKEK)
        }
    }

    @Test("KEK decrypt skips recipients that cannot unwrap the content key")
    func kekDecryptSkipsRecipientsThatCannotUnwrapContentKey() throws {
        let correctEncrypted = try CMS.encrypt(
            Self.plaintext,
            usingKEK: Self.kek,
            keyIdentifier: [0xff]
        )
        let wrongEncrypted = try CMS.encrypt(
            Self.plaintext,
            usingKEK: SymmetricKey(size: .bits256),
            keyIdentifier: [0x00]
        )
        let correctRecipient = try self.firstKEKRecipient(in: correctEncrypted)
        let wrongRecipient = try self.firstKEKRecipient(in: wrongEncrypted)

        var envelopedData = try self.envelopedData(from: correctEncrypted)
        envelopedData.recipientInfos = [
            .kekRecipientInfo(wrongRecipient),
            .kekRecipientInfo(correctRecipient),
        ]
        envelopedData.version = envelopedData.expectedVersion
        let combined = try CMSContentInfo(envelopedData).encodedBytes
        let reparsed = try self.envelopedData(from: combined)
        guard case .kekRecipientInfo(let firstRecipient) = reparsed.recipientInfos[0] else {
            Issue.record("Expected first recipient to be KEKRecipientInfo")
            return
        }
        #expect(Array(firstRecipient.kekIdentifier.keyIdentifier.bytes) == [0x00])

        let decrypted = try CMS.decrypt(combined, usingKEK: Self.kek)
        #expect(decrypted == Self.plaintext)
    }

    @Test("KEK decrypt rejects version mismatch")
    func kekDecryptRejectsVersionMismatch() throws {
        let encrypted = try CMS.encrypt(
            Self.plaintext,
            usingKEK: Self.kek,
            keyIdentifier: Self.kekKeyIdentifier[...]
        )
        var envelopedData = try self.envelopedData(from: encrypted)
        envelopedData.version = .v0
        let malformed = try CMSContentInfo(envelopedData).encodedBytes

        #expect(throws: CMS.EncryptionError.invalidVersion(expected: 4, actual: 0)) {
            try CMS.decrypt(malformed, usingKEK: Self.kek)
        }
    }

    @Test("KEK decrypt rejects key size that does not match key encryption algorithm")
    func kekDecryptRejectsKEKSizeAlgorithmMismatch() throws {
        // Build a CMS block where keyEncryptionAlgorithm claims AES Key Wrap 256
        // but the encrypted key was actually wrapped with a 128-bit KEK, so a
        // caller supplying that 128-bit KEK unwraps the content key successfully.
        // The decrypt path must validate that the supplied KEK size matches the
        // algorithm before attempting unwrap.
        let kek128 = SymmetricKey(size: .bits128)
        let contentKey = SymmetricKey(size: .bits256)
        let iv = AES._CBC.IV()
        let encryptedContent = try AES._CBC.encrypt(Self.plaintext, using: contentKey, iv: iv)
        let wrappedKey = try AES.KeyWrap.wrap(contentKey, using: kek128)

        var envelopedData = CMSEnvelopedData(
            version: .v0,
            originatorInfo: nil,
            recipientInfos: [
                .kekRecipientInfo(
                    CMSKEKRecipientInfo(
                        kekIdentifier: CMSKEKIdentifier(
                            keyIdentifier: ASN1OctetString(contentBytes: Self.kekKeyIdentifier[...])
                        ),
                        keyEncryptionAlgorithm: .cmsAESKeyWrap256,
                        encryptedKey: ASN1OctetString(contentBytes: Array(wrappedKey)[...])
                    )
                )
            ],
            encryptedContentInfo: CMSEncryptedContentInfo(
                contentType: .cmsData,
                contentEncryptionAlgorithm: try .cmsAES256CBC(
                    iv: ASN1OctetString(contentBytes: Array(iv)[...])
                ),
                encryptedContent: ASN1OctetString(contentBytes: Array(encryptedContent)[...])
            ),
            unprotectedAttrs: nil
        )
        envelopedData.version = envelopedData.expectedVersion
        let serialized = try CMSContentInfo(envelopedData).encodedBytes

        #expect(throws: (any Error).self) {
            try CMS.decrypt(serialized, usingKEK: kek128)
        }
    }

    @Test("RSA encrypt with originator certificates")
    func rsaEncryptWithOriginatorCertificates() throws {
        let encrypted = try CMS.encrypt(
            Self.plaintext,
            recipientCertificates: [Self.rsaCert],
            originatorCertificates: [Self.rsaCert]
        )
        let envelopedData = try self.envelopedData(from: encrypted)
        #expect(envelopedData.expectedVersion == .v2)
        #expect(envelopedData.originatorInfo?.certificates?.count == 1)

        let decrypted = try CMS.decrypt(
            encrypted,
            recipientCertificate: Self.rsaCert,
            privateKey: Self.rsaCertKey
        )
        #expect(decrypted == Self.plaintext)
    }

    // MARK: - Password tests

    @Test("Encrypt/decrypt with password")
    func encryptDecryptWithPassword() throws {
        let salt: [UInt8] = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80]
        let encrypted = try CMS.encrypt(
            Self.plaintext,
            usingPassword: Self.password,
            salt: salt,
            iterationCount: 100_000
        )
        let decrypted = try CMS.decrypt(encrypted, usingPassword: Self.password)
        #expect(decrypted == Self.plaintext)
    }

    @Test("Encrypt/decrypt with password using AES-256-GCM")
    func encryptDecryptWithPasswordUsingAES256GCM() throws {
        let salt: [UInt8] = [0x10, 0x20, 0x30, 0x40, 0x50, 0x60, 0x70, 0x80]
        let encrypted = try CMS.encrypt(
            Self.plaintext,
            usingPassword: Self.password,
            salt: salt,
            iterationCount: 100_000,
            contentEncryptionAlgorithm: .aes256GCM
        )
        let envelopedData = try self.envelopedData(from: encrypted)
        #expect(
            envelopedData.encryptedContentInfo.contentEncryptionAlgorithm.algorithm
            == .AlgorithmIdentifier.aes256GCM
        )

        let decrypted = try CMS.decrypt(encrypted, usingPassword: Self.password)
        #expect(decrypted == Self.plaintext)
    }

    @Test("Decrypt with wrong password fails")
    func decryptWithWrongPasswordFails() throws {
        let encrypted = try CMS.encrypt(
            Self.plaintext,
            usingPassword: Self.password,
            salt: [0x01, 0x02, 0x03, 0x04],
            iterationCount: 100_000
        )

        #expect(throws: CryptoKitError.self) {
            try CMS.decrypt(encrypted, usingPassword: "wrong-password")
        }
    }

    @Test("Password decrypt skips recipients that cannot unwrap the content key")
    func passwordDecryptSkipsRecipientsThatCannotUnwrapContentKey() throws {
        let correctEncrypted = try CMS.encrypt(
            Self.plaintext,
            usingPassword: Self.password,
            salt: [0xff, 0xff, 0xff, 0xff],
            iterationCount: 100_000
        )
        let wrongEncrypted = try CMS.encrypt(
            Self.plaintext,
            usingPassword: "wrong-password",
            salt: [0x00, 0x00, 0x00, 0x00],
            iterationCount: 100_000
        )
        let correctRecipient = try self.firstPasswordRecipient(in: correctEncrypted)
        let wrongRecipient = try self.firstPasswordRecipient(in: wrongEncrypted)

        var envelopedData = try self.envelopedData(from: correctEncrypted)
        envelopedData.recipientInfos = [
            .passwordRecipientInfo(wrongRecipient),
            .passwordRecipientInfo(correctRecipient),
        ]
        envelopedData.version = envelopedData.expectedVersion
        let combined = try CMSContentInfo(envelopedData).encodedBytes

        let decrypted = try CMS.decrypt(combined, usingPassword: Self.password)
        #expect(decrypted == Self.plaintext)
    }

    @Test("Password decrypt rejects version mismatch")
    func passwordDecryptRejectsVersionMismatch() throws {
        let salt: [UInt8] = [1, 2, 3, 4]
        let encrypted = try CMS.encrypt(
            Self.plaintext,
            usingPassword: Self.password,
            salt: salt,
            iterationCount: 100_000
        )
        var envelopedData = try self.envelopedData(from: encrypted)
        envelopedData.version = .v0
        let malformed = try CMSContentInfo(envelopedData).encodedBytes
        #expect(throws: CMS.EncryptionError.invalidVersion(expected: 3, actual: 0)) {
            try CMS.decrypt(malformed, usingPassword: Self.password)
        }
    }

    @Test("Expected version is v3 for password recipient")
    func expectedVersionV3ForPassword() throws {
        let salt: [UInt8] = [1, 2, 3, 4]
        let encrypted = try CMS.encrypt(
            Self.plaintext, usingPassword: Self.password, salt: salt, iterationCount: 100_000
        )
        let envelopedData = try self.envelopedData(from: encrypted)
        #expect(envelopedData.expectedVersion == .v3)
    }

    // MARK: - Error tests

    @Test("Decrypt with wrong recipient fails")
    func decryptWithWrongRecipientFails() throws {
        let encrypted = try CMS.encrypt(Self.plaintext, recipientCertificates: [Self.rsaCert])

        #expect(throws: CMS.EncryptionError.noMatchingRecipient) {
            try CMS.decrypt(encrypted, recipientCertificate: Self.rsaCert2, privateKey: Self.rsaCert2Key)
        }
    }

    @Test("Tampered ciphertext produces different output")
    func tamperedCiphertextProducesDifferentOutput() throws {
        var envelopedData = try self.envelopedData(
            from: CMS.encrypt(Self.plaintext, recipientCertificates: [Self.rsaCert])
        )
        var encryptedContent = try #require(envelopedData.encryptedContentInfo.encryptedContent)
        var contentBytes = Array(encryptedContent.bytes)
        if contentBytes.isEmpty {
            contentBytes.append(0xFF)
        } else {
            contentBytes[0] ^= 0xFF
        }
        encryptedContent = ASN1OctetString(contentBytes: contentBytes[...])
        envelopedData.encryptedContentInfo.encryptedContent = encryptedContent
        let encrypted = try CMSContentInfo(envelopedData).encodedBytes

        // AES-CBC doesn't authenticate; tampered ciphertext may still decrypt but to different plaintext
        do {
            let decrypted = try CMS.decrypt(encrypted, recipientCertificate: Self.rsaCert, privateKey: Self.rsaCertKey)
            #expect(decrypted != Self.plaintext)
        } catch is CryptoKitError {
            // Throwing is also acceptable (e.g., bad padding)
        }
    }

    @Test("AES-GCM tampered ciphertext fails decryption")
    func aesGCMTamperedCiphertextFailsDecryption() throws {
        let encrypted = try CMS.encrypt(
            Self.plaintext,
            recipientCertificates: [Self.rsaCert],
            contentEncryptionAlgorithm: .aes256GCM
        )
        var envelopedData = try self.envelopedData(from: encrypted)
        var encryptedContent = try #require(envelopedData.encryptedContentInfo.encryptedContent)
        var contentBytes = Array(encryptedContent.bytes)
        // Flip a bit in the authentication tag (last 16 bytes for GCM)
        contentBytes[contentBytes.count - 1] ^= 0xFF
        encryptedContent = ASN1OctetString(contentBytes: contentBytes[...])
        envelopedData.encryptedContentInfo.encryptedContent = encryptedContent
        let tampered = try CMSContentInfo(envelopedData).encodedBytes

        #expect(throws: CryptoKitError.self) {
            try CMS.decrypt(tampered, recipientCertificate: Self.rsaCert, privateKey: Self.rsaCertKey)
        }
    }

    @Test("RSA-PKCS1v15 decryption without opt-in fails")
    func rsaPKCS1v15DecryptionWithoutOptInFails() throws {
        let encrypted = try CMS.encrypt(
            Self.plaintext,
            recipientCertificates: [Self.rsaCert],
            keyEncryptionAlgorithm: .rsaPKCS1v15
        )

        #expect {
            try CMS.decrypt(encrypted, recipientCertificate: Self.rsaCert, privateKey: Self.rsaCertKey)
        } throws: { error in
            guard case CMS.EncryptionError.unsupportedAlgorithm(let detail) = error else {
                return false
            }
            return detail.contains("allowLegacyKeyEncryption")
        }
    }

    @Test("Encrypt fails when certificate lacks keyEncipherment key usage")
    func encryptFailsWhenCertificateLacksKeyEncipherment() throws {
        #expect {
            try CMS.encrypt(
                Self.plaintext,
                recipientCertificates: [Self.rsaCertSignatureOnlyKeyUsage]
            )
        } throws: { error in
            guard case CMS.EncryptionError.invalidCMSBlock(let detail) = error else {
                return false
            }
            return detail.contains("keyEncipherment")
        }
    }

    @Test("Encrypt succeeds when certificate has no key usage extension")
    func encryptSucceedsWhenCertificateHasNoKeyUsageExtension() throws {
        _ = try CMS.encrypt(Self.plaintext, recipientCertificates: [Self.rsaCert])
    }

    // MARK: - Multi-recipient

    @Test("Multiple recipients can decrypt the same EnvelopedData")
    func multipleRecipients() throws {
        let encrypted = try CMS.encrypt(
            Self.plaintext,
            recipientCertificates: [Self.rsaCert, Self.rsaCert2]
        )
        let envelopedData = try self.envelopedData(from: encrypted)
        #expect(envelopedData.recipientInfos.count == 2)

        let decrypted1 = try CMS.decrypt(
            encrypted,
            recipientCertificate: Self.rsaCert,
            privateKey: Self.rsaCertKey
        )
        let decrypted2 = try CMS.decrypt(
            encrypted,
            recipientCertificate: Self.rsaCert2,
            privateKey: Self.rsaCert2Key
        )
        #expect(decrypted1 == Self.plaintext)
        #expect(decrypted2 == Self.plaintext)
    }

    // MARK: - OpenSSL fixture

    @Test("Decrypt OpenSSL-generated RSA EnvelopedData fixture")
    func decryptOpenSSLGeneratedRSAEnvelopedDataFixture() throws {
        let certificate = try Certificate(derEncoded: Self.opensslFixtureCertificateDER)
        let privateKey = try Certificate.PrivateKey(derBytes: Self.opensslFixturePrivateKeyDER)
        let contentInfo = try CMSContentInfo(berEncoded: ArraySlice(Self.opensslFixtureCMSDER))
        let envelopedData = try #require(try contentInfo.envelopedData)
        let recipientInfo = try #require(
            (envelopedData.recipientInfos.first).flatMap({ info -> CMSKeyTransRecipientInfo? in
                if case .keyTransRecipientInfo(let keyTransRecipientInfo) = info { return keyTransRecipientInfo }
                return nil
            })
        )
        #expect(recipientInfo.recipientIdentifier.matches(certificate: certificate))

        let decrypted = try CMS.decrypt(
            Self.opensslFixtureCMSDER,
            recipientCertificate: certificate,
            privateKey: privateKey,
            allowLegacyKeyEncryption: true
        )
        #expect(decrypted == Array("OpenSSL CMS fixture".utf8))
    }

    #if os(macOS)

    @Test("OpenSSL can decrypt RSA-OAEP-SHA256 EnvelopedData produced by Swift")
    func opensslDecryptsRSAOAEP256EnvelopedData() throws {
        let encrypted = try CMS.encrypt(
            Self.plaintext,
            recipientCertificates: [Self.rsaCert],
            contentEncryptionAlgorithm: .aes256CBC,
            keyEncryptionAlgorithm: .rsaOAEPWithSHA256
        )

        let tempDir = FileManager.default.temporaryDirectory
            .appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: tempDir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: tempDir) }

        let certPEM = try Self.rsaCert.serializeAsPEM().pemString
        let certPath = tempDir.appendingPathComponent("cert.pem")
        try certPEM.write(to: certPath, atomically: true, encoding: .utf8)

        let privateKeyPEM: String
        switch Self.rsaCertKey.backing {
        case .rsa(let rsa):
            privateKeyPEM = rsa.pemRepresentation
        default:
            Issue.record("Expected RSA private key")
            return
        }
        let keyPath = tempDir.appendingPathComponent("key.pem")
        try privateKeyPEM.write(to: keyPath, atomically: true, encoding: .utf8)

        let cmsPath = tempDir.appendingPathComponent("envelope.der")
        try Data(encrypted).write(to: cmsPath)

        let process = Process()
        process.executableURL = URL(fileURLWithPath: "/usr/bin/env")
        process.arguments = [
            "openssl",
            "cms", "-decrypt",
            "-in", cmsPath.path,
            "-inform", "DER",
            "-inkey", keyPath.path,
            "-recip", certPath.path,
        ]
        let stdoutPipe = Pipe()
        let stderrPipe = Pipe()
        process.standardOutput = stdoutPipe
        process.standardError = stderrPipe
        try process.run()
        process.waitUntilExit()

        let stdoutData = stdoutPipe.fileHandleForReading.readDataToEndOfFile()
        let stderrData = stderrPipe.fileHandleForReading.readDataToEndOfFile()

        if process.terminationStatus != 0 {
            let stderr = String(data: stderrData, encoding: .utf8) ?? ""
            Issue.record("OpenSSL failed with status \(process.terminationStatus): \(stderr)")
        } else {
            #expect(Array(stdoutData) == Self.plaintext)
        }
    }
    #endif

    @Test("Decrypt rejects enveloped data version mismatch")
    func decryptRejectsVersionMismatch() throws {
        let envelopedData = CMSEnvelopedData(
            version: .v3,
            originatorInfo: nil,
            recipientInfos: [
                .keyAgreeRecipientInfo(
                    CMSKeyAgreeRecipientInfo(
                        originator: .subjectKeyIdentifier(SubjectKeyIdentifier(keyIdentifier: [1])),
                        keyEncryptionAlgorithm: AlgorithmIdentifier(algorithm: [1, 2, 3], parameters: nil),
                        recipientEncryptedKeys: [
                            CMSRecipientEncryptedKey(
                                recipientIdentifier: .recipientKeyIdentifier(
                                    CMSRecipientKeyIdentifier(
                                        subjectKeyIdentifier: SubjectKeyIdentifier(keyIdentifier: [9])
                                    )
                                ),
                                encryptedKey: ASN1OctetString(contentBytes: [8])
                            )
                        ]
                    )
                )
            ],
            encryptedContentInfo: CMSEncryptedContentInfo(
                contentType: .cmsData,
                contentEncryptionAlgorithm: try .cmsAES256CBC(
                    iv: ASN1OctetString(contentBytes: [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15])
                ),
                encryptedContent: ASN1OctetString(contentBytes: [1, 2, 3])
            ),
            unprotectedAttrs: nil
        )
        let encrypted = try CMSContentInfo(envelopedData).encodedBytes

        #expect(throws: CMS.EncryptionError.invalidVersion(expected: 2, actual: 3)) {
            try CMS.decrypt(encrypted, recipientCertificate: Self.rsaCert, privateKey: Self.rsaCertKey)
        }
    }

    @Test("Password recipient info omits optional key derivation algorithm")
    func passwordRecipientInfoOmitsOptionalKeyDerivationAlgorithm() throws {
        let withoutKeyDerivationAlgorithm = CMSPasswordRecipientInfo(
            keyEncryptionAlgorithm: AlgorithmIdentifier(algorithm: [1, 2, 3], parameters: nil),
            encryptedKey: ASN1OctetString(contentBytes: [4, 5, 6])
        )
        let reparsed = try CMSPasswordRecipientInfo(
            derEncoded: withoutKeyDerivationAlgorithm.encodedBytes
        )
        #expect(reparsed.keyDerivationAlgorithm == nil)
    }

    @Test("Encrypt with KEK rejects non-256-bit key")
    func encryptWithKEKRejectsNon256BitKey() throws {
        let kek128 = SymmetricKey(size: .bits128)
        #expect(throws: CMS.EncryptionError.invalidContentEncryptionKeySize(expected: 32, actual: 16)) {
            try CMS.encrypt(
                Self.plaintext,
                usingKEK: kek128,
                keyIdentifier: Self.kekKeyIdentifier[...]
            )
        }
    }

    private func replacingPasswordRecipient(
        in encrypted: [UInt8],
        _ transform: (inout CMSPasswordRecipientInfo) throws -> Void
    ) throws -> [UInt8] {
        var envelopedData = try self.envelopedData(from: encrypted)
        let recipientIndex = try #require(envelopedData.recipientInfos.firstIndex { recipientInfo in
            if case .passwordRecipientInfo = recipientInfo { return true }
            return false
        })
        guard case .passwordRecipientInfo(var passwordRecipient) = envelopedData.recipientInfos[recipientIndex] else {
            Issue.record("Expected password recipient")
            return encrypted
        }
        try transform(&passwordRecipient)
        envelopedData.recipientInfos[recipientIndex] = .passwordRecipientInfo(passwordRecipient)
        return try DER.Serializer.serialized(element: CMSContentInfo(envelopedData))
    }

    @Test("Password encrypt rejects non-positive PBKDF2 iteration count")
    func passwordEncryptRejectsNonPositivePBKDF2IterationCount() throws {
        #expect(throws: CMS.EncryptionError.invalidCMSBlock("PBKDF2 iteration count must be positive")) {
            try CMS.encrypt(Self.plaintext, usingPassword: Self.password, salt: [1, 2, 3, 4], iterationCount: 0)
        }
    }

    @Test("Password decrypt rejects non-positive PBKDF2 iteration count")
    func passwordDecryptRejectsNonPositivePBKDF2IterationCount() throws {
        let salt: [UInt8] = [1, 2, 3, 4]
        let encrypted = try CMS.encrypt(Self.plaintext, usingPassword: Self.password, salt: salt, iterationCount: 100_000)
        let malformed = try self.replacingPasswordRecipient(in: encrypted) { passwordRecipient in
            passwordRecipient.keyDerivationAlgorithm = AlgorithmIdentifier(
                algorithm: .AlgorithmIdentifier.pbkdf2,
                parameters: try ASN1Any(
                    erasing: CMSPBKDF2Params(
                        salt: ASN1OctetString(contentBytes: salt[...]),
                        iterationCount: 0,
                        keyLength: 32,
                        prf: .hmacWithSHA256
                    )
                )
            )
        }

        #expect(throws: CMS.EncryptionError.invalidCMSBlock("PBKDF2 iteration count must be positive")) {
            try CMS.decrypt(malformed, usingPassword: Self.password)
        }
    }

    @Test("Password decrypt rejects PBKDF2 key length mismatch")
    func passwordDecryptRejectsPBKDF2KeyLengthMismatch() throws {
        let salt: [UInt8] = [1, 2, 3, 4]
        let encrypted = try CMS.encrypt(Self.plaintext, usingPassword: Self.password, salt: salt, iterationCount: 100_000)
        let malformed = try self.replacingPasswordRecipient(in: encrypted) { passwordRecipient in
            passwordRecipient.keyDerivationAlgorithm = AlgorithmIdentifier(
                algorithm: .AlgorithmIdentifier.pbkdf2,
                parameters: try ASN1Any(
                    erasing: CMSPBKDF2Params(
                        salt: ASN1OctetString(contentBytes: salt[...]),
                        iterationCount: 100_000,
                        keyLength: 16,
                        prf: .hmacWithSHA256
                    )
                )
            )
        }

        #expect(throws: CMS.EncryptionError.invalidCMSBlock("PBKDF2 key length 16 does not match key-encryption algorithm; expected 32")) {
            try CMS.decrypt(malformed, usingPassword: Self.password)
        }
    }

}

extension DERSerializable {
    fileprivate var encodedBytes: [UInt8] {
        get throws {
            var serializer = DER.Serializer()
            try serializer.serialize(self)
            return serializer.serializedBytes
        }
    }
}

private func decodeBase64(_ base64: String) throws -> [UInt8] {
    let cleaned = base64.components(separatedBy: .whitespacesAndNewlines).joined()
    return try #require(Data(base64Encoded: cleaned)).map { $0 }
}
