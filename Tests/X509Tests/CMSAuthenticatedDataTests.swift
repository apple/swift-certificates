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
final class CMSAuthenticatedDataTests {
    static let rsaCertKey = try! Certificate.PrivateKey(_RSA.Signing.PrivateKey(keySize: .bits2048))
    static let rsaCertName = try! DistinguishedName { CommonName("Auth RSA") }
    static let rsaCert = try! Certificate(
        version: .v3, serialNumber: .init(), publicKey: rsaCertKey.publicKey,
        notValidBefore: Date(), notValidAfter: Date().advanced(by: 60*60*24*360),
        issuer: rsaCertName, subject: rsaCertName, signatureAlgorithm: .sha256WithRSAEncryption,
        extensions: try! Certificate.Extensions { Critical(BasicConstraints.isCertificateAuthority(maxPathLength: nil)) },
        issuerPrivateKey: rsaCertKey
    )

    @Test("Authenticate and verify")
    func authenticateAndVerify() throws {
        let data = Array("authenticated data".utf8)
        let authBytes = try CMS.authenticate(data, recipientCertificates: [Self.rsaCert])
        let isValid = try CMS.verifyAuthentication(
            authBytes,
            recipientCertificate: Self.rsaCert,
            privateKey: Self.rsaCertKey
        )
        #expect(isValid)
    }
    @Test("Verify with wrong certificate throws no matching recipient")
    func verifyWithWrongCertificateThrows() throws {
        let data = Array("test".utf8)
        let authBytes = try CMS.authenticate(data, recipientCertificates: [Self.rsaCert])

        // Create a different RSA certificate
        let otherKey = try Certificate.PrivateKey(_RSA.Signing.PrivateKey(keySize: .bits2048))
        let otherName = try DistinguishedName { CommonName("Other RSA") }
        let otherCert = try Certificate(
            version: .v3, serialNumber: .init(), publicKey: otherKey.publicKey,
            notValidBefore: Date(), notValidAfter: Date().advanced(by: 60 * 60 * 24 * 360),
            issuer: otherName, subject: otherName,
            signatureAlgorithm: .sha256WithRSAEncryption,
            extensions: try Certificate.Extensions {
                Critical(BasicConstraints.isCertificateAuthority(maxPathLength: nil))
            },
            issuerPrivateKey: otherKey
        )

        #expect(throws: CMS.EncryptionError.noMatchingRecipient) {
            try CMS.verifyAuthentication(
                authBytes, recipientCertificate: otherCert, privateKey: otherKey
            )
        }
    }

    @Test("Tampered authenticated data fails")
    func tamperedAuthenticatedDataFails() throws {
        let data = Array("authenticated data".utf8)
        var authBytes = try CMS.authenticate(data, recipientCertificates: [Self.rsaCert])
        // Tamper with a byte near the end
        authBytes[authBytes.count - 5] ^= 0xFF
        do {
            let isValid = try CMS.verifyAuthentication(
                authBytes,
                recipientCertificate: Self.rsaCert,
                privateKey: Self.rsaCertKey
            )
            #expect(!isValid)
        } catch is ASN1Error {
            // Tampered bytes may break ASN.1 parsing
        } catch is CMS.EncryptionError {
            // Tampered bytes may hit CMS validation guards
        }
    }

    @Test("AuthenticatedData ContentInfo structure")
    func authenticatedDataContentInfoStructure() throws {
        let data = Array("test".utf8)
        let authBytes = try CMS.authenticate(data, recipientCertificates: [Self.rsaCert])
        let contentInfo = try CMSContentInfo(berEncoded: ArraySlice(authBytes))
        #expect(contentInfo.contentType == .cmsAuthenticatedData)
        let authData = try #require(try contentInfo.authenticatedData)
        #expect(authData.macAlgorithm == .hmacWithSHA256)
    }

    @Test("Rejects unsupported MAC algorithm")
    func rejectsUnsupportedMACAlgorithm() throws {
        let authData = CMSAuthenticatedData(
            version: .v0,
            originatorInfo: nil,
            recipientInfos: [],
            macAlgorithm: .sha256,
            digestAlgorithm: nil,
            encapContentInfo: CMSEncapsulatedContentInfo(
                eContentType: .cmsData,
                eContent: ASN1OctetString(contentBytes: [1, 2, 3])
            ),
            authAttrs: nil,
            mac: ASN1OctetString(contentBytes: [0]),
            unauthAttrs: nil
        )
        let bytes = try CMSContentInfo(authData).encodedBytes

        #expect {
            try CMS.verifyAuthentication(
                bytes,
                recipientCertificate: Self.rsaCert,
                privateKey: Self.rsaCertKey
            )
        } throws: { error in
            guard case CMS.EncryptionError.unsupportedAlgorithm = error else { return false }
            return true
        }
    }

    @Test("Authenticated attributes round trip")
    func authenticatedAttributesRoundTrip() throws {
        let data = Array("authenticated data with attrs".utf8)
        let authBytes = try CMS.authenticate(
            data,
            recipientCertificates: [Self.rsaCert],
            includeAuthenticatedAttributes: true
        )
        let contentInfo = try CMSContentInfo(berEncoded: ArraySlice(authBytes))
        #expect(contentInfo.contentType == .cmsAuthenticatedData)
        let authData = try #require(try contentInfo.authenticatedData)
        #expect(authData.authAttrs != nil)
        #expect(authData.digestAlgorithm != nil)

        guard let authAttrs = authData.authAttrs else {
            Issue.record("Expected non-nil authAttrs")
            return
        }
        #expect(try authAttrs.contentType == .cmsData)
        #expect(try authAttrs.messageDigest != nil)

        #expect(try CMS.verifyAuthentication(
            authBytes,
            recipientCertificate: Self.rsaCert,
            privateKey: Self.rsaCertKey
        ))
    }

    @Test("Rejects digestAlgorithm without authAttrs")
    func rejectsDigestAlgorithmWithoutAuthAttrs() throws {
        let authData = CMSAuthenticatedData(
            version: .v0,
            originatorInfo: nil,
            recipientInfos: [],
            macAlgorithm: .hmacWithSHA256,
            digestAlgorithm: .sha256,
            encapContentInfo: CMSEncapsulatedContentInfo(
                eContentType: .cmsData,
                eContent: ASN1OctetString(contentBytes: [1, 2, 3])
            ),
            authAttrs: nil,
            mac: ASN1OctetString(contentBytes: [0]),
            unauthAttrs: nil
        )
        var serializer = DER.Serializer()
        try serializer.serialize(CMSContentInfo(authData))
        let bytes = serializer.serializedBytes

        #expect {
            try CMS.verifyAuthentication(
                bytes,
                recipientCertificate: Self.rsaCert,
                privateKey: Self.rsaCertKey
            )
        } throws: { error in
            guard case CMS.EncryptionError.unsupportedAlgorithm = error else { return false }
            return true
        }
    }

    static let rsaCertNoKeyEnciphermentKey = try! Certificate.PrivateKey(_RSA.Signing.PrivateKey(keySize: .bits2048))
    static let rsaCertNoKeyEnciphermentName = try! DistinguishedName { CommonName("Auth RSA No KE") }
    static let rsaCertNoKeyEncipherment = try! Certificate(
        version: .v3,
        serialNumber: .init(),
        publicKey: rsaCertNoKeyEnciphermentKey.publicKey,
        notValidBefore: Date(),
        notValidAfter: Date().advanced(by: 60 * 60 * 24 * 360),
        issuer: rsaCertNoKeyEnciphermentName,
        subject: rsaCertNoKeyEnciphermentName,
        signatureAlgorithm: .sha256WithRSAEncryption,
        extensions: try! Certificate.Extensions {
            Critical(BasicConstraints.isCertificateAuthority(maxPathLength: nil))
            Critical(KeyUsage(digitalSignature: true))
        },
        issuerPrivateKey: rsaCertNoKeyEnciphermentKey
    )

    @Test("Authenticate rejects certificate missing keyEncipherment")
    func authenticateRejectsCertificateMissingKeyEncipherment() throws {
        let data = Array("test".utf8)
        #expect(throws: CMS.EncryptionError.invalidCMSBlock("Certificate missing keyEncipherment key usage")) {
            try CMS.authenticate(data, recipientCertificates: [Self.rsaCertNoKeyEncipherment])
        }
    }

    @Test("Authenticate allows missing keyEncipherment when validation is disabled")
    func authenticateAllowsMissingKeyEnciphermentWhenValidationDisabled() throws {
        let data = Array("test".utf8)
        let authBytes = try CMS.authenticate(
            data,
            recipientCertificates: [Self.rsaCertNoKeyEncipherment],
            validateRecipientKeyUsage: false
        )
        #expect(try CMS.verifyAuthentication(authBytes, recipientCertificate: Self.rsaCertNoKeyEncipherment, privateKey: Self.rsaCertNoKeyEnciphermentKey))
    }

    @Test("Authenticate with originator certificates")
    func authenticateWithOriginatorCertificates() throws {
        let data = Array("auth with originator".utf8)
        let authBytes = try CMS.authenticate(
            data,
            recipientCertificates: [Self.rsaCert],
            originatorCertificates: [Self.rsaCert]
        )
        let contentInfo = try CMSContentInfo(berEncoded: ArraySlice(authBytes))
        let authData = try #require(try contentInfo.authenticatedData)
        #expect(authData.originatorInfo?.certificates?.count == 1)

        #expect(try CMS.verifyAuthentication(
            authBytes,
            recipientCertificate: Self.rsaCert,
            privateKey: Self.rsaCertKey
        ))
    }
}

extension CMSContentInfo {
    fileprivate var encodedBytes: [UInt8] {
        get throws {
            var serializer = DER.Serializer()
            try serializer.serialize(self)
            return serializer.serializedBytes
        }
    }
}
