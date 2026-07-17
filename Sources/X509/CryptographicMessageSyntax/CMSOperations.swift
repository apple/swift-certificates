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
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import SwiftASN1
import Crypto
import _CryptoExtras
#if canImport(Darwin)
import Darwin
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#elseif canImport(WinSDK)
import WinSDK
#endif

/// A namespace for Cryptographic Message Syntax (CMS) operations.
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public enum CMS: Sendable {
    @_spi(CMS)
    @inlinable
    public static func sign<Bytes: DataProtocol>(
        _ bytes: Bytes,
        signatureAlgorithm: Certificate.SignatureAlgorithm,
        additionalIntermediateCertificates: [Certificate] = [],
        certificate: Certificate,
        privateKey: Certificate.PrivateKey,
        signingTime: Date? = nil,
        detached: Bool = true
    ) throws -> [UInt8] {
        if let signingTime = signingTime {
            return try self.signWithSigningTime(
                bytes,
                signatureAlgorithm: signatureAlgorithm,
                additionalIntermediateCertificates: additionalIntermediateCertificates,
                certificate: certificate,
                privateKey: privateKey,
                signingTime: signingTime,
                detached: detached
            )
        }

        // no signing time provided, sign regularly (without signedAttrs)
        let signature = try privateKey.sign(bytes: bytes, signatureAlgorithm: signatureAlgorithm)
        let signedData = try self.generateSignedData(
            signatureBytes: ASN1OctetString(signature),
            signatureAlgorithm: signatureAlgorithm,
            additionalIntermediateCertificates: additionalIntermediateCertificates,
            certificate: certificate,
            withContent: detached ? nil : bytes
        )

        return try self.serializeSignedData(signedData)
    }

    @_spi(CMS)
    @inlinable
    public static func sign<Bytes: DataProtocol>(
        _ bytes: Bytes,
        additionalIntermediateCertificates: [Certificate] = [],
        certificate: Certificate,
        privateKey: Certificate.PrivateKey,
        signingTime: Date? = nil,
        detached: Bool = true
    ) throws -> [UInt8] {
        return try self.sign(
            bytes,
            signatureAlgorithm: privateKey.defaultSignatureAlgorithm,
            additionalIntermediateCertificates: additionalIntermediateCertificates,
            certificate: certificate,
            privateKey: privateKey,
            signingTime: signingTime,
            detached: detached
        )
    }

    @inlinable
    static func signWithSigningTime<Bytes: DataProtocol>(
        _ bytes: Bytes,
        signatureAlgorithm: Certificate.SignatureAlgorithm,
        additionalIntermediateCertificates: [Certificate] = [],
        certificate: Certificate,
        privateKey: Certificate.PrivateKey,
        signingTime: Date,
        detached: Bool = true
    ) throws -> [UInt8] {
        var signedAttrs: [CMSAttribute] = []
        // As specified in RFC 5652 section 11 when including signedAttrs we need to include a minimum of:
        // 1. content-type
        // 2. message-digest

        // add content-type signedAttr cms data
        let contentTypeVal = try ASN1Any(erasing: ASN1ObjectIdentifier.cmsData)
        let contentTypeAttribute = CMSAttribute(attrType: .contentType, attrValues: [contentTypeVal])
        signedAttrs.append(contentTypeAttribute)

        // add message-digest of provided content bytes
        let digestAlgorithm = try AlgorithmIdentifier(digestAlgorithmFor: signatureAlgorithm)
        let computedDigest = try Digest.computeDigest(for: bytes, using: digestAlgorithm)
        let messageDigest = ASN1OctetString(contentBytes: ArraySlice(computedDigest))
        let messageDigestVal = try ASN1Any(erasing: messageDigest)
        let messageDigestAttr = CMSAttribute(attrType: .messageDigest, attrValues: [messageDigestVal])
        signedAttrs.append(messageDigestAttr)

        // add signing time utc time in 'YYMMDDHHMMSSZ' format as specificed in `UTCTime`
        let utcTime = try UTCTime(signingTime.utcDate)
        let signingTimeAttrVal = try ASN1Any(erasing: utcTime)
        let signingTimeAttribute = CMSAttribute(attrType: .signingTime, attrValues: [signingTimeAttrVal])
        signedAttrs.append(signingTimeAttribute)

        // As specified in RFC 5652 section 5.4:
        // When the [signedAttrs] field is present, however, the result is the message digest of the complete DER encoding of the SignedAttrs value contained in the signedAttrs field.
        var coder = DER.Serializer()
        try coder.serializeSetOf(signedAttrs)
        let signedAttrBytes = coder.serializedBytes[...]
        let signature = try privateKey.sign(bytes: signedAttrBytes, signatureAlgorithm: signatureAlgorithm)
        let signedData = try self.generateSignedData(
            signatureBytes: ASN1OctetString(signature),
            signatureAlgorithm: signatureAlgorithm,
            additionalIntermediateCertificates: additionalIntermediateCertificates,
            certificate: certificate,
            signedAttrs: signedAttrs,
            withContent: detached ? nil : bytes
        )
        return try self.serializeSignedData(signedData)
    }

    @_spi(CMS)
    @inlinable
    public static func sign(
        signatureBytes: ASN1OctetString,
        signatureAlgorithm: Certificate.SignatureAlgorithm,
        additionalIntermediateCertificates: [Certificate] = [],
        certificate: Certificate
    ) throws -> [UInt8] {
        let signedData = try self.generateSignedData(
            signatureBytes: signatureBytes,
            signatureAlgorithm: signatureAlgorithm,
            additionalIntermediateCertificates: additionalIntermediateCertificates,
            certificate: certificate,
            withContent: nil as Data?
        )

        return try serializeSignedData(signedData)
    }

    @inlinable
    static func generateSignedData(
        signatureBytes: ASN1OctetString,
        signatureAlgorithm: Certificate.SignatureAlgorithm,
        additionalIntermediateCertificates: [Certificate],
        certificate: Certificate,
        signedAttrs: [CMSAttribute]? = nil
    ) throws -> CMSContentInfo {
        return try generateSignedData(
            signatureBytes: signatureBytes,
            signatureAlgorithm: signatureAlgorithm,
            additionalIntermediateCertificates: additionalIntermediateCertificates,
            certificate: certificate,
            signedAttrs: signedAttrs,
            withContent: nil as Data?
        )
    }

    @inlinable
    static func generateSignedData<Bytes: DataProtocol>(
        signatureBytes: ASN1OctetString,
        signatureAlgorithm: Certificate.SignatureAlgorithm,
        additionalIntermediateCertificates: [Certificate],
        certificate: Certificate,
        signedAttrs: [CMSAttribute]? = nil,
        withContent content: Bytes? = nil
    ) throws -> CMSContentInfo {
        let digestAlgorithm = try AlgorithmIdentifier(digestAlgorithmFor: signatureAlgorithm)
        var contentInfo = CMSEncapsulatedContentInfo(eContentType: .cmsData)
        if let content {
            contentInfo.eContent = ASN1OctetString(contentBytes: Array(content)[...])
        }

        let signerInfo = CMSSignerInfo(
            signerIdentifier: .init(issuerAndSerialNumber: certificate),
            digestAlgorithm: digestAlgorithm,
            signedAttrs: signedAttrs,
            signatureAlgorithm: AlgorithmIdentifier(signatureAlgorithm),
            signature: signatureBytes
        )

        var certificates = additionalIntermediateCertificates
        certificates.append(certificate)

        let signedData = CMSSignedData(
            version: .v1,
            digestAlgorithms: [digestAlgorithm],
            encapContentInfo: contentInfo,
            certificates: certificates,
            signerInfos: [signerInfo]
        )
        return try CMSContentInfo(signedData)
    }

    @inlinable
    static func serializeSignedData(
        _ contentInfo: CMSContentInfo
    ) throws -> [UInt8] {
        var serializer = DER.Serializer()
        try serializer.serialize(contentInfo)
        return serializer.serializedBytes
    }

    /// Encrypts data as CMS `EnvelopedData` for one or more RSA key-transport recipient certificates.
    ///
    /// The returned bytes are a DER-encoded CMS `ContentInfo` containing `EnvelopedData`.
    /// The current public API supports RSA key-transport recipients; key-agreement recipient
    /// information can be parsed but is not produced by this operation.
    ///
    /// - Parameters:
    ///   - bytes: The plaintext content to encrypt.
    ///   - recipientCertificates: The RSA recipient certificates used to wrap the content-encryption key.
    ///   - contentEncryptionAlgorithm: The AES content-encryption algorithm used for the encrypted content.
    ///   - keyEncryptionAlgorithm: The RSA key-transport algorithm used to wrap the content-encryption key.
    ///   - originatorCertificates: Certificates to include in `originatorInfo`.
    ///   - validateRecipientKeyUsage: Whether to reject certificates that explicitly lack `keyEncipherment`.
    public static func encrypt<Bytes: DataProtocol>(
        _ bytes: Bytes,
        recipientCertificates: [Certificate],
        contentEncryptionAlgorithm: ContentEncryptionAlgorithm = .aes256CBC,
        keyEncryptionAlgorithm: KeyEncryptionAlgorithm = .rsaOAEPWithSHA256,
        originatorCertificates: [Certificate] = [],
        validateRecipientKeyUsage: Bool = true
    ) throws -> [UInt8] {
        let envelopedData = try self.generateEnvelopedData(
            bytes,
            recipientCertificates: recipientCertificates,
            contentEncryptionAlgorithm: contentEncryptionAlgorithm,
            keyEncryptionAlgorithm: keyEncryptionAlgorithm,
            originatorCertificates: originatorCertificates,
            validateRecipientKeyUsage: validateRecipientKeyUsage
        )
        return try self.serializeCMSContentInfo(envelopedData)
    }

    /// Decrypts CMS `EnvelopedData` addressed to an RSA key-transport recipient.
    ///
    /// - Parameters:
    ///   - cmsBytes: DER or BER encoded CMS `ContentInfo` containing `EnvelopedData`.
    ///   - recipientCertificate: The recipient certificate used to identify the matching recipient info.
    ///   - privateKey: The RSA private key corresponding to `recipientCertificate`.
    ///   - allowLegacyKeyEncryption: Allows RSA-PKCS1v1.5 key transport when set.
    public static func decrypt<CMSBytes: DataProtocol>(
        _ cmsBytes: CMSBytes,
        recipientCertificate: Certificate,
        privateKey: Certificate.PrivateKey,
        allowLegacyKeyEncryption: Bool = false
    ) throws -> [UInt8] {
        let parsed = try CMSContentInfo(berEncoded: ArraySlice(cmsBytes))
        guard let envelopedData = try parsed.envelopedData else {
            throw EncryptionError.invalidCMSBlock("Expected CMS EnvelopedData content")
        }

        guard envelopedData.version == envelopedData.expectedVersion else {
            throw EncryptionError.invalidVersion(
                expected: envelopedData.expectedVersion.rawValue,
                actual: envelopedData.version.rawValue
            )
        }

        guard envelopedData.encryptedContentInfo.contentType == .cmsData else {
            throw EncryptionError.invalidCMSBlock(
                "Unsupported encrypted content type \(envelopedData.encryptedContentInfo.contentType)"
            )
        }

        guard let encryptedContent = envelopedData.encryptedContentInfo.encryptedContent else {
            throw EncryptionError.invalidCMSBlock("EnvelopedData does not contain encrypted content")
        }

        let recipientInfo = try envelopedData.recipientInfos.matchingKeyTransRecipient(
            recipientCertificate: recipientCertificate
        )
        let rsaPrivateKey = try _RSA.Encryption.PrivateKey(privateKey)
        let padding = try recipientInfo.keyEncryptionAlgorithm.cmsRSAEncryptionPadding(
            allowLegacyKeyEncryption: allowLegacyKeyEncryption
        )
        let contentEncryptionKeyBytes = ZeroedBytes(
            Array(try rsaPrivateKey.decrypt(recipientInfo.encryptedKey.bytes, padding: padding))
        )
        defer { contentEncryptionKeyBytes.zero() }

        let expectedKeySize = try envelopedData.encryptedContentInfo.contentEncryptionAlgorithm.cmsContentEncryptionKeySize()
        guard contentEncryptionKeyBytes.bytes.count == expectedKeySize else {
            throw EncryptionError.invalidContentEncryptionKeySize(
                expected: expectedKeySize,
                actual: contentEncryptionKeyBytes.bytes.count
            )
        }

        let contentEncryptionKey = contentEncryptionKeyBytes.symmetricKey
        return try decryptContent(
            encryptedContent,
            using: contentEncryptionKey,
            algorithm: envelopedData.encryptedContentInfo.contentEncryptionAlgorithm
        )
    }


    /// Creates CMS `DigestedData` for the supplied data.
    ///
    /// - Parameters:
    ///   - bytes: The content to digest.
    ///   - digestAlgorithm: The digest algorithm to use. Defaults to SHA-256.
    public static func digest<Bytes: DataProtocol>(
        _ bytes: Bytes,
        digestAlgorithm: DigestAlgorithm = .sha256
    ) throws -> [UInt8] {
        let algorithmIdentifier = digestAlgorithm.algorithmIdentifier
        let computedDigest = try Digest.computeDigest(for: bytes, using: algorithmIdentifier)
        let digestedData = CMSDigestedData(
            version: .v0,
            digestAlgorithm: algorithmIdentifier,
            encapContentInfo: CMSEncapsulatedContentInfo(
                eContentType: .cmsData,
                eContent: ASN1OctetString(contentBytes: Array(bytes)[...])
            ),
            digest: ASN1OctetString(contentBytes: ArraySlice(computedDigest))
        )
        return try serializeCMSContentInfo(CMSContentInfo(digestedData))
    }

    /// Constant-time comparison of two byte sequences.
    private static func constantTimeEqual<L: Sequence<UInt8>, R: Sequence<UInt8>>(
        _ lhs: L, _ rhs: R
    ) -> Bool {
        var difference: UInt8 = 0
        var lhsCount = 0
        var rhsIterator = rhs.makeIterator()
        for lhsByte in lhs {
            lhsCount += 1
            if let rhsByte = rhsIterator.next() {
                difference |= lhsByte ^ rhsByte
            } else {
                difference |= 1
            }
        }
        // Check rhs wasn't longer
        var rhsCount = lhsCount
        while rhsIterator.next() != nil {
            rhsCount += 1
            difference |= 1
        }
        return lhsCount == rhsCount && difference == 0
    }
    /// Verifies the digest embedded in CMS `DigestedData`.
    public static func verifyDigest<CMSBytes: DataProtocol>(
        _ cmsBytes: CMSBytes
    ) throws -> Bool {
        let parsed = try CMSContentInfo(berEncoded: ArraySlice(cmsBytes))
        guard let digestedData = try parsed.digestedData else {
            throw EncryptionError.invalidCMSBlock("Expected CMS DigestedData content")
        }
        guard digestedData.encapContentInfo.eContentType == .cmsData else {
            throw EncryptionError.invalidCMSBlock(
                "Unsupported digested content type \(digestedData.encapContentInfo.eContentType)"
            )
        }
        guard digestedData.digestAlgorithm != .sha1 && digestedData.digestAlgorithm != .sha1UsingNil else {
            throw EncryptionError.unsupportedAlgorithm(
                "Unsupported digest algorithm \(digestedData.digestAlgorithm)"
            )
        }

        guard let content = digestedData.encapContentInfo.eContent else {
            throw EncryptionError.invalidCMSBlock("DigestedData missing encapsulated content")
        }
        let computedDigest = try Digest.computeDigest(for: content.bytes, using: digestedData.digestAlgorithm)
        return constantTimeEqual(computedDigest, digestedData.digest.bytes)
    }

    /// Encrypts data as CMS `EncryptedData` with a directly supplied AES key.
    ///
    /// When `contentEncryptionAlgorithm` is omitted, this operation preserves the historical behavior and chooses the
    /// CBC algorithm that matches `key`'s size.
    ///
    /// - Parameters:
    ///   - bytes: The plaintext content to encrypt.
    ///   - key: The AES content-encryption key.
    ///   - contentEncryptionAlgorithm: The AES content-encryption algorithm to use.
    public static func encrypt<Bytes: DataProtocol>(
        _ bytes: Bytes,
        usingKey key: SymmetricKey,
        contentEncryptionAlgorithm: ContentEncryptionAlgorithm? = nil
    ) throws -> [UInt8] {
        let contentEncryptionAlgorithm = try contentEncryptionAlgorithm ?? self.defaultContentEncryptionAlgorithm(
            forKeyBitCount: key.bitCount
        )
        let expectedKeySize = self.contentEncryptionKeySize(for: contentEncryptionAlgorithm)
        guard key.bitCount / 8 == expectedKeySize else {
            throw EncryptionError.invalidContentEncryptionKeySize(
                expected: expectedKeySize,
                actual: key.bitCount / 8
            )
        }

        let (contentEncryptionAlgorithmIdentifier, encryptedContentBytes) = try self.encryptContent(
            bytes,
            using: key,
            algorithm: contentEncryptionAlgorithm
        )

        let encryptedContentInfo = CMSEncryptedContentInfo(
            contentType: .cmsData,
            contentEncryptionAlgorithm: contentEncryptionAlgorithmIdentifier,
            encryptedContent: ASN1OctetString(contentBytes: encryptedContentBytes[...])
        )
        return try serializeCMSContentInfo(
            CMSContentInfo(CMSEncryptedData(version: .v0, encryptedContentInfo: encryptedContentInfo, unprotectedAttrs: nil))
        )
    }

    /// Decrypts CMS `EncryptedData` with a directly supplied AES key.
    public static func decrypt<CMSBytes: DataProtocol>(
        _ cmsBytes: CMSBytes,
        usingKey key: SymmetricKey
    ) throws -> [UInt8] {
        let parsed = try CMSContentInfo(berEncoded: ArraySlice(cmsBytes))
        guard let encryptedData = try parsed.encryptedData else {
            throw EncryptionError.invalidCMSBlock("Expected CMS EncryptedData content")
        }
        guard encryptedData.encryptedContentInfo.contentType == .cmsData else {
            throw EncryptionError.invalidCMSBlock(
                "Unsupported encrypted content type \(encryptedData.encryptedContentInfo.contentType)"
            )
        }
        let expectedKeySize = try encryptedData.encryptedContentInfo.contentEncryptionAlgorithm.cmsContentEncryptionKeySize()
        guard key.bitCount / 8 == expectedKeySize else {
            throw EncryptionError.invalidContentEncryptionKeySize(
                expected: expectedKeySize,
                actual: key.bitCount / 8
            )
        }
        guard let encryptedContent = encryptedData.encryptedContentInfo.encryptedContent else {
            throw EncryptionError.invalidCMSBlock("EncryptedData missing encrypted content")
        }
        return try decryptContent(
            encryptedContent,
            using: key,
            algorithm: encryptedData.encryptedContentInfo.contentEncryptionAlgorithm
        )
    }

    /// Encrypts data as CMS `EnvelopedData` using an AES key-encryption key recipient.
    ///
    /// - Parameters:
    ///   - bytes: The plaintext content to encrypt.
    ///   - kek: The 256-bit AES key-encryption key used to wrap the content-encryption key.
    ///   - keyIdentifier: The key identifier recorded in the KEK recipient info.
    ///   - contentEncryptionAlgorithm: The AES content-encryption algorithm used for the encrypted content.
    ///   - originatorCertificates: Certificates to include in `originatorInfo`.
    public static func encrypt<Bytes: DataProtocol>(
        _ bytes: Bytes,
        usingKEK kek: SymmetricKey,
        keyIdentifier: ArraySlice<UInt8>,
        contentEncryptionAlgorithm: ContentEncryptionAlgorithm = .aes256CBC,
        originatorCertificates: [Certificate] = []
    ) throws -> [UInt8] {
        guard kek.bitCount / 8 == 32 else {
            throw EncryptionError.invalidContentEncryptionKeySize(
                expected: 32,
                actual: kek.bitCount / 8
            )
        }

        let contentEncryptionKey = SymmetricKey(
            size: self.contentEncryptionKeySizeOption(for: contentEncryptionAlgorithm)
        )
        let (contentEncryptionAlgorithmIdentifier, encryptedContentBytes) = try self.encryptContent(
            bytes,
            using: contentEncryptionKey,
            algorithm: contentEncryptionAlgorithm
        )

        let wrappedKey = try AES.KeyWrap.wrap(contentEncryptionKey, using: kek)

        let kekRecipientInfo = CMSKEKRecipientInfo(
            kekIdentifier: CMSKEKIdentifier(
                keyIdentifier: ASN1OctetString(contentBytes: keyIdentifier)
            ),
            keyEncryptionAlgorithm: .cmsAESKeyWrap256,
            encryptedKey: ASN1OctetString(contentBytes: Array(wrappedKey)[...])
        )
        let recipientInfos: [CMSRecipientInfo] = [.kekRecipientInfo(kekRecipientInfo)]

        let encryptedContentInfo = CMSEncryptedContentInfo(
            contentType: .cmsData,
            contentEncryptionAlgorithm: contentEncryptionAlgorithmIdentifier,
            encryptedContent: ASN1OctetString(contentBytes: encryptedContentBytes[...])
        )
        var envelopedData = CMSEnvelopedData(
            version: .v0,
            originatorInfo: self.originatorInfo(certificates: originatorCertificates),
            recipientInfos: recipientInfos,
            encryptedContentInfo: encryptedContentInfo,
            unprotectedAttrs: nil
        )
        envelopedData.version = envelopedData.expectedVersion
        return try serializeCMSContentInfo(CMSContentInfo(envelopedData))
    }

    /// Decrypts CMS `EnvelopedData` using an AES key-encryption key recipient.
    public static func decrypt<CMSBytes: DataProtocol>(
        _ cmsBytes: CMSBytes,
        usingKEK kek: SymmetricKey
    ) throws -> [UInt8] {
        let parsed = try CMSContentInfo(berEncoded: ArraySlice(cmsBytes))
        guard let envelopedData = try parsed.envelopedData else {
            throw EncryptionError.invalidCMSBlock("Expected CMS EnvelopedData content")
        }

        guard envelopedData.version == envelopedData.expectedVersion else {
            throw EncryptionError.invalidVersion(
                expected: envelopedData.expectedVersion.rawValue,
                actual: envelopedData.version.rawValue
            )
        }

        guard envelopedData.encryptedContentInfo.contentType == .cmsData else {
            throw EncryptionError.invalidCMSBlock(
                "Unsupported encrypted content type \(envelopedData.encryptedContentInfo.contentType)"
            )
        }

        let kekRecipients = envelopedData.recipientInfos.compactMap { recipientInfo -> CMSKEKRecipientInfo? in
            if case .kekRecipientInfo(let kekRecipientInfo) = recipientInfo {
                return kekRecipientInfo
            }
            return nil
        }
        guard !kekRecipients.isEmpty else {
            throw EncryptionError.noMatchingRecipient
        }

        let expectedKeySize = try envelopedData.encryptedContentInfo.contentEncryptionAlgorithm.cmsContentEncryptionKeySize()
        guard let encryptedContent = envelopedData.encryptedContentInfo.encryptedContent else {
            throw EncryptionError.invalidCMSBlock("Missing encrypted content")
        }
        var lastRecipientError: Swift.Error?
        for kekRecipient in kekRecipients {
            do {
                let contentEncryptionKey = try kekRecipient.keyEncryptionAlgorithm.cmsUnwrapContentEncryptionKey(
                    kekRecipient.encryptedKey,
                    using: kek
                )

                guard contentEncryptionKey.bitCount / 8 == expectedKeySize else {
                    throw EncryptionError.invalidContentEncryptionKeySize(
                        expected: expectedKeySize,
                        actual: contentEncryptionKey.bitCount / 8
                    )
                }

                return try decryptContent(
                    encryptedContent,
                    using: contentEncryptionKey,
                    algorithm: envelopedData.encryptedContentInfo.contentEncryptionAlgorithm
                )
            } catch {
                lastRecipientError = error
            }
        }

        throw lastRecipientError ?? EncryptionError.noMatchingRecipient
    }

    /// Encrypts data as CMS `EnvelopedData` using a password recipient.
    ///
    /// - Parameters:
    ///   - bytes: The plaintext content to encrypt.
    ///   - password: The password used to derive the key-encryption key.
    ///   - salt: The PBKDF2 salt. A random salt is generated when `nil`.
    ///   - iterationCount: The PBKDF2 iteration count.
    ///   - contentEncryptionAlgorithm: The AES content-encryption algorithm used for the encrypted content.
    ///   - originatorCertificates: Certificates to include in `originatorInfo`.
    public static func encrypt<Bytes: DataProtocol>(
        _ bytes: Bytes,
        usingPassword password: String,
        salt: [UInt8]? = nil,
        iterationCount: Int = 600_000,
        contentEncryptionAlgorithm: ContentEncryptionAlgorithm = .aes256CBC,
        originatorCertificates: [Certificate] = []
    ) throws -> [UInt8] {
        let actualSalt: [UInt8]
        if let salt {
            actualSalt = salt
        } else {
            actualSalt = SymmetricKey(size: .bits128).withUnsafeBytes { Array($0) }
        }

        guard iterationCount > 0 else {
            throw EncryptionError.invalidCMSBlock("PBKDF2 iteration count must be positive")
        }

        let passwordData = ZeroedBytes(Array(password.utf8))
        defer { passwordData.zero() }
        let derivedKey: SymmetricKey
        if iterationCount >= 210_000 {
            derivedKey = try KDF.Insecure.PBKDF2.deriveKey(
                from: passwordData.bytes,
                salt: actualSalt,
                using: .sha256,
                outputByteCount: 32,
                rounds: iterationCount
            )
        } else {
            derivedKey = try KDF.Insecure.PBKDF2.deriveKey(
                from: passwordData.bytes,
                salt: actualSalt,
                using: .sha256,
                outputByteCount: 32,
                unsafeUncheckedRounds: iterationCount
            )
        }

        let contentEncryptionKey = SymmetricKey(
            size: self.contentEncryptionKeySizeOption(for: contentEncryptionAlgorithm)
        )
        let (contentEncryptionAlgorithmIdentifier, encryptedContentBytes) = try self.encryptContent(
            bytes,
            using: contentEncryptionKey,
            algorithm: contentEncryptionAlgorithm
        )

        let wrappedKey = try AES.KeyWrap.wrap(contentEncryptionKey, using: derivedKey)

        let saltOctetString = ASN1OctetString(contentBytes: actualSalt[...])
        let passwordRecipientInfo = CMSPasswordRecipientInfo(
            keyDerivationAlgorithm: try .cmsPBKDF2(
                salt: saltOctetString,
                iterationCount: iterationCount,
                keyLength: 32
            ),
            keyEncryptionAlgorithm: .cmsAESKeyWrap256,
            encryptedKey: ASN1OctetString(contentBytes: Array(wrappedKey)[...])
        )
        let recipientInfos: [CMSRecipientInfo] = [.passwordRecipientInfo(passwordRecipientInfo)]

        let encryptedContentInfo = CMSEncryptedContentInfo(
            contentType: .cmsData,
            contentEncryptionAlgorithm: contentEncryptionAlgorithmIdentifier,
            encryptedContent: ASN1OctetString(contentBytes: encryptedContentBytes[...])
        )
        var envelopedData = CMSEnvelopedData(
            version: .v0,
            originatorInfo: self.originatorInfo(certificates: originatorCertificates),
            recipientInfos: recipientInfos,
            encryptedContentInfo: encryptedContentInfo,
            unprotectedAttrs: nil
        )
        envelopedData.version = envelopedData.expectedVersion
        return try serializeCMSContentInfo(CMSContentInfo(envelopedData))
    }

    /// Decrypts CMS `EnvelopedData` using a password recipient.
    public static func decrypt<CMSBytes: DataProtocol>(
        _ cmsBytes: CMSBytes,
        usingPassword password: String
    ) throws -> [UInt8] {
        let parsed = try CMSContentInfo(berEncoded: ArraySlice(cmsBytes))
        guard let envelopedData = try parsed.envelopedData else {
            throw EncryptionError.invalidCMSBlock("Expected CMS EnvelopedData content")
        }

        guard envelopedData.version == envelopedData.expectedVersion else {
            throw EncryptionError.invalidVersion(
                expected: envelopedData.expectedVersion.rawValue,
                actual: envelopedData.version.rawValue
            )
        }

        guard envelopedData.encryptedContentInfo.contentType == .cmsData else {
            throw EncryptionError.invalidCMSBlock(
                "Unsupported encrypted content type \(envelopedData.encryptedContentInfo.contentType)"
            )
        }

        let passwordRecipients = envelopedData.recipientInfos.compactMap { recipientInfo -> CMSPasswordRecipientInfo? in
            if case .passwordRecipientInfo(let passwordRecipientInfo) = recipientInfo {
                return passwordRecipientInfo
            }
            return nil
        }
        guard !passwordRecipients.isEmpty else {
            throw EncryptionError.noMatchingRecipient
        }

        let expectedKeySize = try envelopedData.encryptedContentInfo.contentEncryptionAlgorithm.cmsContentEncryptionKeySize()
        guard let encryptedContent = envelopedData.encryptedContentInfo.encryptedContent else {
            throw EncryptionError.invalidCMSBlock("Missing encrypted content")
        }
        var lastRecipientError: Swift.Error?
        for passwordRecipient in passwordRecipients {
            do {
                guard let keyDerivationAlgorithm = passwordRecipient.keyDerivationAlgorithm else {
                    throw EncryptionError.invalidCMSBlock("Password recipient info missing key derivation algorithm")
                }

                let keyEncryptionKeySize = try passwordRecipient.keyEncryptionAlgorithm.cmsKeyEncryptionKeySize()
                let derivedKey = try keyDerivationAlgorithm.cmsDerivedKey(
                    from: password,
                    outputByteCount: keyEncryptionKeySize
                )
                let contentEncryptionKey = try passwordRecipient.keyEncryptionAlgorithm.cmsUnwrapContentEncryptionKey(
                    passwordRecipient.encryptedKey,
                    using: derivedKey
                )

                guard contentEncryptionKey.bitCount / 8 == expectedKeySize else {
                    throw EncryptionError.invalidContentEncryptionKeySize(
                        expected: expectedKeySize,
                        actual: contentEncryptionKey.bitCount / 8
                    )
                }

                return try decryptContent(
                    encryptedContent,
                    using: contentEncryptionKey,
                    algorithm: envelopedData.encryptedContentInfo.contentEncryptionAlgorithm
                )
            } catch {
                lastRecipientError = error
            }
        }

        throw lastRecipientError ?? EncryptionError.noMatchingRecipient
    }

    /// Creates CMS `AuthenticatedData` for one or more RSA key-transport recipient certificates.
    ///
    /// - Parameters:
    ///   - bytes: The content to authenticate.
    ///   - recipientCertificates: The RSA recipient certificates used to wrap the MAC key.
    ///   - includeAuthenticatedAttributes: Whether to MAC the DER encoding of CMS authenticated attributes.
    ///   - originatorCertificates: Certificates to include in `originatorInfo`.
    ///   - validateRecipientKeyUsage: Whether to reject certificates that explicitly lack `keyEncipherment`.
    public static func authenticate<Bytes: DataProtocol>(
        _ bytes: Bytes,
        recipientCertificates: [Certificate],
        includeAuthenticatedAttributes: Bool = false,
        originatorCertificates: [Certificate] = [],
        validateRecipientKeyUsage: Bool = true
    ) throws -> [UInt8] {
        guard !recipientCertificates.isEmpty else {
            throw EncryptionError.invalidCMSBlock("At least one recipient certificate is required")
        }

        let macKey = SymmetricKey(size: .bits256)
        let macKeyBytes = ZeroedBytes(macKey.withUnsafeBytes { Array($0) })
        defer { macKeyBytes.zero() }

        let recipientInfos = try recipientCertificates.map { certificate -> CMSRecipientInfo in
            if validateRecipientKeyUsage {
                if let keyUsage = try? certificate.extensions.keyUsage,
                   !keyUsage.keyEncipherment
                {
                    throw EncryptionError.invalidCMSBlock(
                        "Certificate missing keyEncipherment key usage"
                    )
                }
            }
            let rsaPublicKey = try _RSA.Encryption.PublicKey(certificate.publicKey)
            let encryptedKey = try rsaPublicKey.encrypt(macKeyBytes.bytes, padding: .PKCS1_OAEP_SHA256)
            let recipientIdentifier: CMSRecipientIdentifier
            if let ski = try? certificate.extensions.subjectKeyIdentifier {
                recipientIdentifier = .subjectKeyIdentifier(ski)
            } else {
                recipientIdentifier = .init(issuerAndSerialNumber: certificate)
            }
            let keyTransRecipientInfo = CMSKeyTransRecipientInfo(
                recipientIdentifier: recipientIdentifier,
                keyEncryptionAlgorithm: .cmsRSAESOAEPWithSHA256,
                encryptedKey: ASN1OctetString(contentBytes: Array(encryptedKey)[...])
            )
            return .keyTransRecipientInfo(keyTransRecipientInfo)
        }

        let encapContentInfo = CMSEncapsulatedContentInfo(
            eContentType: .cmsData,
            eContent: ASN1OctetString(contentBytes: Array(bytes)[...])
        )

        let digestAlgorithm: AlgorithmIdentifier?
        let authAttrs: [CMSAttribute]?
        let authenticatedBytes: [UInt8]
        if includeAuthenticatedAttributes {
            digestAlgorithm = .sha256
            let contentTypeValue = try ASN1Any(erasing: ASN1ObjectIdentifier.cmsData)
            let contentTypeAttribute = CMSAttribute(attrType: .contentType, attrValues: [contentTypeValue])
            let computedDigest = try Digest.computeDigest(for: bytes, using: .sha256)
            let messageDigest = ASN1OctetString(contentBytes: ArraySlice(computedDigest))
            let messageDigestValue = try ASN1Any(erasing: messageDigest)
            let messageDigestAttribute = CMSAttribute(attrType: .messageDigest, attrValues: [messageDigestValue])
            let attributes = [contentTypeAttribute, messageDigestAttribute]
            authAttrs = attributes
            authenticatedBytes = try self.encodedAttributes(attributes)
        } else {
            digestAlgorithm = nil
            authAttrs = nil
            authenticatedBytes = Array(bytes)
        }

        let mac = HMAC<SHA256>.authenticationCode(for: authenticatedBytes, using: macKey)

        let authenticatedData = CMSAuthenticatedData(
            version: .v0,
            originatorInfo: self.originatorInfo(certificates: originatorCertificates),
            recipientInfos: recipientInfos,
            macAlgorithm: .hmacWithSHA256,
            digestAlgorithm: digestAlgorithm,
            encapContentInfo: encapContentInfo,
            authAttrs: authAttrs,
            mac: ASN1OctetString(contentBytes: ArraySlice(Data(mac))),
            unauthAttrs: nil
        )
        return try serializeCMSContentInfo(CMSContentInfo(authenticatedData))
    }

    /// Verifies CMS `AuthenticatedData` addressed to an RSA key-transport recipient.
    public static func verifyAuthentication<CMSBytes: DataProtocol>(
        _ cmsBytes: CMSBytes,
        recipientCertificate: Certificate,
        privateKey: Certificate.PrivateKey
    ) throws -> Bool {
        let parsed = try CMSContentInfo(berEncoded: ArraySlice(cmsBytes))
        guard let authData = try parsed.authenticatedData else {
            throw EncryptionError.invalidCMSBlock("Expected CMS AuthenticatedData content")
        }
        guard authData.macAlgorithm == .hmacWithSHA256 else {
            throw EncryptionError.unsupportedAlgorithm(
                "Unsupported MAC algorithm \(authData.macAlgorithm)"
            )
        }
        guard authData.encapContentInfo.eContentType == .cmsData else {
            throw EncryptionError.invalidCMSBlock(
                "Unsupported authenticated content type \(authData.encapContentInfo.eContentType)"
            )
        }
        guard let content = authData.encapContentInfo.eContent else {
            throw EncryptionError.invalidCMSBlock("AuthenticatedData missing content")
        }

        let authenticatedBytes: [UInt8]
        if let authAttrs = authData.authAttrs {
            guard let digestAlgorithm = authData.digestAlgorithm else {
                throw EncryptionError.invalidCMSBlock(
                    "AuthenticatedData with authenticated attributes is missing digestAlgorithm"
                )
            }
            guard let contentType = try authAttrs.contentType, contentType == .cmsData else {
                throw EncryptionError.invalidCMSBlock("Authenticated attributes missing cmsData content type")
            }
            guard let messageDigest = try authAttrs.messageDigest else {
                throw EncryptionError.invalidCMSBlock("Authenticated attributes missing message digest")
            }
            let computedDigest = try Digest.computeDigest(for: content.bytes, using: digestAlgorithm)
            guard constantTimeEqual(computedDigest, messageDigest) else {
                return false
            }
            authenticatedBytes = try self.encodedAttributes(authAttrs)
        } else {
            guard authData.digestAlgorithm == nil else {
                throw EncryptionError.unsupportedAlgorithm(
                    "digestAlgorithm must not be present when authenticated attributes are absent"
                )
            }
            authenticatedBytes = Array(content.bytes)
        }

        let recipientInfo = try authData.recipientInfos.matchingKeyTransRecipient(
            recipientCertificate: recipientCertificate
        )
        let rsaPrivateKey = try _RSA.Encryption.PrivateKey(privateKey)
        let padding = try recipientInfo.keyEncryptionAlgorithm.cmsRSAEncryptionPadding(allowLegacyKeyEncryption: false)
        let macKeyBytes = ZeroedBytes(Array(try rsaPrivateKey.decrypt(recipientInfo.encryptedKey.bytes, padding: padding)))
        defer { macKeyBytes.zero() }
        let macKey = SymmetricKey(data: macKeyBytes.bytes)

        return HMAC<SHA256>.isValidAuthenticationCode(
            authData.mac.bytes,
            authenticating: authenticatedBytes,
            using: macKey
        )
    }
    @inlinable
    static func serializeCMSContentInfo(_ contentInfo: CMSContentInfo) throws -> [UInt8] {
        var serializer = DER.Serializer()
        try serializer.serialize(contentInfo)
        return serializer.serializedBytes
    }

    static func originatorInfo(certificates: [Certificate]) -> CMSOriginatorInfo? {
        guard !certificates.isEmpty else {
            return nil
        }
        return CMSOriginatorInfo(certificates: certificates)
    }

    static func encodedAttributes(_ attributes: [CMSAttribute]) throws -> [UInt8] {
        var coder = DER.Serializer()
        try coder.serializeSetOf(attributes)
        return coder.serializedBytes
    }

    static func defaultContentEncryptionAlgorithm(forKeyBitCount keyBitCount: Int) throws -> ContentEncryptionAlgorithm {
        switch keyBitCount {
        case 256:
            return .aes256CBC
        case 192:
            return .aes192CBC
        case 128:
            return .aes128CBC
        default:
            throw EncryptionError.invalidCMSBlock(
                "Unsupported symmetric key size \(keyBitCount) bits; expected 128, 192, or 256"
            )
        }
    }

    static func contentEncryptionKeySize(for contentEncryptionAlgorithm: ContentEncryptionAlgorithm) -> Int {
        switch contentEncryptionAlgorithm {
        case .aes256CBC, .aes256GCM:
            return 32
        case .aes192CBC, .aes192GCM:
            return 24
        case .aes128CBC, .aes128GCM:
            return 16
        }
    }

    static func contentEncryptionKeySizeOption(for contentEncryptionAlgorithm: ContentEncryptionAlgorithm) -> SymmetricKeySize {
        switch contentEncryptionAlgorithm {
        case .aes256CBC, .aes256GCM:
            return .bits256
        case .aes192CBC, .aes192GCM:
            return .bits192
        case .aes128CBC, .aes128GCM:
            return .bits128
        }
    }

    static func encryptContent<Bytes: DataProtocol>(
        _ bytes: Bytes,
        using key: SymmetricKey,
        algorithm contentEncryptionAlgorithm: ContentEncryptionAlgorithm
    ) throws -> (algorithmIdentifier: AlgorithmIdentifier, encryptedContentBytes: [UInt8]) {
        switch contentEncryptionAlgorithm {
        case .aes256CBC, .aes192CBC, .aes128CBC:
            let iv = AES._CBC.IV()
            let encryptedContent = try AES._CBC.encrypt(bytes, using: key, iv: iv)
            let ivOctets = ASN1OctetString(contentBytes: Array(iv)[...])
            let algorithmIdentifier: AlgorithmIdentifier
            switch contentEncryptionAlgorithm {
            case .aes256CBC:
                algorithmIdentifier = try .cmsAES256CBC(iv: ivOctets)
            case .aes192CBC:
                algorithmIdentifier = try .cmsAES192CBC(iv: ivOctets)
            case .aes128CBC:
                algorithmIdentifier = try .cmsAES128CBC(iv: ivOctets)
            case .aes256GCM, .aes192GCM, .aes128GCM:
                throw EncryptionError.invalidCMSBlock("Unexpected GCM algorithm in CBC encryption branch")
            }
            return (algorithmIdentifier, Array(encryptedContent))

        case .aes256GCM, .aes192GCM, .aes128GCM:
            let nonce = AES.GCM.Nonce()
            let sealedBox = try AES.GCM.seal(bytes, using: key, nonce: nonce)
            let encryptedContentBytes = Array(sealedBox.ciphertext) + Array(sealedBox.tag)
            let parameters = CMSGCMParameters(
                nonce: ASN1OctetString(contentBytes: Array(nonce)[...]),
                icvLength: CMSGCMParameters.supportedICVLength
            )
            let algorithmIdentifier: AlgorithmIdentifier
            switch contentEncryptionAlgorithm {
            case .aes256GCM:
                algorithmIdentifier = try .cmsAES256GCM(parameters: parameters)
            case .aes192GCM:
                algorithmIdentifier = try .cmsAES192GCM(parameters: parameters)
            case .aes128GCM:
                algorithmIdentifier = try .cmsAES128GCM(parameters: parameters)
            case .aes256CBC, .aes192CBC, .aes128CBC:
                throw EncryptionError.invalidCMSBlock("Unexpected CBC algorithm in GCM encryption branch")
            }
            return (algorithmIdentifier, encryptedContentBytes)
        }
    }

    static func decryptContent(
        _ encryptedContent: ASN1OctetString,
        using key: SymmetricKey,
        algorithm contentEncryptionAlgorithm: AlgorithmIdentifier
    ) throws -> [UInt8] {
        switch contentEncryptionAlgorithm.algorithm {
        case .AlgorithmIdentifier.aes256CBC, .AlgorithmIdentifier.aes192CBC, .AlgorithmIdentifier.aes128CBC:
            let iv = try contentEncryptionAlgorithm.cmsCBCIV()
            let decryptedContent = try AES._CBC.decrypt(
                encryptedContent.bytes,
                using: key,
                iv: iv
            )
            return Array(decryptedContent)

        case .AlgorithmIdentifier.aes256GCM, .AlgorithmIdentifier.aes192GCM, .AlgorithmIdentifier.aes128GCM:
            let parameters = try contentEncryptionAlgorithm.cmsGCMParameters()
            guard encryptedContent.bytes.count >= CMSGCMParameters.supportedICVLength else {
                throw EncryptionError.invalidCMSBlock("AES-GCM encrypted content is shorter than its authentication tag")
            }

            let nonce = try AES.GCM.Nonce(data: parameters.nonce.bytes)
            let tag = encryptedContent.bytes.suffix(CMSGCMParameters.supportedICVLength)
            let ciphertext = encryptedContent.bytes.dropLast(CMSGCMParameters.supportedICVLength)
            let sealedBox = try AES.GCM.SealedBox(nonce: nonce, ciphertext: ciphertext, tag: tag)
            return Array(try AES.GCM.open(sealedBox, using: key))

        default:
            throw EncryptionError.unsupportedAlgorithm(
                "Unsupported content encryption algorithm \(contentEncryptionAlgorithm.algorithm)"
            )
        }
    }

    static func generateEnvelopedData<Bytes: DataProtocol>(
        _ bytes: Bytes,
        recipientCertificates: [Certificate],
        contentEncryptionAlgorithm: ContentEncryptionAlgorithm = .aes256CBC,
        keyEncryptionAlgorithm: KeyEncryptionAlgorithm = .rsaOAEPWithSHA256,
        originatorCertificates: [Certificate] = [],
        validateRecipientKeyUsage: Bool = true
    ) throws -> CMSContentInfo {
        guard !recipientCertificates.isEmpty else {
            throw EncryptionError.invalidCMSBlock("At least one recipient certificate is required")
        }
        let keySize = self.contentEncryptionKeySizeOption(for: contentEncryptionAlgorithm)

        let contentEncryptionKey = SymmetricKey(size: keySize)
        let contentEncryptionKeyBytes = ZeroedBytes(
            contentEncryptionKey.withUnsafeBytes { Array($0) }
        )
        defer { contentEncryptionKeyBytes.zero() }

        let (contentEncryptionAlgorithmIdentifier, encryptedContentBytes) = try self.encryptContent(
            bytes,
            using: contentEncryptionKey,
            algorithm: contentEncryptionAlgorithm
        )

        let rsaPadding: _RSA.Encryption.Padding
        let keyEncryptionAlgorithmIdentifier: AlgorithmIdentifier
        switch keyEncryptionAlgorithm {
        case .rsaOAEPWithSHA256:
            rsaPadding = .PKCS1_OAEP_SHA256
            keyEncryptionAlgorithmIdentifier = .cmsRSAESOAEPWithSHA256
        case .rsaOAEPWithSHA1:
            rsaPadding = .PKCS1_OAEP
            keyEncryptionAlgorithmIdentifier = .cmsRSAESOAEPWithSHA1
        case .rsaPKCS1v15:
            rsaPadding = ._WEAK_AND_INSECURE_PKCS_V1_5
            keyEncryptionAlgorithmIdentifier = .rsaKey
        }

        let recipientInfos = try recipientCertificates.map { certificate -> CMSRecipientInfo in
            if validateRecipientKeyUsage {
                if let keyUsage = try? certificate.extensions.keyUsage,
                   !keyUsage.keyEncipherment
                {
                    throw EncryptionError.invalidCMSBlock(
                        "Certificate missing keyEncipherment key usage"
                    )
                }
            }

            let rsaPublicKey = try _RSA.Encryption.PublicKey(certificate.publicKey)
            let encryptedKey = try rsaPublicKey.encrypt(
                contentEncryptionKeyBytes.bytes,
                padding: rsaPadding
            )

            let recipientIdentifier: CMSRecipientIdentifier
            if let ski = try? certificate.extensions.subjectKeyIdentifier {
                recipientIdentifier = .subjectKeyIdentifier(ski)
            } else {
                recipientIdentifier = .init(issuerAndSerialNumber: certificate)
            }

            let keyTransRecipientInfo = CMSKeyTransRecipientInfo(
                recipientIdentifier: recipientIdentifier,
                keyEncryptionAlgorithm: keyEncryptionAlgorithmIdentifier,
                encryptedKey: ASN1OctetString(contentBytes: Array(encryptedKey)[...])
            )
            return .keyTransRecipientInfo(keyTransRecipientInfo)
        }

        let encryptedContentInfo = CMSEncryptedContentInfo(
            contentType: .cmsData,
            contentEncryptionAlgorithm: contentEncryptionAlgorithmIdentifier,
            encryptedContent: ASN1OctetString(contentBytes: encryptedContentBytes[...])
        )
        var envelopedData = CMSEnvelopedData(
            version: .v0,
            originatorInfo: self.originatorInfo(certificates: originatorCertificates),
            recipientInfos: recipientInfos,
            encryptedContentInfo: encryptedContentInfo,
            unprotectedAttrs: nil
        )
        envelopedData.version = envelopedData.expectedVersion

        return try CMSContentInfo(envelopedData)
    }

    @_spi(CMS)
    @inlinable
    public static func isValidAttachedSignature<SignatureBytes: DataProtocol>(
        signatureBytes: SignatureBytes,
        additionalIntermediateCertificates: [Certificate] = [],
        trustRoots: CertificateStore,
        diagnosticCallback: ((VerificationDiagnostic) -> Void)? = nil,
        microsoftCompatible: Bool = false,
        @PolicyBuilder policy: () throws -> some VerifierPolicy
    ) async rethrows -> SignatureVerificationResult {
        do {
            // this means we parse the blob twice, but that's probably better than repeating a lot of code.
            let parsedSignature = try CMSContentInfo(berEncoded: ArraySlice(signatureBytes))
            guard let attachedData = try parsedSignature.signedData?.encapContentInfo.eContent else {
                return .failure(.init(invalidCMSBlockReason: "No attached content"))
            }

            return try await isValidSignature(
                dataBytes: attachedData.bytes,
                signatureBytes: signatureBytes,
                trustRoots: trustRoots,
                diagnosticCallback: diagnosticCallback,
                microsoftCompatible: microsoftCompatible,
                allowAttachedContent: true,
                policy: policy
            )
        } catch {
            return .failure(.invalidCMSBlock(.init(reason: String(describing: error))))
        }
    }

    @_spi(CMS)
    @inlinable
    public static func isValidSignature<
        DataBytes: DataProtocol,
        SignatureBytes: DataProtocol
    >(
        dataBytes: DataBytes,
        signatureBytes: SignatureBytes,
        additionalIntermediateCertificates: [Certificate] = [],
        trustRoots: CertificateStore,
        diagnosticCallback: ((VerificationDiagnostic) -> Void)? = nil,
        microsoftCompatible: Bool = false,
        allowAttachedContent: Bool = false,
        @PolicyBuilder policy: () throws -> some VerifierPolicy
    ) async rethrows -> SignatureVerificationResult {
        let signedData: CMSSignedData
        let signingCert: Certificate
        do {
            let parsedSignature = try CMSContentInfo(berEncoded: ArraySlice(signatureBytes))
            guard let _signedData = try parsedSignature.signedData else {
                return .failure(.init(invalidCMSBlockReason: "Unable to parse signed data"))
            }
            signedData = _signedData

            guard signedData.signerInfos.count == 1 else {
                return .failure(.init(invalidCMSBlockReason: "Too many signatures"))
            }

            switch signedData.version {
            case .v1:
                // If no attribute certificates are present in the certificates field, the
                // encapsulated content type is id-data, and all of the elements of
                // SignerInfos are version 1, then the value of version shall be 1.
                guard signedData.encapContentInfo.eContentType == .cmsData,
                    signedData.signerInfos.allSatisfy({ $0.version == .v1 })
                else {
                    return .failure(.init(invalidCMSBlockReason: "Invalid v1 signed data: \(signedData)"))
                }

            case .v3:
                // no v2 Attribute Certificates are allowed, but we don't currently support that anyway
                guard
                    signedData.encapContentInfo.eContentType == .cmsData
                        || signedData.encapContentInfo.eContentType == .cmsSignedData
                else {
                    return .failure(.init(invalidCMSBlockReason: "Invalid v3 signed data: \(signedData)"))
                }
                break

            case .v4:
                guard
                    signedData.encapContentInfo.eContentType == .cmsData
                        || signedData.encapContentInfo.eContentType == .cmsSignedData
                else {
                    return .failure(.init(invalidCMSBlockReason: "Invalid v4 signed data: \(signedData)"))
                }
                break

            default:
                // v2 and v5 are not for SignedData
                return .failure(.init(invalidCMSBlockReason: "Invalid signed data: \(signedData)"))
            }

            if let attachedContent = signedData.encapContentInfo.eContent {
                guard allowAttachedContent else {
                    return .failure(.init(invalidCMSBlockReason: "Attached content data not allowed"))
                }
                // we will tolerate attached content, and simply check if what the caller provided matches the attached content.
                guard dataBytes.elementsEqual(attachedContent.bytes) else {
                    return .failure(.init(invalidCMSBlockReason: "Attached content data does not match provided data"))
                }
            }

            // This subscript is safe, we confirmed a count of 1 above.
            let signer = signedData.signerInfos[0]

            // Double-check that the signer included their digest algorithm in the parent set.
            //
            // Per RFC 5652 § 5.1:
            //
            // > digestAlgorithms is a collection of message digest algorithm
            // > identifiers.
            // > ...
            // > Implementations MAY fail to validate signatures that use a digest
            // > algorithm that is not included in this set.
            guard signedData.digestAlgorithms.contains(signer.digestAlgorithm) else {
                return .failure(.init(invalidCMSBlockReason: "Digest algorithm mismatch"))
            }

            // Convert the signature algorithm to confirm we understand it.
            // We also want to confirm the digest algorithm matches the signature algorithm.
            var signatureAlgorithm = Certificate.SignatureAlgorithm(algorithmIdentifier: signer.signatureAlgorithm)

            // For legacy reasons originating from Microsoft, some signatureAlgorithms will incorrectly be `ecPublicKey`
            // instead of a correct Signature Algorithm Identifier. This affects macOS systems using Security.framework by default.
            if microsoftCompatible
                && signer.signatureAlgorithm.algorithm == ASN1ObjectIdentifier.AlgorithmIdentifier.idEcPublicKey
            {
                // We're under microsoft compatibility, so we can assume that the digest algorithm is ECDSA
                let sigAlgID: AlgorithmIdentifier
                switch signer.digestAlgorithm {
                case .sha256:
                    sigAlgID = .ecdsaWithSHA256

                case .sha384:
                    sigAlgID = .ecdsaWithSHA384

                case .sha512:
                    sigAlgID = .ecdsaWithSHA512

                default:
                    return .failure(.init(invalidCMSBlockReason: "Invalid digest algorithm"))
                }
                signatureAlgorithm = Certificate.SignatureAlgorithm(algorithmIdentifier: sigAlgID)
            } else {
                let expectedDigestAlgorithm = try AlgorithmIdentifier(digestAlgorithmFor: signatureAlgorithm)
                guard expectedDigestAlgorithm == signer.digestAlgorithm else {
                    return .failure(.init(invalidCMSBlockReason: "Digest and signature algorithm mismatch"))
                }
            }

            // Ok, now we need to find the signer. We expect to find them in the list of certificates provided
            // in the signature.
            guard let _signingCert = try signedData.certificates?.certificate(signerInfo: signer) else {
                return .failure(.init(invalidCMSBlockReason: "Unable to locate signing certificate"))
            }
            signingCert = _signingCert

            // Ok at this point we've done the cheap stuff and we're fairly confident we have the entity who should have
            // done the signing. Our next step is to confirm that they did in fact sign the data. For that we have to compute
            // the digest and validate the signature. If SignedAttributes (Optional) is present, the Signature is over the DER encoding
            // of the entire SignedAttributes, and not the immediate content data.
            let signature = try Certificate.Signature(
                signatureAlgorithm: signatureAlgorithm,
                signatureBytes: signer.signature
            )
            if let signedAttrs = signer.signedAttrs {
                guard let messageDigest = try signedAttrs.messageDigest else {
                    return .failure(.init(invalidCMSBlockReason: "Missing message digest from signed attributes"))
                }

                let digestAlgorithm = try AlgorithmIdentifier(digestAlgorithmFor: signatureAlgorithm)
                let actualDigest = try Digest.computeDigest(for: dataBytes, using: digestAlgorithm)

                guard actualDigest.elementsEqual(messageDigest) else {
                    return .failure(.init(invalidCMSBlockReason: "Message digest mismatch"))
                }

                guard
                    signingCert.publicKey.isValidSignature(
                        signature,
                        for: try signer._signedAttrsBytes(),
                        signatureAlgorithm: signatureAlgorithm
                    )
                else {
                    return .failure(
                        .init(invalidCMSBlockReason: "Invalid signature from signing certificate: \(signingCert)")
                    )
                }
            } else {
                guard
                    signingCert.publicKey.isValidSignature(
                        signature,
                        for: dataBytes,
                        signatureAlgorithm: signatureAlgorithm
                    )
                else {
                    return .failure(
                        .init(invalidCMSBlockReason: "Invalid signature from signing certificate: \(signingCert)")
                    )
                }
            }

        } catch {
            return .failure(.invalidCMSBlock(.init(reason: String(describing: error))))
        }

        // Ok, the signature was signed by the private key associated with this cert. Now we need to validate the certificate.
        // This force-unwrap is safe: we know there are certificates because we've located at least one certificate from this set!
        var untrustedIntermediates = CertificateStore(signedData.certificates!)
        untrustedIntermediates.append(contentsOf: additionalIntermediateCertificates)

        var verifier = try Verifier(rootCertificates: trustRoots, policy: policy)
        let result = await verifier.validate(
            leaf: signingCert,
            intermediates: untrustedIntermediates,
            diagnosticCallback: diagnosticCallback
        )

        switch result {
        case .validCertificate:
            return .success(.init(signer: signingCert))
        case .couldNotValidate(let validationFailures):
            return .failure(.unableToValidateSigner(.init(validationFailures: validationFailures, signer: signingCert)))
        }
    }

    /// CMS content-encryption algorithms supported by the public CMS encryption APIs.
    ///
    /// The CBC and GCM variants correspond to the AES content-encryption algorithms registered for CMS.
    /// GCM encryption uses 16-octet authentication tags, matching Swift Crypto's `AES.GCM` primitive.
    /// CMS messages encoded with shorter AES-GCM ICV lengths are rejected.
    public enum ContentEncryptionAlgorithm: Sendable {
        /// AES-256-CBC content encryption.
        case aes256CBC
        /// AES-192-CBC content encryption.
        case aes192CBC
        /// AES-128-CBC content encryption.
        case aes128CBC
        /// AES-256-GCM authenticated content encryption.
        case aes256GCM
        /// AES-192-GCM authenticated content encryption.
        case aes192GCM
        /// AES-128-GCM authenticated content encryption.
        case aes128GCM
    }

    /// Digest algorithms supported by ``CMS/digest(_:digestAlgorithm:)``.
    public enum DigestAlgorithm: Sendable {
        /// SHA-256.
        case sha256
        /// SHA-384.
        case sha384
        /// SHA-512.
        case sha512

        @usableFromInline
        var algorithmIdentifier: AlgorithmIdentifier {
            switch self {
            case .sha256:
                return .sha256
            case .sha384:
                return .sha384
            case .sha512:
                return .sha512
            }
        }
    }

    /// CMS key-encryption algorithms supported for RSA key-transport recipients.
    public enum KeyEncryptionAlgorithm: Sendable {
        /// RSAES-OAEP using SHA-256.
        case rsaOAEPWithSHA256
        /// RSAES-OAEP using SHA-1.
        case rsaOAEPWithSHA1
        /// RSA PKCS#1 v1.5 key transport.
        case rsaPKCS1v15
    }

    /// Errors thrown by CMS encryption, decryption, authentication, and digest operations.
    public enum EncryptionError: Swift.Error, Hashable, Sendable, CustomStringConvertible {
        case unsupportedAlgorithm(String)
        case noMatchingRecipient
        case invalidVersion(expected: Int, actual: Int)
        case missingInitializationVector
        case invalidContentEncryptionKeySize(expected: Int, actual: Int)
        case invalidCMSBlock(String)

        public var description: String {
            switch self {
            case .unsupportedAlgorithm(let detail):
                return "Unsupported algorithm: \(detail)"
            case .noMatchingRecipient:
                return "No matching recipient was found"
            case .invalidVersion(let expected, let actual):
                return "Invalid CMS version \(actual); expected \(expected)"
            case .missingInitializationVector:
                return "Missing initialization vector"
            case .invalidContentEncryptionKeySize(let expected, let actual):
                return "Invalid content encryption key size: expected \(expected), got \(actual)"
            case .invalidCMSBlock(let detail):
                return "Invalid CMS block: \(detail)"
            }
        }
    }

    @_spi(CMS)
    public enum Error: Swift.Error {
        case incorrectCMSVersionUsed
        case unexpectedCMSType
    }

    @_spi(CMS)
    public typealias SignatureVerificationResult = Result<Valid, VerificationError>

    public struct Valid: Hashable, Sendable {
        public var signer: Certificate

        @inlinable
        public init(signer: Certificate) {
            self.signer = signer
        }
    }

    @_spi(CMS) public enum VerificationError: Swift.Error, Hashable {
        case unableToValidateSigner(SignerValidationFailure)
        case invalidCMSBlock(InvalidCMSBlock)

        public struct SignerValidationFailure: Hashable, Swift.Error {
            @available(*, deprecated, renamed: "policyFailures")
            public var validationFailures: [VerificationResult.PolicyFailure] {
                get { self.policyFailures.map { .init($0) } }
                set { self.policyFailures = newValue.map { $0.upgrade() } }
            }

            public var policyFailures: [CertificateValidationResult.PolicyFailure]

            public var signer: Certificate

            @available(*, deprecated, renamed: "init(failures:signer:)")
            @inlinable
            public init(validationFailures: [VerificationResult.PolicyFailure], signer: Certificate) {
                self.policyFailures = validationFailures.map { $0.upgrade() }
                self.signer = signer
            }

            @inlinable
            public init(validationFailures: [CertificateValidationResult.PolicyFailure], signer: Certificate) {
                self.policyFailures = validationFailures
                self.signer = signer
            }
        }

        public struct InvalidCMSBlock: Hashable, Swift.Error {
            public var reason: String

            @inlinable
            public init(reason: String) {
                self.reason = reason
            }
        }

        @inlinable
        internal init(invalidCMSBlockReason: String) {
            self = .invalidCMSBlock(.init(reason: invalidCMSBlockReason))
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension _RSA.Encryption.PublicKey {
    init(_ publicKey: Certificate.PublicKey) throws {
        switch publicKey.backing {
        case .rsa(let rsa):
            try self.init(derRepresentation: rsa.derRepresentation)
        case .p256, .p384, .p521, .ed25519:
            throw CMS.EncryptionError.unsupportedAlgorithm("Recipient certificate does not contain an RSA public key")
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension _RSA.Encryption.PrivateKey {
    init(_ privateKey: Certificate.PrivateKey) throws {
        switch privateKey.backing {
        case .rsa(let rsa):
            try self.init(derRepresentation: rsa.derRepresentation)
        case .p256, .p384, .p521, .ed25519:
            throw CMS.EncryptionError.unsupportedAlgorithm("Private key is not an RSA private key")
        #if canImport(Darwin)
        case .secureEnclaveP256, .secKey:
            throw CMS.EncryptionError.unsupportedAlgorithm("Private key is not an RSA private key usable for CMS decryption")
        #endif
        case .custom:
            throw CMS.EncryptionError.unsupportedAlgorithm("Custom private keys are not supported for CMS decryption")
        }
    }
}
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Array where Element == CMSRecipientInfo {
    func matchingKeyTransRecipient(recipientCertificate: Certificate) throws -> CMSKeyTransRecipientInfo {
        for recipientInfo in self {
            switch recipientInfo {
            case .keyTransRecipientInfo(let keyTransRecipientInfo):
                if keyTransRecipientInfo.recipientIdentifier.matches(certificate: recipientCertificate) {
                    return keyTransRecipientInfo
                }

            case .keyAgreeRecipientInfo, .kekRecipientInfo, .passwordRecipientInfo, .otherRecipientInfo:
                break
            }
        }

        throw CMS.EncryptionError.noMatchingRecipient
    }
}


@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension CMSRecipientIdentifier {
    func matches(certificate: Certificate) -> Bool {
        switch self {
        case .issuerAndSerialNumber(let issuerAndSerialNumber):
            return certificate.issuer == issuerAndSerialNumber.issuer
                && certificate.serialNumber == issuerAndSerialNumber.serialNumber

        case .subjectKeyIdentifier(let subjectKeyIdentifier):
            return (try? certificate.extensions.subjectKeyIdentifier)?.keyIdentifier == subjectKeyIdentifier.keyIdentifier
        }
    }
}

extension AlgorithmIdentifier {
    func cmsCBCIV() throws -> AES._CBC.IV {
        switch self.algorithm {
        case .AlgorithmIdentifier.aes256CBC, .AlgorithmIdentifier.aes192CBC, .AlgorithmIdentifier.aes128CBC:
            guard let parameters = self.parameters else {
                throw CMS.EncryptionError.missingInitializationVector
            }
            let iv = try ASN1OctetString(asn1Any: parameters)
            return try AES._CBC.IV(ivBytes: iv.bytes)
        default:
            throw CMS.EncryptionError.unsupportedAlgorithm("Unsupported CBC algorithm \(self.algorithm)")
        }
    }

    func cmsGCMParameters() throws -> CMSGCMParameters {
        switch self.algorithm {
        case .AlgorithmIdentifier.aes256GCM, .AlgorithmIdentifier.aes192GCM, .AlgorithmIdentifier.aes128GCM:
            guard let parameters = self.parameters else {
                throw CMS.EncryptionError.invalidCMSBlock("Missing GCM parameters")
            }
            let gcmParameters = try CMSGCMParameters(asn1Any: parameters)
            guard gcmParameters.icvLength == CMSGCMParameters.supportedICVLength else {
                throw CMS.EncryptionError.unsupportedAlgorithm(
                    "Unsupported AES-GCM authentication tag length \(gcmParameters.icvLength)"
                )
            }
            return gcmParameters
        default:
            throw CMS.EncryptionError.unsupportedAlgorithm("Unsupported GCM algorithm \(self.algorithm)")
        }
    }

    func cmsRSAEncryptionPadding(allowLegacyKeyEncryption: Bool = false) throws -> _RSA.Encryption.Padding {
        switch self.algorithm {
        case .AlgorithmIdentifier.rsaEncryption:
            guard allowLegacyKeyEncryption else {
                throw CMS.EncryptionError.unsupportedAlgorithm(
                    "RSA-PKCS1v15 requires allowLegacyKeyEncryption"
                )
            }
            return ._WEAK_AND_INSECURE_PKCS_V1_5

        case .AlgorithmIdentifier.rsaESOAEP:
            guard let parameters = self.parameters else {
                return .PKCS1_OAEP
            }

            let params = try CMSRSAESOAEPParams(asn1Any: parameters)
            return try params.supportedPadding()

        default:
            throw CMS.EncryptionError.unsupportedAlgorithm("Unsupported key encryption algorithm \(self.algorithm)")
        }
    }

    func cmsContentEncryptionKeySize() throws -> Int {
        switch self.algorithm {
        case .AlgorithmIdentifier.aes256CBC, .AlgorithmIdentifier.aes256GCM:
            return 32
        case .AlgorithmIdentifier.aes192CBC, .AlgorithmIdentifier.aes192GCM:
            return 24
        case .AlgorithmIdentifier.aes128CBC, .AlgorithmIdentifier.aes128GCM:
            return 16
        default:
            throw CMS.EncryptionError.unsupportedAlgorithm("Cannot determine key size for \(self.algorithm)")
        }
    }
    func cmsKeyEncryptionKeySize() throws -> Int {
        switch self.algorithm {
        case .AlgorithmIdentifier.aesKeyWrap128:
            return 16
        case .AlgorithmIdentifier.aesKeyWrap256:
            return 32
        default:
            throw CMS.EncryptionError.unsupportedAlgorithm("Cannot determine key-encryption key size for \(self.algorithm)")
        }
    }


    func cmsUnwrapContentEncryptionKey(_ encryptedKey: ASN1OctetString, using kek: SymmetricKey) throws -> SymmetricKey {
        let expectedKeySize = try self.cmsKeyEncryptionKeySize()
        let actualKeySize = kek.bitCount / 8
        guard actualKeySize == expectedKeySize else {
            throw CMS.EncryptionError.invalidCMSBlock(
                "Key-encryption key size \(actualKeySize) does not match key-encryption algorithm; expected \(expectedKeySize)"
            )
        }

        switch self.algorithm {
        case .AlgorithmIdentifier.aesKeyWrap128, .AlgorithmIdentifier.aesKeyWrap256:
            return try AES.KeyWrap.unwrap(encryptedKey.bytes, using: kek)
        default:
            throw CMS.EncryptionError.unsupportedAlgorithm("Unsupported key encryption algorithm \(self.algorithm)")
        }
    }

    func cmsDerivedKey(from password: String, outputByteCount expectedOutputByteCount: Int) throws -> SymmetricKey {
        guard self.algorithm == .AlgorithmIdentifier.pbkdf2 else {
            throw CMS.EncryptionError.unsupportedAlgorithm("Expected PBKDF2 key derivation algorithm, got \(self.algorithm)")
        }
        guard let parameters = self.parameters else {
            throw CMS.EncryptionError.invalidCMSBlock("PBKDF2 parameters are missing")
        }

        let params = try CMSPBKDF2Params(asn1Any: parameters)
        guard params.iterationCount > 0 else {
            throw CMS.EncryptionError.invalidCMSBlock("PBKDF2 iteration count must be positive")
        }
        if let keyLength = params.keyLength {
            guard keyLength == expectedOutputByteCount else {
                throw CMS.EncryptionError.invalidCMSBlock(
                    "PBKDF2 key length \(keyLength) does not match key-encryption algorithm; expected \(expectedOutputByteCount)"
                )
            }
        }
        let passwordData = ZeroedBytes(Array(password.utf8))
        defer { passwordData.zero() }
        let hashFunction = try params.prf.cmsPBKDF2HashFunction()

        if params.iterationCount >= 210_000 {
            return try KDF.Insecure.PBKDF2.deriveKey(
                from: passwordData.bytes,
                salt: params.salt.bytes,
                using: hashFunction,
                outputByteCount: expectedOutputByteCount,
                rounds: params.iterationCount
            )
        }
        return try KDF.Insecure.PBKDF2.deriveKey(
            from: passwordData.bytes,
            salt: params.salt.bytes,
            using: hashFunction,
            outputByteCount: expectedOutputByteCount,
            unsafeUncheckedRounds: params.iterationCount
        )
    }

    func cmsPBKDF2HashFunction() throws -> KDF.Insecure.PBKDF2.HashFunction {
        switch self.algorithm {
        case .AlgorithmIdentifier.hmacWithSHA256:
            return .sha256
        case .AlgorithmIdentifier.hmacWithSHA1:
            return .insecureSHA1
        default:
            throw CMS.EncryptionError.unsupportedAlgorithm("Unsupported PBKDF2 PRF \(self.algorithm)")
        }
    }
}

extension CMSRSAESOAEPParams {
    enum SupportedDigest {
        case sha1
        case sha256
    }

    func supportedPadding() throws -> _RSA.Encryption.Padding {
        let hashAlgorithm = try SupportedDigest(self.hashAlgorithm)
        let maskGenAlgorithm = try self.supportedMGF1Digest()
        guard hashAlgorithm == maskGenAlgorithm else {
            throw CMS.EncryptionError.invalidCMSBlock("RSA-OAEP hash and MGF1 hash do not match")
        }

        try self.validatePSourceAlgorithm()

        switch hashAlgorithm {
        case .sha1:
            return .PKCS1_OAEP
        case .sha256:
            return .PKCS1_OAEP_SHA256
        }
    }

    func supportedMGF1Digest() throws -> SupportedDigest {
        guard self.maskGenAlgorithm.algorithm == .AlgorithmIdentifier.mgf1 else {
            throw CMS.EncryptionError.unsupportedAlgorithm("Unsupported RSA-OAEP mask generation algorithm")
        }

        guard let parameters = self.maskGenAlgorithm.parameters else {
            return .sha1
        }

        return try SupportedDigest(AlgorithmIdentifier(asn1Any: parameters))
    }

    func validatePSourceAlgorithm() throws {
        guard self.pSourceAlgorithm.algorithm == .AlgorithmIdentifier.pSpecified else {
            throw CMS.EncryptionError.unsupportedAlgorithm("Unsupported RSA-OAEP pSource algorithm")
        }

        guard let parameters = self.pSourceAlgorithm.parameters else {
            return
        }

        let label = try ASN1OctetString(asn1Any: parameters)
        guard label.bytes.isEmpty else {
            throw CMS.EncryptionError.unsupportedAlgorithm("RSA-OAEP labels are not supported")
        }
    }
}

extension CMSRSAESOAEPParams.SupportedDigest {
    init(_ algorithmIdentifier: AlgorithmIdentifier) throws {
        switch algorithmIdentifier.algorithm {
        case .AlgorithmIdentifier.sha1:
            self = .sha1
        case .AlgorithmIdentifier.sha256:
            self = .sha256
        default:
            throw CMS.EncryptionError.unsupportedAlgorithm("Unsupported RSA-OAEP digest algorithm \(algorithmIdentifier.algorithm)")
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Array where Element == Certificate {
    @usableFromInline
    func certificate(signerInfo: CMSSignerInfo) throws -> Certificate? {
        switch signerInfo.signerIdentifier {
        case .issuerAndSerialNumber(let issuerAndSerialNumber):
            return self.first { cert in
                cert.issuer == issuerAndSerialNumber.issuer && cert.serialNumber == issuerAndSerialNumber.serialNumber
            }

        case .subjectKeyIdentifier(let subjectKeyIdentifier):
            return self.first { cert in
                (try? cert.extensions.subjectKeyIdentifier)?.keyIdentifier == subjectKeyIdentifier.keyIdentifier
            }
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.Signature {
    @inlinable
    init(signatureAlgorithm: Certificate.SignatureAlgorithm, signatureBytes: ASN1OctetString) throws {
        self = try Certificate.Signature(
            signatureAlgorithm: signatureAlgorithm,
            signatureBytes: ASN1BitString(bytes: signatureBytes.bytes)
        )
    }
}

/// A helper that holds a sensitive byte array and attempts to zero the memory
/// when the value is no longer needed.
@usableFromInline
final class ZeroedBytes {
    @usableFromInline
    private(set) var bytes: [UInt8]

    @usableFromInline
    init(_ bytes: [UInt8]) {
        self.bytes = bytes
    }

    @usableFromInline
    var symmetricKey: SymmetricKey {
        SymmetricKey(data: self.bytes)
    }

    @usableFromInline
    @inline(never)
    static func _secureZero(_ buffer: UnsafeMutableRawBufferPointer) {
        guard let baseAddress = buffer.baseAddress, buffer.count > 0 else { return }
        #if canImport(Darwin)
        memset_s(baseAddress, buffer.count, 0, buffer.count)
        #elseif canImport(Glibc) || canImport(Musl)
        explicit_bzero(baseAddress, buffer.count)
        #elseif canImport(WinSDK)
        SecureZeroMemory(baseAddress, buffer.count)
        #else
        // No secure zeroing primitive available — use a volatile-style workaround.
        // The @inline(never) on _secureZero prevents the Swift frontend from eliminating
        // this, but does not protect against LTO. Prefer adding a platform branch.
        for i in 0..<buffer.count {
            buffer.storeBytes(of: 0, toByteOffset: i, as: UInt8.self)
        }
        #endif
    }

    @usableFromInline
    func zero() {
        self.bytes.withUnsafeMutableBytes { ZeroedBytes._secureZero($0) }
        self.bytes = []
    }

    deinit {
        self.bytes.withUnsafeMutableBytes { ZeroedBytes._secureZero($0) }
    }
}
