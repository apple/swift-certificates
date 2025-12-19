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
    static func serializeSignedData(
        _ contentInfo: CMSContentInfo
    ) throws -> [UInt8] {
        var serializer = DER.Serializer()
        try serializer.serialize(contentInfo)
        return serializer.serializedBytes
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
