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
import Foundation
import SwiftASN1

public enum CMS {
    @_spi(CMS)
    @inlinable
    public static func sign<Bytes: DataProtocol>(
        _ bytes: Bytes,
        signatureAlgorithm: Certificate.SignatureAlgorithm,
        additionalIntermediateCertificates: [Certificate] = [],
        certificate: Certificate,
        privateKey: Certificate.PrivateKey
    ) throws -> [UInt8] {
        let signature = try privateKey.sign(bytes: bytes, signatureAlgorithm: signatureAlgorithm)
        return try sign(
            signatureBytes: ASN1OctetString(signature),
            signatureAlgorithm: signatureAlgorithm,
            additionalIntermediateCertificates: additionalIntermediateCertificates,
            certificate: certificate
        )
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
            certificate: certificate
        )

        var serializer = DER.Serializer()
        try serializer.serialize(signedData)
        return serializer.serializedBytes
    }

    @inlinable
    static func generateSignedData(
        signatureBytes: ASN1OctetString,
        signatureAlgorithm: Certificate.SignatureAlgorithm,
        additionalIntermediateCertificates: [Certificate],
        certificate: Certificate
    ) throws -> CMSContentInfo {
        let digestAlgorithm = try AlgorithmIdentifier(digestAlgorithmFor: signatureAlgorithm)
        let contentInfo = CMSEncapsulatedContentInfo(eContentType: .cmsData)

        let signerInfo = CMSSignerInfo(
            signerIdentifier: .init(issuerAndSerialNumber: certificate),
            digestAlgorithm: digestAlgorithm,
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
    public static func isValidSignature<
        DataBytes: DataProtocol,
        SignatureBytes: DataProtocol
    >(
        dataBytes: DataBytes,
        signatureBytes: SignatureBytes,
        additionalIntermediateCertificates: [Certificate] = [],
        trustRoots: CertificateStore,
        @PolicyBuilder policy: () throws -> some VerifierPolicy
    ) async rethrows -> SignatureVerificationResult {
        let signedData: CMSSignedData
        let signingCert: Certificate
        do {
            let parsedSignature = try CMSContentInfo(derEncoded: ArraySlice(signatureBytes))
            guard let _signedData = try parsedSignature.signedData else {
                return .failure(.init(invalidCMSBlockReason: "Unable to parse signed data"))
            }
            signedData = _signedData

            // We have a bunch of very specific requirements here: in particular, we need to have only one signature. We also only want
            // to tolerate v1 signatures and detached signatures.
            guard signedData.version == .v1, signedData.signerInfos.count == 1, signedData.encapContentInfo.eContentType == .cmsData,
                  signedData.encapContentInfo.eContent == nil else {
                return .failure(.init(invalidCMSBlockReason: "Invalid signed data: \(signedData)"))
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
            let signatureAlgorithm = Certificate.SignatureAlgorithm(algorithmIdentifier: signer.signatureAlgorithm)
            let expectedDigestAlgorithm = try AlgorithmIdentifier(digestAlgorithmFor: signatureAlgorithm)
            guard expectedDigestAlgorithm == signer.digestAlgorithm else {
                return .failure(.init(invalidCMSBlockReason: "Digest and signature algorithm mismatch"))
            }

            // Ok, now we need to find the signer. We expect to find them in the list of certificates provided
            // in the signature.
            guard let _signingCert = try signedData.certificates?.certificate(signerInfo: signer) else {
                return .failure(.init(invalidCMSBlockReason: "Unable to locate signing certificate"))
            }
            signingCert = _signingCert

            // Ok at this point we've done the cheap stuff and we're fairly confident we have the entity who should have
            // done the signing. Our next step is to confirm that they did in fact sign the data. For that we have to compute
            // the digest and validate the signature.
            let signature = try Certificate.Signature(signatureAlgorithm: signatureAlgorithm, signatureBytes: signer.signature)
            guard signingCert.publicKey.isValidSignature(signature, for: dataBytes, signatureAlgorithm: signatureAlgorithm) else {
                return .failure(.init(invalidCMSBlockReason: "Invalid signature from signing certificate: \(signingCert)"))
            }
        } catch {
            return .failure(.invalidCMSBlock(.init(reason: String(describing: error))))
        }

        // Ok, the signature was signed by the private key associated with this cert. Now we need to validate the certificate.
        // This force-unwrap is safe: we know there are certificates because we've located at least one certificate from this set!
        var untrustedIntermediates = CertificateStore(signedData.certificates!)
        untrustedIntermediates.insert(contentsOf: additionalIntermediateCertificates)
        
        var verifier = try Verifier(rootCertificates: trustRoots, policy: policy)
        let result = await verifier.validate(leafCertificate: signingCert, intermediates: untrustedIntermediates)

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

    public struct Valid: Hashable {
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
            public var validationFailures: [VerificationResult.PolicyFailure]

            public var signer: Certificate

            @inlinable
            public init(validationFailures: [VerificationResult.PolicyFailure], signer: Certificate) {
                self.validationFailures = validationFailures
                self.signer = signer
            }
        }

        public struct InvalidCMSBlock: Hashable, Swift.Error {
            public var reason: String

            @inlinable
            public init(reason: String){
                self.reason = reason
            }
        }

        @inlinable
        internal init(invalidCMSBlockReason: String) {
            self = .invalidCMSBlock(.init(reason: invalidCMSBlockReason))
        }
    }
}

extension Array where Element == Certificate {
    @usableFromInline
    func certificate(signerInfo: CMSSignerInfo) throws -> Certificate? {
        switch signerInfo.signerIdentifier {
        case .issuerAndSerialNumber(let issuerAndSerialNumber):
            for cert in self {
                if cert.issuer == issuerAndSerialNumber.issuer && cert.serialNumber == issuerAndSerialNumber.serialNumber {
                    return cert
                }
            }
        case .subjectKeyIdentifier:
            // This is unsupported for now.
            return nil
        }

        return nil
    }
}

extension Certificate.Signature {
    @inlinable
    init(signatureAlgorithm: Certificate.SignatureAlgorithm, signatureBytes: ASN1OctetString) throws {
        self = try Certificate.Signature(signatureAlgorithm: signatureAlgorithm, signatureBytes: ASN1BitString(bytes: signatureBytes.bytes))
    }
}
