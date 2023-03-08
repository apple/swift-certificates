//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCertificates open source project
//
// Copyright (c) 2022 Apple Inc. and the SwiftCertificates project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCertificates project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import SwiftASN1
@preconcurrency import Crypto
@preconcurrency import _CryptoExtras
import Foundation

extension Certificate {
    /// An abstract representation of the cryptographic signature on a certificate.
    ///
    /// Certificates may have a wide range of signature types. This type provides a runtime
    /// abstraction across these types. It ensures that we understand the algorithm used to
    /// sign the certificate, and enables us to provide verification logic, without forcing
    /// users to wrestle with the wide variety of runtime types that may represent a
    /// signature.
    ///
    /// This type is almost entirely opaque. It can be validated by way of
    /// ``Certificate/PublicKey-swift.struct/isValidSignature(_:for:)``, and it
    /// can be generated by ``Certificate/PrivateKey``s automatically when
    /// used by ``Certificate/init(version:serialNumber:publicKey:notValidBefore:notValidAfter:issuer:subject:signatureAlgorithm:extensions:issuerPrivateKey:)``.
    /// Otherwise, this type has essentially no behaviours.
    public struct Signature {
        @usableFromInline
        var backing: BackingSignature

        @inlinable
        internal init(backing: BackingSignature) {
            self.backing = backing
        }

        @inlinable
        internal init(signatureAlgorithm: SignatureAlgorithm, signatureBytes: ASN1BitString) throws {
            switch signatureAlgorithm {
            case .ecdsaWithSHA256:
                let signature = try P256.Signing.ECDSASignature(derRepresentation: signatureBytes.bytes)
                self.backing = .p256(signature)
            case .ecdsaWithSHA384:
                let signature = try P384.Signing.ECDSASignature(derRepresentation: signatureBytes.bytes)
                self.backing = .p384(signature)
            case .ecdsaWithSHA512:
                let signature = try P521.Signing.ECDSASignature(derRepresentation: signatureBytes.bytes)
                self.backing = .p521(signature)
            case .sha1WithRSAEncryption:
                // TODO: We need to validate the signature is actually reasonable here.
                let signature = _RSA.Signing.RSASignature(rawRepresentation: signatureBytes.bytes)
                self.backing = .rsa(signature)
            case .sha256WithRSAEncryption:
                // TODO: We need to validate the signature is actually reasonable here.
                let signature = _RSA.Signing.RSASignature(rawRepresentation: signatureBytes.bytes)
                self.backing = .rsa(signature)
            case .sha384WithRSAEncryption:
                // TODO: We need to validate the signature is actually reasonable here.
                let signature = _RSA.Signing.RSASignature(rawRepresentation: signatureBytes.bytes)
                self.backing = .rsa(signature)
            case .sha512WithRSAEncryption:
                // TODO: We need to validate the signature is actually reasonable here.
                let signature = _RSA.Signing.RSASignature(rawRepresentation: signatureBytes.bytes)
                self.backing = .rsa(signature)
            default:
                throw CertificateError.unsupportedSignatureAlgorithm(reason: "\(signatureAlgorithm)")
            }
        }
    }
}

extension Certificate.Signature: Hashable { }

extension Certificate.Signature: Sendable { }

extension Certificate.Signature: CustomStringConvertible {
    public var description: String {
        return String(describing: self.backing)
    }
}

extension Certificate.Signature {
    @usableFromInline
    enum BackingSignature: Hashable, Sendable {
        case p256(Crypto.P256.Signing.ECDSASignature)
        case p384(Crypto.P384.Signing.ECDSASignature)
        case p521(Crypto.P521.Signing.ECDSASignature)
        case rsa(_CryptoExtras._RSA.Signing.RSASignature)

        @inlinable
        static func ==(lhs: BackingSignature, rhs: BackingSignature) -> Bool {
            switch (lhs, rhs) {
            case (.p256(let l), .p256(let r)):
                return l.rawRepresentation == r.rawRepresentation
            case (.p384(let l), .p384(let r)):
                return l.rawRepresentation == r.rawRepresentation
            case (.p521(let l), .p521(let r)):
                return l.rawRepresentation == r.rawRepresentation
            case (.rsa(let l), .rsa(let r)):
                return l.rawRepresentation == r.rawRepresentation
            default:
                return false
            }
        }

        @inlinable
        func hash(into hasher: inout Hasher) {
            switch self {
            case .p256(let digest):
                hasher.combine(0)
                hasher.combine(digest.rawRepresentation)
            case .p384(let digest):
                hasher.combine(1)
                hasher.combine(digest.rawRepresentation)
            case .p521(let digest):
                hasher.combine(2)
                hasher.combine(digest.rawRepresentation)
            case .rsa(let digest):
                hasher.combine(3)
                hasher.combine(digest.rawRepresentation)
            }
        }
    }
}

extension ASN1BitString {
    @inlinable
    init(_ signature: Certificate.Signature) {
        switch signature.backing {
        case .p256(let sig):
            self = ASN1BitString(bytes: ArraySlice(sig.derRepresentation))
        case .p384(let sig):
            self = ASN1BitString(bytes: ArraySlice(sig.derRepresentation))
        case .p521(let sig):
            self = ASN1BitString(bytes: ArraySlice(sig.derRepresentation))
        case .rsa(let sig):
            self = ASN1BitString(bytes: ArraySlice(sig.rawRepresentation))
        }
    }
}

extension ASN1OctetString {
    @inlinable
    init(_ signature: Certificate.Signature) {
        switch signature.backing {
        case .p256(let sig):
            self = ASN1OctetString(contentBytes: ArraySlice(sig.derRepresentation))
        case .p384(let sig):
            self = ASN1OctetString(contentBytes: ArraySlice(sig.derRepresentation))
        case .p521(let sig):
            self = ASN1OctetString(contentBytes: ArraySlice(sig.derRepresentation))
        case .rsa(let sig):
            self = ASN1OctetString(contentBytes: ArraySlice(sig.rawRepresentation))
        }
    }
}
