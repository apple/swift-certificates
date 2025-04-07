//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCertificates open source project
//
// Copyright (c) 2024 Apple Inc. and the SwiftCertificates project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCertificates project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

#if canImport(Darwin)
import SwiftASN1
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
@preconcurrency import Crypto
@preconcurrency import _CryptoExtras
@preconcurrency import Security

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.PrivateKey {
    /// A wrapper around ``Security.SecKey`` to allow the use of `SecKey` with certificates.
    @usableFromInline
    struct SecKeyWrapper: Sendable {
        @usableFromInline
        let privateKey: SecKey
        @usableFromInline
        let publicKey: Certificate.PublicKey
        @usableFromInline
        let type: KeyType
        @usableFromInline
        let attributes: [String: any Sendable]

        @usableFromInline
        enum ECKeySize: Sendable {
            case P256
            case P384
            case P521
        }

        @usableFromInline
        enum KeyType: Sendable {
            case RSA
            case ECDSA(ECKeySize)
        }

        /// Init with an existing `SecKey`.
        ///
        /// This parses the given `SecKey` and attempts to pre-emptively extract
        /// data that will be needed at later points. Importantly, some of these operations
        /// can throw, so these are performs during initialisation rather than at later
        /// stages where throwing is unacceptable.
        @inlinable
        init(key: SecKey) throws {
            self.privateKey = key

            self.attributes = try Self.keyAttributes(key: key)

            try Self.validateSecKey(attributes: self.attributes)

            self.type = try Self.keyType(attributes: self.attributes)

            self.publicKey = try Self.publicKey(privateKey: key, type: self.type)
        }

        @usableFromInline
        static func keyAttributes(key: SecKey) throws -> [String: any Sendable] {
            guard let attributes = SecKeyCopyAttributes(key) as? [CFString: any Sendable] else {
                throw CertificateError.unsupportedPrivateKey(
                    reason: "cannot copy SecKey attributes"
                )
            }

            return attributes as [String: any Sendable]
        }

        @usableFromInline
        static func validateSecKey(attributes: [String: any Sendable]) throws {
            guard let keyClassType = attributes[kSecAttrKeyClass as String] as? String else {
                throw CertificateError.unsupportedPrivateKey(
                    reason: "cannot determine class of SecKey"
                )
            }

            let privateKeyClassType = kSecAttrKeyClassPrivate as String
            if keyClassType != privateKeyClassType {
                throw CertificateError.unsupportedPrivateKey(
                    reason: "SecKey class must be \(privateKeyClassType), not \(keyClassType)"
                )
            }
        }

        @usableFromInline
        static func publicKeyData(privateKey: SecKey) throws -> Data {
            var error: Unmanaged<CFError>? = nil
            guard let publicSecKey = SecKeyCopyPublicKey(privateKey),
                let publicKeyData = SecKeyCopyExternalRepresentation(publicSecKey, &error) as Data?
            else {
                if let error = error?.takeRetainedValue() {
                    throw CertificateError.unsupportedPrivateKey(
                        reason: "cannot get public key from SecKey instance: \(error)"
                    )
                }

                throw CertificateError.unsupportedPrivateKey(
                    reason: "SecKeyCopyExternalRepresentation returned empty data"
                )
            }

            return publicKeyData
        }

        @usableFromInline
        static func keyType(attributes: [String: any Sendable]) throws -> KeyType {
            guard let privateKeyType = attributes[kSecAttrKeyType as String] as? String else {
                throw CertificateError.unsupportedPrivateKey(
                    reason: "cannot get SecKey type"
                )
            }

            if privateKeyType == (kSecAttrKeyTypeECSECPrimeRandom as String) {
                let keySize = attributes[kSecAttrKeySizeInBits as String] as? Int ?? -1

                if keySize == 256 {
                    return .ECDSA(.P256)
                } else if keySize == 384 {
                    return .ECDSA(.P384)
                } else if keySize == 521 {
                    return .ECDSA(.P521)
                } else {
                    throw CertificateError.unsupportedPrivateKey(
                        reason: "unsupported SecKey key size: \(keySize)"
                    )
                }
            } else if privateKeyType == (kSecAttrKeyTypeRSA as String) {
                return .RSA
            } else {
                throw CertificateError.unsupportedPrivateKey(
                    reason: "unsupported SecKey key type: \(privateKeyType)"
                )
            }
        }

        @usableFromInline
        static func publicKey(privateKey: SecKey, type: KeyType) throws -> Certificate.PublicKey {
            let publicKeyData = try Self.publicKeyData(privateKey: privateKey)

            do {
                switch type {
                case .ECDSA(let keySize):
                    if keySize == .P256 {
                        return Certificate.PublicKey(try P256.Signing.PublicKey(x963Representation: publicKeyData))
                    } else if keySize == .P384 {
                        return Certificate.PublicKey(try P384.Signing.PublicKey(x963Representation: publicKeyData))
                    } else if keySize == .P521 {
                        return Certificate.PublicKey(try P521.Signing.PublicKey(x963Representation: publicKeyData))
                    } else {
                        throw CertificateError.unsupportedPrivateKey(
                            reason: "unsupported SecKey ECDSA key size: \(keySize)"
                        )
                    }
                case .RSA:
                    return Certificate.PublicKey(try _RSA.Signing.PublicKey(derRepresentation: publicKeyData))
                }
            } catch {
                throw CertificateError.unsupportedPrivateKey(
                    reason: "cannot get public key from SecKey instance \(error)"
                )
            }
        }

        static func signatureData<Bytes: DataProtocol>(
            key: SecKey,
            type: KeyType,
            signatureAlgorithm: Certificate.SignatureAlgorithm,
            bytes: Bytes
        ) throws -> Data {

            let signatureAlgorithm = try Self.keyAlgorithm(signatureAlgorithm: signatureAlgorithm, type: type)

            var error: Unmanaged<CFError>?
            guard
                let signatureData = SecKeyCreateSignature(
                    key,
                    signatureAlgorithm,
                    Data(bytes) as CFData,
                    &error
                ) as Data?
            else {
                if let error = error?.takeRetainedValue() {
                    throw CertificateError.unsupportedPrivateKey(
                        reason: "could not create signature with SecKey: \(error)"
                    )
                }

                throw CertificateError.unsupportedPrivateKey(reason: "SecKeyCreateSignature returned empty data")
            }

            return signatureData
        }

        static func keyAlgorithm(
            signatureAlgorithm: Certificate.SignatureAlgorithm,
            type: KeyType
        ) throws -> SecKeyAlgorithm {
            let algorithm: SecKeyAlgorithm
            switch type {
            case .RSA:
                switch signatureAlgorithm {
                case .sha1WithRSAEncryption:
                    algorithm = .rsaSignatureMessagePKCS1v15SHA1
                case .sha256WithRSAEncryption:
                    algorithm = .rsaSignatureMessagePKCS1v15SHA256
                case .sha384WithRSAEncryption:
                    algorithm = .rsaSignatureMessagePKCS1v15SHA384
                case .sha512WithRSAEncryption:
                    algorithm = .rsaSignatureMessagePKCS1v15SHA512
                default:
                    throw CertificateError.unsupportedSignatureAlgorithm(
                        reason: "Cannot use \(signatureAlgorithm) with RSA key"
                    )
                }
            case .ECDSA:
                switch signatureAlgorithm {
                case .ecdsaWithSHA256:
                    algorithm = .ecdsaSignatureMessageX962SHA256
                case .ecdsaWithSHA384:
                    algorithm = .ecdsaSignatureMessageX962SHA384
                case .ecdsaWithSHA512:
                    algorithm = .ecdsaSignatureMessageX962SHA512
                default:
                    throw CertificateError.unsupportedSignatureAlgorithm(
                        reason: "Cannot use \(signatureAlgorithm) with ECDSA key"
                    )
                }
            }

            return algorithm
        }

        @usableFromInline
        func signature<Bytes: DataProtocol>(
            for bytes: Bytes,
            signatureAlgorithm: Certificate.SignatureAlgorithm
        ) throws -> Certificate.Signature {

            let signatureData = try Self.signatureData(
                key: self.privateKey,
                type: self.type,
                signatureAlgorithm: signatureAlgorithm,
                bytes: bytes
            )

            switch self.type {
            case .RSA:
                let signature = _RSA.Signing.RSASignature(rawRepresentation: signatureData)
                return Certificate.Signature(backing: .rsa(signature))
            case .ECDSA(let keySize):
                switch keySize {
                case .P256:
                    let signature = try P256.Signing.ECDSASignature(derRepresentation: signatureData)
                    return Certificate.Signature(backing: .ecdsa(.init(signature)))
                case .P384:
                    let signature = try P384.Signing.ECDSASignature(derRepresentation: signatureData)
                    return Certificate.Signature(backing: .ecdsa(.init(signature)))
                case .P521:
                    let signature = try P521.Signing.ECDSASignature(derRepresentation: signatureData)
                    return Certificate.Signature(backing: .ecdsa(.init(signature)))
                }
            }
        }

        @usableFromInline
        var isSerializable: Bool {
            if let extractable = self.attributes[kSecAttrIsExtractable as String] as? Bool {
                return extractable
            }

            return false
        }

        @available(macOS 11.0, iOS 14, tvOS 14, watchOS 7, macCatalyst 14, visionOS 1.0, *)
        @inlinable
        func pemDocument() throws -> PEMDocument {
            if !self.isSerializable {
                throw CertificateError.unsupportedPrivateKey(
                    reason: "SecKey private key PEM cannot be extracted"
                )
            }

            var error: Unmanaged<CFError>?
            guard let keyData = SecKeyCopyExternalRepresentation(self.privateKey, &error) as Data? else {
                if let error = error?.takeRetainedValue() {
                    throw CertificateError.unsupportedPrivateKey(
                        reason: "cannot get external representation of SecKey: \(error)"
                    )
                }

                throw CertificateError.unsupportedPrivateKey(
                    reason: "SecKeyCopyExternalRepresentation returned empty data"
                )
            }

            let derData: Data
            let type: String

            switch self.type {
            case .RSA:
                type = "RSA PRIVATE KEY"
                // keyData is DER-encoded private key
                derData = keyData
            case .ECDSA(let keySize):
                type = "EC PRIVATE KEY"
                switch keySize {
                case .P256:
                    derData = try P256.Signing.PrivateKey(x963Representation: keyData).derRepresentation
                case .P384:
                    derData = try P384.Signing.PrivateKey(x963Representation: keyData).derRepresentation
                case .P521:
                    derData = try P521.Signing.PrivateKey(x963Representation: keyData).derRepresentation
                }
            }

            let array = [UInt8](derData)
            return PEMDocument(type: type, derBytes: array)
        }
    }
}
#endif
