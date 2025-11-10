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

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate {
    /// A representation of a kind of signature algorithm.
    ///
    /// X.509 certificates support a wide range of signature algorithms. This type
    /// identifies the algorithm, independently of the signature itself.
    ///
    /// This type represents an unbounded enumeration. There are potentially infinite
    /// signature algorithms. Users are able to create representations of the signature
    /// algorithms this library supports by using static fields on this type.
    public struct SignatureAlgorithm {
        @usableFromInline
        var _algorithmIdentifier: AlgorithmIdentifier

        @inlinable
        init(algorithmIdentifier: AlgorithmIdentifier) {
            switch algorithmIdentifier {
            // Per RFC 4055 § 5, we need to accept the RSA parameters field being
            // absent, but we must _produce_ the one with an explicit NULL. So we
            // normalise the signature algorithm here.
            case .sha1WithRSAEncryptionUsingNil:
                self._algorithmIdentifier = .sha1WithRSAEncryption
            case .sha256WithRSAEncryptionUsingNil:
                self._algorithmIdentifier = .sha256WithRSAEncryption
            case .sha384WithRSAEncryptionUsingNil:
                self._algorithmIdentifier = .sha384WithRSAEncryption
            case .sha512WithRSAEncryptionUsingNil:
                self._algorithmIdentifier = .sha512WithRSAEncryption
            case let identifier:
                self._algorithmIdentifier = identifier
            }
        }

        /// This value represents an ECDSA signature using SHA256 and P256.
        public static let ecdsaWithSHA256 = Self(algorithmIdentifier: .ecdsaWithSHA256)

        /// This value represents an ECDSA signature using SHA384 and P384.
        public static let ecdsaWithSHA384 = Self(algorithmIdentifier: .ecdsaWithSHA384)

        /// This value represents an ECDSA signature using SHA512 and P521.
        public static let ecdsaWithSHA512 = Self(algorithmIdentifier: .ecdsaWithSHA512)

        /// This value represents an RSA signature with PKCS1v1.5 padding and SHA1 as the hash function.
        public static let sha1WithRSAEncryption = Self(algorithmIdentifier: .sha1WithRSAEncryption)

        /// This value represents an RSA signature with PKCS1v1.5 padding and SHA256 as the hash function.
        public static let sha256WithRSAEncryption = Self(algorithmIdentifier: .sha256WithRSAEncryption)

        /// This value represents an RSA signature with PKCS1v1.5 padding and SHA384 as the hash function.
        public static let sha384WithRSAEncryption = Self(algorithmIdentifier: .sha384WithRSAEncryption)

        /// This value represents an RSA signature with PKCS1v1.5 padding and SHA512 as the hash function.
        public static let sha512WithRSAEncryption = Self(algorithmIdentifier: .sha512WithRSAEncryption)

        /// This value represents an EdDSA signature using Curve25519.
        public static let ed25519 = Self(algorithmIdentifier: .ed25519)

        /// Whether this algorithm represents an ECDSA signature.
        @inlinable
        var isECDSA: Bool {
            switch self {
            case .ecdsaWithSHA256, .ecdsaWithSHA384, .ecdsaWithSHA512:
                return true
            default:
                return false
            }
        }

        @inlinable
        var isRSA: Bool {
            switch self {
            case .sha1WithRSAEncryption, .sha256WithRSAEncryption, .sha384WithRSAEncryption, .sha512WithRSAEncryption:
                return true
            default:
                return false
            }
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.SignatureAlgorithm: Hashable {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.SignatureAlgorithm: Sendable {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.SignatureAlgorithm: CustomStringConvertible {
    public var description: String {
        switch self {
        case .ecdsaWithSHA256:
            return "SignatureAlgorithm.ecdsaWithSHA256"
        case .ecdsaWithSHA384:
            return "SignatureAlgorithm.ecdsaWithSHA384"
        case .ecdsaWithSHA512:
            return "SignatureAlgorithm.ecdsaWithSHA512"
        case .sha1WithRSAEncryption:
            return "SignatureAlgorithm.sha1WithRSAEncryption"
        case .sha256WithRSAEncryption:
            return "SignatureAlgorithm.sha256WithRSAEncryption"
        case .sha384WithRSAEncryption:
            return "SignatureAlgorithm.sha384WithRSAEncryption"
        case .sha512WithRSAEncryption:
            return "SignatureAlgorithm.sha512WithRSAEncryption"
        case .ed25519:
            return "SignatureAlgorithm.ed25519"
        default:
            return "SignatureAlgorithm(\(self._algorithmIdentifier))"
        }

    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension AlgorithmIdentifier {
    @inlinable
    init(_ signatureAlgorithm: Certificate.SignatureAlgorithm) {
        self = signatureAlgorithm._algorithmIdentifier
    }

    @inlinable
    init(digestAlgorithmFor signatureAlgorithm: Certificate.SignatureAlgorithm) throws {
        // Per RFC 5754 § 2, we must produce digest algorithm identifiers with
        // absent parameters, so we do.
        switch signatureAlgorithm {
        case .ecdsaWithSHA256, .sha256WithRSAEncryption:
            self = .sha256UsingNil
        case .ecdsaWithSHA384, .sha384WithRSAEncryption:
            self = .sha384UsingNil
        case .ecdsaWithSHA512, .sha512WithRSAEncryption, .ed25519:
            self = .sha512UsingNil
        case .sha1WithRSAEncryption:
            self = .sha1
        default:
            throw CertificateError.unsupportedSignatureAlgorithm(
                reason: "Cannot generate digest algorithm for \(signatureAlgorithm)"
            )
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.SignatureAlgorithm {
    /// Map a signature algorithm to the signature scheme value defined in RFC 8446 for TLS 1.3.
    public var rfc8446SignatureSchemeValue: UInt16 {
        get throws {
            switch self {
            case .ecdsaWithSHA256:
                return 0x0403
            case .ecdsaWithSHA384:
                return 0x0503
            case .ecdsaWithSHA512:
                return 0x0603
            case .sha1WithRSAEncryption:
                return 0x0201
            case .sha256WithRSAEncryption:
                return 0x0401
            case .sha384WithRSAEncryption:
                return 0x0501
            case .sha512WithRSAEncryption:
                return 0x0601
            case .ed25519:
                return 0x0807
            default:
                throw CertificateError.unsupportedSignatureAlgorithm(
                    reason: "SignatureAlgorithm(\(self)) has an unsupprted value"
                )
            }
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.SignatureAlgorithm {
    /// Initialize a signature algorithm from a raw value as defined in RFC8446.
    ///
    /// Returns: The signature algorithm matching the value for the algorithms supported by Swift Certificates and
    ///     nil otherwise.
    public init?(rfc8446SignatureSchemeValue value: UInt16) {
        switch value {
        case 0x0403:
            self = .ecdsaWithSHA256
        case 0x0503:
            self = .ecdsaWithSHA384
        case 0x0603:
            self = .ecdsaWithSHA512
        case 0x0201:
            self = .sha1WithRSAEncryption
        case 0x0401:
            self = .sha256WithRSAEncryption
        case 0x0501:
            self = .sha384WithRSAEncryption
        case 0x0601:
            self = .sha512WithRSAEncryption
        case 0x0807:
            self = .ed25519
        default:
            return nil
        }
    }
}
