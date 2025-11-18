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
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
@preconcurrency import Crypto
import _CryptoExtras

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate {
    /// A private key that can be used with a certificate.
    ///
    /// This type provides an opaque wrapper around the various private key types
    /// provided by `swift-crypto` and `Security`. Users are expected to construct this key from
    /// one of those types.
    ///
    /// As private keys are never sent over the wire, this type does not offer
    /// support for being unwrapped back into the underlying key types.
    public struct PrivateKey {
        @usableFromInline
        var backing: BackingPrivateKey

        @inlinable
        internal init(backing: BackingPrivateKey) {
            self.backing = backing
        }

        /// Construct a private key wrapping a P256 private key.
        /// - Parameter p256: The P256 private key to wrap.
        @inlinable
        public init(_ p256: P256.Signing.PrivateKey) {
            self.backing = .p256(p256)
        }

        /// Construct a private key wrapping a P384 private key.
        /// - Parameter p384: The P384 private key to wrap.
        @inlinable
        public init(_ p384: P384.Signing.PrivateKey) {
            self.backing = .p384(p384)
        }

        /// Construct a private key wrapping a P521 private key.
        /// - Parameter p521: The P521 private key to wrap.
        @inlinable
        public init(_ p521: P521.Signing.PrivateKey) {
            self.backing = .p521(p521)
        }

        /// Construct a private key wrapping a RSA private key.
        /// - Parameter rsa: The RSA private key to wrap.
        @inlinable
        public init(_ rsa: _RSA.Signing.PrivateKey) {
            self.backing = .rsa(rsa)
        }

        /// Construct a private key wrapping an Ed25519 private key.
        /// - Parameter ed25519: The Ed25519 private key to wrap.
        @inlinable
        public init(_ ed25519: Curve25519.Signing.PrivateKey) {
            self.backing = .ed25519(ed25519)
        }

        #if canImport(Darwin)
        /// Construct a private key wrapping a SecureEnclave.P256 private key.
        /// - Parameter secureEnclaveP256: The SecureEnclave.P256 private key to wrap.
        @inlinable
        public init(_ secureEnclaveP256: SecureEnclave.P256.Signing.PrivateKey) {
            self.backing = .secureEnclaveP256(secureEnclaveP256)
        }

        /// Construct a private key wrapping a SecKey private key.
        /// - Parameter secKey: The SecKey private key to wrap.
        @inlinable
        public init(_ secKey: SecKey) throws {
            self.backing = .secKey(try SecKeyWrapper(key: secKey))
        }
        #endif

        /// Use the private key to sign the provided bytes with a given signature algorithm.
        ///
        /// - Parameters:
        ///   - bytes: The data to create the signature for.
        ///   - signatureAlgorithm: The signature algorithm to use.
        /// - Returns: The signature.
        @inlinable
        public func sign<Bytes: DataProtocol>(
            bytes: Bytes,
            signatureAlgorithm: SignatureAlgorithm
        ) throws -> Signature {
            switch self.backing {
            case .p256(let p256):
                return try p256.signature(for: bytes, signatureAlgorithm: signatureAlgorithm)
            case .p384(let p384):
                return try p384.signature(for: bytes, signatureAlgorithm: signatureAlgorithm)
            case .p521(let p521):
                return try p521.signature(for: bytes, signatureAlgorithm: signatureAlgorithm)
            case .rsa(let rsa):
                return try rsa.signature(for: bytes, signatureAlgorithm: signatureAlgorithm)
            #if canImport(Darwin)
            case .secureEnclaveP256(let secureEnclaveP256):
                return try secureEnclaveP256.signature(for: bytes, signatureAlgorithm: signatureAlgorithm)
            case .secKey(let secKeyWrapper):
                return try secKeyWrapper.signature(for: bytes, signatureAlgorithm: signatureAlgorithm)
            #endif
            case .ed25519(let ed25519):
                return try ed25519.signature(for: bytes, signatureAlgorithm: signatureAlgorithm)
            }
        }

        /// Obtain the ``Certificate/PublicKey-swift.struct`` corresponding to
        /// this private key.
        @inlinable
        public var publicKey: PublicKey {
            switch self.backing {
            case .p256(let p256):
                return PublicKey(p256.publicKey)
            case .p384(let p384):
                return PublicKey(p384.publicKey)
            case .p521(let p521):
                return PublicKey(p521.publicKey)
            case .rsa(let rsa):
                return PublicKey(rsa.publicKey)
            #if canImport(Darwin)
            case .secureEnclaveP256(let secureEnclaveP256):
                return PublicKey(secureEnclaveP256.publicKey)
            case .secKey(let secKeyWrapper):
                return secKeyWrapper.publicKey
            #endif
            case .ed25519(let ed25519):
                return PublicKey(ed25519.publicKey)
            }
        }

        @inlinable
        var defaultSignatureAlgorithm: SignatureAlgorithm {
            switch backing {
            case .p256:
                return .ecdsaWithSHA256
            case .p384:
                return .ecdsaWithSHA384
            case .p521:
                return .ecdsaWithSHA512
            case .rsa:
                return .sha256WithRSAEncryption
            #if canImport(Darwin)
            case .secureEnclaveP256:
                return .ecdsaWithSHA256
            case .secKey(let key):
                switch key.type {
                case .RSA:
                    return .sha256WithRSAEncryption
                case .ECDSA(let keySize):
                    switch keySize {
                    case .P256:
                        return .ecdsaWithSHA256
                    case .P384:
                        return .ecdsaWithSHA384
                    case .P521:
                        return .ecdsaWithSHA512
                    }
                }
            #endif
            case .ed25519:
                return .ed25519
            }
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.PrivateKey: Hashable {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.PrivateKey: Sendable {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.PrivateKey: CustomStringConvertible {
    public var description: String {
        switch self.backing {
        case .p256:
            return "P256.PrivateKey"
        case .p384:
            return "P384.PrivateKey"
        case .p521:
            return "P521.PrivateKey"
        case .rsa(let publicKey):
            return "RSA\(publicKey.keySizeInBits).PrivateKey"
        #if canImport(Darwin)
        case .secureEnclaveP256:
            return "SecureEnclave.P256.PrivateKey"
        case .secKey:
            return "SecKey"
        #endif
        case .ed25519:
            return "Ed25519.PrivateKey"
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.PrivateKey {
    @usableFromInline
    enum BackingPrivateKey: Hashable, Sendable {
        case p256(Crypto.P256.Signing.PrivateKey)
        case p384(Crypto.P384.Signing.PrivateKey)
        case p521(Crypto.P521.Signing.PrivateKey)
        case rsa(_CryptoExtras._RSA.Signing.PrivateKey)
        #if canImport(Darwin)
        case secureEnclaveP256(SecureEnclave.P256.Signing.PrivateKey)
        case secKey(SecKeyWrapper)
        #endif
        case ed25519(Crypto.Curve25519.Signing.PrivateKey)

        @inlinable
        static func == (lhs: BackingPrivateKey, rhs: BackingPrivateKey) -> Bool {
            switch (lhs, rhs) {
            case (.p256(let l), .p256(let r)):
                return l.rawRepresentation == r.rawRepresentation
            case (.p384(let l), .p384(let r)):
                return l.rawRepresentation == r.rawRepresentation
            case (.p521(let l), .p521(let r)):
                return l.rawRepresentation == r.rawRepresentation
            case (.rsa(let l), .rsa(let r)):
                return l.derRepresentation == r.derRepresentation
            #if canImport(Darwin)
            case (.secureEnclaveP256(let l), .secureEnclaveP256(let r)):
                return l.dataRepresentation == r.dataRepresentation
            case (.secKey(let l), .secKey(let r)):
                return l.publicKey.backing == r.publicKey.backing
            #endif
            case (.ed25519(let l), .ed25519(let r)):
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
                hasher.combine(digest.derRepresentation)
            #if canImport(Darwin)
            case .secureEnclaveP256(let digest):
                hasher.combine(4)
                hasher.combine(digest.dataRepresentation)
            case .secKey(let secKeyWrapper):
                hasher.combine(5)
                hasher.combine(secKeyWrapper.privateKey.hashValue)
                hasher.combine(secKeyWrapper.publicKey.hashValue)
            #endif
            case .ed25519(let digest):
                hasher.combine(6)
                hasher.combine(digest.rawRepresentation)
            }
        }
    }
}

@available(macOS 11.0, iOS 14, tvOS 14, watchOS 7, macCatalyst 14, visionOS 1.0, *)
extension Certificate.PrivateKey {
    @inlinable
    static var pemDiscriminatorForRSA: String { "RSA PRIVATE KEY" }

    @inlinable
    static var pemDiscriminatorForSEC1: String { "EC PRIVATE KEY" }

    @inlinable
    static var pemDiscriminatorForPKCS8: String { "PRIVATE KEY" }

    @inlinable
    public init(pemEncoded: String) throws {
        try self.init(pemDocument: PEMDocument(pemString: pemEncoded))
    }

    @inlinable
    public init(pemDocument: PEMDocument) throws {
        switch pemDocument.discriminator {
        case Self.pemDiscriminatorForRSA:
            self = try .init(_CryptoExtras._RSA.Signing.PrivateKey.init(derRepresentation: pemDocument.derBytes))

        case Self.pemDiscriminatorForSEC1:
            let sec1 = try SEC1PrivateKey(derEncoded: pemDocument.derBytes)
            self = try .init(ecdsaAlgorithm: sec1.algorithm, rawEncodedPrivateKey: sec1.privateKey.bytes)

        case Self.pemDiscriminatorForPKCS8:
            self = try .init(derBytes: pemDocument.derBytes)

        default:
            throw ASN1Error.invalidPEMDocument(
                reason:
                    "PEMDocument has incorrect discriminator \(pemDocument.discriminator). Expected \(Self.pemDiscriminatorForPKCS8), \(Self.pemDiscriminatorForSEC1) or \(Self.pemDiscriminatorForRSA) instead"
            )
        }
    }

    @inlinable
    init(ecdsaAlgorithm: AlgorithmIdentifier?, rawEncodedPrivateKey: ArraySlice<UInt8>) throws {
        switch ecdsaAlgorithm {
        case .some(.ecdsaP256):
            self = try .init(P256.Signing.PrivateKey(rawRepresentation: rawEncodedPrivateKey))
        case .some(.ecdsaP384):
            self = try .init(P384.Signing.PrivateKey(rawRepresentation: rawEncodedPrivateKey))
        case .some(.ecdsaP521):
            self = try .init(P521.Signing.PrivateKey(rawRepresentation: rawEncodedPrivateKey))
        default:
            throw CertificateError.unsupportedPrivateKey(
                reason: "unknown algorithm \(String(reflecting: ecdsaAlgorithm))"
            )
        }
    }

    @inlinable
    public func serializeAsPEM() throws -> PEMDocument {
        switch backing {
        case .p256(let key): return try PEMDocument(pemString: key.pemRepresentation)
        case .p384(let key): return try PEMDocument(pemString: key.pemRepresentation)
        case .p521(let key): return try PEMDocument(pemString: key.pemRepresentation)
        case .rsa(let key): return try PEMDocument(pemString: key.pemRepresentation)
        #if canImport(Darwin)
        case .secureEnclaveP256:
            throw CertificateError.unsupportedPrivateKey(
                reason: "secure enclave private keys can not be serialised as PEM"
            )
        case .secKey(let key): return try key.pemDocument()
        #endif
        case .ed25519(let key): return key.pemRepresentation
        }
    }
}

@available(macOS 11.0, iOS 14, tvOS 14, watchOS 7, macCatalyst 14, visionOS 1.0, *)
extension Certificate.PrivateKey {
    /// Initialize a new certificate private key from PKCS8-format DER bytes.
    public init(derBytes: [UInt8]) throws {
        let pkcs8 = try PKCS8PrivateKey(derEncoded: derBytes)
        switch pkcs8.algorithm {
        case .ecdsaP256, .ecdsaP384, .ecdsaP521:
            let sec1 = try SEC1PrivateKey(derEncoded: pkcs8.privateKey.bytes)
            if let innerAlgorithm = sec1.algorithm, innerAlgorithm != pkcs8.algorithm {
                throw ASN1Error.invalidASN1Object(
                    reason: "algorithm mismatch. PKCS#8 is \(pkcs8.algorithm) but inner SEC1 is \(innerAlgorithm)"
                )
            }
            self = try .init(ecdsaAlgorithm: pkcs8.algorithm, rawEncodedPrivateKey: sec1.privateKey.bytes)

        case .rsaKey:
            self = try .init(_CryptoExtras._RSA.Signing.PrivateKey(derRepresentation: pkcs8.privateKey.bytes))
        case .ed25519:
            self = try .init(Curve25519.Signing.PrivateKey(pkcs8Key: pkcs8))
        default:
            throw CertificateError.unsupportedPrivateKey(reason: "unknown algorithm \(pkcs8.algorithm)")
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.PrivateKey {
    /// Return a list of all supported signature types for this private key. The ordering is not a comment on the
    /// preference or security of the contained algorithms.
    @inlinable
    public var supportedSignatureAlgorithms: [Certificate.SignatureAlgorithm] {
        switch backing {
        case .p256, .p384, .p521:
            return [.ecdsaWithSHA512, .ecdsaWithSHA384, .ecdsaWithSHA256]
        case .rsa:
            return [
                .sha512WithRSAEncryption, .sha384WithRSAEncryption, .sha256WithRSAEncryption, .sha1WithRSAEncryption,
            ]
        #if canImport(Darwin)
        case .secureEnclaveP256:
            return [.ecdsaWithSHA512, .ecdsaWithSHA384, .ecdsaWithSHA256]
        case .secKey(let key):
            switch key.type {
            case .RSA:
                return [
                    .sha512WithRSAEncryption, .sha384WithRSAEncryption, .sha256WithRSAEncryption,
                    .sha1WithRSAEncryption,
                ]
            case .ECDSA:
                return [.ecdsaWithSHA512, .ecdsaWithSHA384, .ecdsaWithSHA256]
            }
        #endif
        case .ed25519:
            return [.ed25519]
        }
    }
}
