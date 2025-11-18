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
import _CryptoExtras
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate {
    /// A public key that can be used with a certificate.
    ///
    /// This type provides an opaque wrapper around the various public key types
    /// provided by `swift-crypto`. Users are expected to construct this key from
    /// one of those types, or to decode it from the network.
    public struct PublicKey {
        @usableFromInline
        var backing: BackingPublicKey

        @inlinable
        internal init(spki: SubjectPublicKeyInfo) throws {
            switch spki.algorithmIdentifier {
            case .p256PublicKey:
                let key = try P256.Signing.PublicKey(x963Representation: spki.key.bytes)
                self.backing = .p256(key)
            case .p384PublicKey:
                let key = try P384.Signing.PublicKey(x963Representation: spki.key.bytes)
                self.backing = .p384(key)
            case .p521PublicKey:
                let key = try P521.Signing.PublicKey(x963Representation: spki.key.bytes)
                self.backing = .p521(key)
            case .rsaKey:
                // To confirm that only the PKCS#1 format is allowed here, we actually attempt to decode the inner key
                // format. Sadly, Swift Crypto doesn't have a way to accept the raw numbers directly, so we then ask it
                // to decode as well.
                _ = try RSAPKCS1PublicKey(derEncoded: spki.key.bytes)
                let key = try _RSA.Signing.PublicKey(derRepresentation: spki.key.bytes)
                self.backing = .rsa(key)
            case .ed25519:
                let key = try Curve25519.Signing.PublicKey(rawRepresentation: spki.key.bytes)
                self.backing = .ed25519(key)
            default:
                throw CertificateError.unsupportedPublicKeyAlgorithm(reason: "\(spki.algorithmIdentifier)")
            }
        }

        @inlinable
        internal init(backing: BackingPublicKey) {
            self.backing = backing
        }

        /// Construct a public key wrapping a P256 public key.
        /// - Parameter p256: The P256 public key to wrap.
        @inlinable
        public init(_ p256: P256.Signing.PublicKey) {
            self.backing = .p256(p256)
        }

        /// Construct a public key wrapping a P384 public key.
        /// - Parameter p384: The P384 public key to wrap.
        @inlinable
        public init(_ p384: P384.Signing.PublicKey) {
            self.backing = .p384(p384)
        }

        /// Construct a public key wrapping a P521 public key.
        /// - Parameter p521: The P521 public key to wrap.
        @inlinable
        public init(_ p521: P521.Signing.PublicKey) {
            self.backing = .p521(p521)
        }

        /// Construct a public key wrapping a RSA public key.
        /// - Parameter rsa: The RSA public key to wrap.
        @inlinable
        public init(_ rsa: _RSA.Signing.PublicKey) {
            self.backing = .rsa(rsa)
        }

        /// Construct a public key wrapping an Ed25519 public key.
        /// - Parameter ed25519: The Ed25519 public key to wrap.
        @inlinable
        public init(_ ed25519: Curve25519.Signing.PublicKey) {
            self.backing = .ed25519(ed25519)
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.PublicKey {
    /// Confirms that `signature` is a valid signature for `certificate`, created by the
    /// private key associated with this public key.
    ///
    /// This function abstracts over the need to unwrap both the signature and public key to
    /// confirm they're of matching type before we validate the signature.
    ///
    /// - Parameters:
    ///   - signature: The signature to validate against `certificate`.
    ///   - certificate: The `certificate` to validate against `signature`.
    /// - Returns: Whether the signature was produced by signing `certificate` with the private key corresponding to this public key.
    @inlinable
    public func isValidSignature(_ signature: Certificate.Signature, for certificate: Certificate) -> Bool {
        return self.isValidSignature(
            signature,
            for: certificate.tbsCertificateBytes,
            signatureAlgorithm: certificate.signatureAlgorithm
        )
    }

    /// Confirms that `signature` is a valid signature for `csr`, created by the
    /// private key associated with this public key.
    ///
    /// This function abstracts over the need to unwrap both the signature and public key to
    /// confirm they're of matching type before we validate the signature.
    ///
    /// - Parameters:
    ///   - signature: The signature to validate against `csr`.
    ///   - csr: The ``CertificateSigningRequest`` to validate against `signature`.
    /// - Returns: Whether the signature was produced by signing `csr` with the private key corresponding to this public key.
    @inlinable
    public func isValidSignature(_ signature: Certificate.Signature, for csr: CertificateSigningRequest) -> Bool {
        return self.isValidSignature(signature, for: csr.infoBytes, signatureAlgorithm: csr.signatureAlgorithm)
    }

    @inlinable
    internal func isValidSignature<Bytes: DataProtocol>(
        _ signature: Certificate.Signature,
        for bytes: Bytes,
        signatureAlgorithm: Certificate.SignatureAlgorithm
    ) -> Bool {
        switch self.backing {
        case .p256(let p256):
            return p256.isValidSignature(signature, for: bytes, signatureAlgorithm: signatureAlgorithm)
        case .p384(let p384):
            return p384.isValidSignature(signature, for: bytes, signatureAlgorithm: signatureAlgorithm)
        case .p521(let p521):
            return p521.isValidSignature(signature, for: bytes, signatureAlgorithm: signatureAlgorithm)
        case .rsa(let rsa):
            return rsa.isValidSignature(signature, for: bytes, signatureAlgorithm: signatureAlgorithm)
        case .ed25519(let ed25519):
            return ed25519.isValidSignature(signature, for: bytes, signatureAlgorithm: signatureAlgorithm)
        }
    }

    /// Confirms that `signature` is a valid signature for `bytes`, created by the
    /// private key associated with this public key.
    ///
    /// This function accepts raw signature bytes (such as those from a TLS handshake)
    /// and validates them directly against the data.
    ///
    /// - Parameters:
    ///   - signature: The raw signature bytes to validate.
    ///   - bytes: The data that was signed.
    ///   - signatureAlgorithm: The algorithm used to create the signature.
    /// - Returns: Whether the signature was produced by signing `bytes` with the private key corresponding to this public key.
    @inlinable
    public func isValidSignature<SignatureBytes: DataProtocol, Bytes: DataProtocol>(
        _ signature: SignatureBytes,
        for bytes: Bytes,
        signatureAlgorithm: Certificate.SignatureAlgorithm
    ) -> Bool {
        switch self.backing {
        case .p256(let p256):
            return p256.isValidSignature(signature, for: bytes, signatureAlgorithm: signatureAlgorithm)
        case .p384(let p384):
            return p384.isValidSignature(signature, for: bytes, signatureAlgorithm: signatureAlgorithm)
        case .p521(let p521):
            return p521.isValidSignature(signature, for: bytes, signatureAlgorithm: signatureAlgorithm)
        case .rsa(let rsa):
            return rsa.isValidSignature(signature, for: bytes, signatureAlgorithm: signatureAlgorithm)
        case .ed25519(let ed25519):
            return ed25519.isValidSignature(signature, for: bytes, signatureAlgorithm: signatureAlgorithm)
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.PublicKey: Hashable {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.PublicKey: Sendable {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.PublicKey: CustomStringConvertible {
    public var description: String {
        switch self.backing {
        case .p256:
            return "P256.PublicKey"
        case .p384:
            return "P384.PublicKey"
        case .p521:
            return "P521.PublicKey"
        case .rsa(let publicKey):
            return "RSA\(publicKey.keySizeInBits).PublicKey"
        case .ed25519:
            return "Ed25519.PublicKey"
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.PublicKey {
    @usableFromInline
    enum BackingPublicKey: Hashable, Sendable {
        case p256(Crypto.P256.Signing.PublicKey)
        case p384(Crypto.P384.Signing.PublicKey)
        case p521(Crypto.P521.Signing.PublicKey)
        case rsa(_CryptoExtras._RSA.Signing.PublicKey)
        case ed25519(Curve25519.Signing.PublicKey)

        @inlinable
        static func == (lhs: BackingPublicKey, rhs: BackingPublicKey) -> Bool {
            switch (lhs, rhs) {
            case (.p256(let l), .p256(let r)):
                return l.rawRepresentation == r.rawRepresentation
            case (.p384(let l), .p384(let r)):
                return l.rawRepresentation == r.rawRepresentation
            case (.p521(let l), .p521(let r)):
                return l.rawRepresentation == r.rawRepresentation
            case (.rsa(let l), .rsa(let r)):
                return l.derRepresentation == r.derRepresentation
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
            case .ed25519(let digest):
                hasher.combine(4)
                hasher.combine(digest.rawRepresentation)
            }
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension SubjectPublicKeyInfo {
    @inlinable
    init(_ publicKey: Certificate.PublicKey) {
        let algorithmIdentifier: AlgorithmIdentifier
        let key: ASN1BitString

        switch publicKey.backing {
        case .p256(let p256):
            algorithmIdentifier = .p256PublicKey
            key = .init(bytes: ArraySlice(p256.x963Representation))
        case .p384(let p384):
            algorithmIdentifier = .p384PublicKey
            key = .init(bytes: ArraySlice(p384.x963Representation))
        case .p521(let p521):
            algorithmIdentifier = .p521PublicKey
            key = .init(bytes: ArraySlice(p521.x963Representation))
        case .rsa(let rsa):
            algorithmIdentifier = .rsaKey
            key = .init(bytes: ArraySlice(rsa.pkcs1DERRepresentation))
        case .ed25519(let ed25519):
            algorithmIdentifier = .ed25519
            key = .init(bytes: ArraySlice(ed25519.rawRepresentation))
        }

        self.algorithmIdentifier = algorithmIdentifier
        self.key = key
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.PublicKey {
    /// The byte array of the public key used in the certificate.
    ///
    /// The `subjectPublicKeyInfoBytes` property represents the public key in its canonical form that is determined by the key's algorithm and common representation.
    @inlinable
    public var subjectPublicKeyInfoBytes: ArraySlice<UInt8> {
        SubjectPublicKeyInfo(self).key.bytes
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension P256.Signing.PublicKey {
    /// Create a P256 Public Key from a given ``Certificate/PublicKey-swift.struct``.
    ///
    /// Fails if the key is not a P256 key.
    ///
    /// - parameters:
    ///     - key: The key to unwrap.
    public init?(_ key: Certificate.PublicKey) {
        guard case .p256(let inner) = key.backing else {
            return nil
        }
        self = inner
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension P384.Signing.PublicKey {
    /// Create a P384 Public Key from a given ``Certificate/PublicKey-swift.struct``.
    ///
    /// Fails if the key is not a P384 key.
    ///
    /// - parameters:
    ///     - key: The key to unwrap.
    public init?(_ key: Certificate.PublicKey) {
        guard case .p384(let inner) = key.backing else {
            return nil
        }
        self = inner
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension P521.Signing.PublicKey {
    /// Create a P521 Public Key from a given ``Certificate/PublicKey-swift.struct``.
    ///
    /// Fails if the key is not a P521 key.
    ///
    /// - parameters:
    ///     - key: The key to unwrap.
    public init?(_ key: Certificate.PublicKey) {
        guard case .p521(let inner) = key.backing else {
            return nil
        }
        self = inner
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension _RSA.Signing.PublicKey {
    /// Create an RSA Public Key from a given ``Certificate/PublicKey-swift.struct``.
    ///
    /// Fails if the key is not an RSA key.
    ///
    /// - parameters:
    ///     - key: The key to unwrap.
    public init?(_ key: Certificate.PublicKey) {
        guard case .rsa(let inner) = key.backing else {
            return nil
        }
        self = inner
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Curve25519.Signing.PublicKey {
    /// Create a Curve25519 Public Key from a given ``Certificate/PublicKey-swift.struct``.
    ///
    /// Fails if the key is not a Curve25519 key.
    ///
    /// - parameters:
    ///     - key: The key to unwrap.
    public init?(_ key: Certificate.PublicKey) {
        guard case .ed25519(let inner) = key.backing else {
            return nil
        }
        self = inner
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.PublicKey: PEMParseable, PEMSerializable {
    @inlinable
    public static var defaultPEMDiscriminator: String {
        return "PUBLIC KEY"
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.PublicKey: DERImplicitlyTaggable {
    @inlinable
    public static var defaultIdentifier: SwiftASN1.ASN1Identifier {
        SubjectPublicKeyInfo.defaultIdentifier
    }

    @inlinable
    public init(derEncoded: SwiftASN1.ASN1Node, withIdentifier identifier: SwiftASN1.ASN1Identifier) throws {
        try self.init(spki: try SubjectPublicKeyInfo(derEncoded: derEncoded, withIdentifier: identifier))
    }

    @inlinable
    public func serialize(
        into coder: inout SwiftASN1.DER.Serializer,
        withIdentifier identifier: SwiftASN1.ASN1Identifier
    ) throws {
        let spki = SubjectPublicKeyInfo(self)
        try spki.serialize(into: &coder, withIdentifier: identifier)
    }
}
