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
            case .rsaPublicKey:
                // TODO: Confirm that the derRepresentation here only tolerates the representation
                // we want to allow.
                let key = try _RSA.Signing.PublicKey(derRepresentation: spki.key.bytes)
                self.backing = .rsa(key)
            default:
                // TODO(cory): RSA keys
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
    }
}

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
        self.isValidSignature(signature, for: certificate.tbsCertificateBytes, using: certificate.signatureAlgorithm)
    }
    
    @inlinable
    internal func isValidSignature(
        _ signature: Certificate.Signature,
        for tbsBytes: ArraySlice<UInt8>,
        using signatureAlgorithm: Certificate.SignatureAlgorithm
    ) -> Bool {
        let digest: Digest
        do {
            let digestAlgorithm = try AlgorithmIdentifier(digestAlgorithmFor: signatureAlgorithm)
            digest = try Digest.computeDigest(for: tbsBytes, using: digestAlgorithm)
        } catch {
            return false
        }
        
        switch self.backing {
        case .p256(let p256):
            return p256.isValidSignature(signature, for: digest)
        case .p384(let p384):
            return p384.isValidSignature(signature, for: digest)
        case .p521(let p521):
            return p521.isValidSignature(signature, for: digest)
        case .rsa(let rsa):
            // TODO: Extend for PSS?
            do {
                let padding = try _RSA.Signing.Padding(forSignatureAlgorithm: signatureAlgorithm)
                return rsa.isValidSignature(signature, for: digest, padding: padding)
            } catch {
                return false
            }
        }
    }
}

extension Certificate.PublicKey: Hashable { }

extension Certificate.PublicKey: Sendable { }

extension Certificate.PublicKey: CustomStringConvertible {
    public var description: String {
        return "TODO"
    }
}

extension Certificate.PublicKey {
    @usableFromInline
    enum BackingPublicKey: Hashable, Sendable {
        case p256(Crypto.P256.Signing.PublicKey)
        case p384(Crypto.P384.Signing.PublicKey)
        case p521(Crypto.P521.Signing.PublicKey)
        case rsa(_CryptoExtras._RSA.Signing.PublicKey)

        @inlinable
        static func ==(lhs: BackingPublicKey, rhs: BackingPublicKey) -> Bool {
            switch (lhs, rhs) {
            case (.p256(let l), .p256(let r)):
                return l.rawRepresentation == r.rawRepresentation
            case (.p384(let l), .p384(let r)):
                return l.rawRepresentation == r.rawRepresentation
            case (.p521(let l), .p521(let r)):
                return l.rawRepresentation == r.rawRepresentation
            case (.rsa(let l), .rsa(let r)):
                return l.derRepresentation == r.derRepresentation
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
            }
        }
    }
}

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
            algorithmIdentifier = .rsaPublicKey
            key = .init(bytes: ArraySlice(rsa.derRepresentation))
        }

        self.algorithmIdentifier = algorithmIdentifier
        self.key = key
    }
}

extension _RSA.Signing.Padding {
    @inlinable
    init(forSignatureAlgorithm signatureAlgorithm: Certificate.SignatureAlgorithm) throws {
        switch signatureAlgorithm {
        case .sha1WithRSAEncryption, .sha256WithRSAEncryption, .sha384WithRSAEncryption, .sha512WithRSAEncryption:
            self = .insecurePKCS1v1_5
        default:
            // Either this is RSA PSS, or we hit a bug. Either way, unsupported.
            throw CertificateError.unsupportedSignatureAlgorithm(reason: "Unable to determine RSA padding mode for \(signatureAlgorithm)")
        }
    }
}
