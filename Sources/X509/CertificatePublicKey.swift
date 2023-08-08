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
            case .rsaKey:
                // To confirm that only the PKCS#1 format is allowed here, we actually attempt to decode the inner key
                // format. Sadly, Swift Crypto doesn't have a way to accept the raw numbers directly, so we then ask it
                // to decode as well.
                _ = try RSAPKCS1PublicKey(derEncoded: spki.key.bytes)
                let key = try _RSA.Signing.PublicKey(derRepresentation: spki.key.bytes)
                self.backing = .rsa(key)
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
        return self.isValidSignature(signature, for: certificate.tbsCertificateBytes, signatureAlgorithm: certificate.signatureAlgorithm)
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
    internal func isValidSignature<Bytes: DataProtocol>(_ signature: Certificate.Signature, for bytes: Bytes, signatureAlgorithm: Certificate.SignatureAlgorithm) -> Bool {
        let digest: Digest
        do {
            let digestAlgorithm = try AlgorithmIdentifier(digestAlgorithmFor: signatureAlgorithm)
            digest = try Digest.computeDigest(for: bytes, using: digestAlgorithm)
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
            // For now we don't support RSA PSS, as it's not deployed in the WebPKI.
            // We could, if there are sufficient user needs.
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
        switch self.backing {
        case .p256:
            return "P256"
        case .p384:
            return "P384"
        case .p521:
            return "P521"
        case .rsa(let publicKey):
            return "RSA\(publicKey.keySizeInBits)"
        }
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
            algorithmIdentifier = .rsaKey
            key = .init(bytes: ArraySlice(rsa.pkcs1DERRepresentation))
        }

        self.algorithmIdentifier = algorithmIdentifier
        self.key = key
    }
}

extension Certificate.PublicKey {
    /// The byte array of the public key used in the certificate.
    ///
    /// The `subjectPublicKeyInfoBytes` property represents the public key in its canonical form that is determined by the key's algorithm and common representation.
    @inlinable
    public var subjectPublicKeyInfoBytes: ArraySlice<UInt8> {
         SubjectPublicKeyInfo(self).key.bytes
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

extension P256.Signing.PublicKey {
    /// Create a P256 Public Key from a given ``Certificate/PublicKey-swift.struct``.
    ///
    /// Fails if the key is not a P256 key.
    ///
    /// - parameters:
    ///     - key: The key to unwrap.
    public init?(_ key: Certificate.PublicKey) {
        if case .p256(let inner) = key.backing {
            self = inner
        } else {
            return nil
        }
    }
}

extension P384.Signing.PublicKey {
    /// Create a P384 Public Key from a given ``Certificate/PublicKey-swift.struct``.
    ///
    /// Fails if the key is not a P384 key.
    ///
    /// - parameters:
    ///     - key: The key to unwrap.
    public init?(_ key: Certificate.PublicKey) {
        if case .p384(let inner) = key.backing {
            self = inner
        } else {
            return nil
        }
    }
}

extension P521.Signing.PublicKey {
    /// Create a P521 Public Key from a given ``Certificate/PublicKey-swift.struct``.
    ///
    /// Fails if the key is not a P521 key.
    ///
    /// - parameters:
    ///     - key: The key to unwrap.
    public init?(_ key: Certificate.PublicKey) {
        if case .p521(let inner) = key.backing {
            self = inner
        } else {
            return nil
        }
    }
}

extension _RSA.Signing.PublicKey {
    /// Create an RSA Public Key from a given ``Certificate/PublicKey-swift.struct``.
    ///
    /// Fails if the key is not an RSA key.
    ///
    /// - parameters:
    ///     - key: The key to unwrap.
    public init?(_ key: Certificate.PublicKey) {
        if case .rsa(let inner) = key.backing {
            self = inner
        } else {
            return nil
        }
    }
}

extension Certificate.PublicKey {
    @inlinable
    static var pemDiscriminatorForPublicKey: String { "PUBLIC KEY" }
    
    @inlinable
    public init(pemEncoded: String) throws {
        try self.init(pemDocument: PEMDocument(pemString: pemEncoded))
    }
    
    @inlinable
    public init(pemDocument: PEMDocument) throws {
        guard pemDocument.discriminator == Self.pemDiscriminatorForPublicKey else {
            throw ASN1Error.invalidPEMDocument(reason: "PEMDocument has incorrect discriminator \(pemDocument.discriminator). Expected \(Self.pemDiscriminatorForPublicKey) instead")
        }
        
        try self.init(spki: try SubjectPublicKeyInfo(derEncoded: pemDocument.derBytes))
    }
    
    func serializeAsPEM() throws -> PEMDocument {
        let spki = SubjectPublicKeyInfo(self)
        let derBytes = try DER.Serializer.serialized(element: spki)
        return PEMDocument(type: "PUBLIC KEY", derBytes: derBytes)
    }
}
