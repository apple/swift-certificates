//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCertificates open source project
//
// Copyright (c) 2022 Apple Inc. and the SwiftCertificates project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.md for the list of SwiftCertificates project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

@preconcurrency import Crypto
@preconcurrency import _CryptoExtras

extension Certificate {
    /// A private key that can be used with a certificate.
    ///
    /// This type provides an opaque wrapper around the various private key types
    /// provided by `swift-crypto`. Users are expected to construct this key from
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

        @inlinable
        internal func sign(tbsCertificateBytes: ArraySlice<UInt8>) throws -> Signature {
            switch self.backing {
            case .p256(let p256):
                let sig = try p256.signature(for: tbsCertificateBytes)
                return Signature(backing: .p256(sig))
            case .p384(let p384):
                let sig = try p384.signature(for: tbsCertificateBytes)
                return Signature(backing: .p384(sig))
            case .p521(let p521):
                let sig = try p521.signature(for: tbsCertificateBytes)
                return Signature(backing: .p521(sig))
            case .rsa:
                fatalError("TODO: not implemented")
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
            }
        }
    }
}

extension Certificate.PrivateKey: Hashable { }

extension Certificate.PrivateKey: Sendable { }

extension Certificate.PrivateKey: CustomStringConvertible {
    public var description: String {
        return "TODO"
    }
}

extension Certificate.PrivateKey {
    @usableFromInline
    enum BackingPrivateKey: Hashable, Sendable {
        case p256(Crypto.P256.Signing.PrivateKey)
        case p384(Crypto.P384.Signing.PrivateKey)
        case p521(Crypto.P521.Signing.PrivateKey)
        case rsa(_CryptoExtras._RSA.Signing.PrivateKey)

        @inlinable
        static func ==(lhs: BackingPrivateKey, rhs: BackingPrivateKey) -> Bool {
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
