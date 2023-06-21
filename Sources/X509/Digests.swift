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
import Crypto
import _CryptoExtras

@usableFromInline
enum Digest {
    case insecureSHA1(Insecure.SHA1Digest)
    case sha256(SHA256Digest)
    case sha384(SHA384Digest)
    case sha512(SHA512Digest)

    @inlinable
    static func computeDigest<Bytes: DataProtocol>(for bytes: Bytes, using digestIdentifier: AlgorithmIdentifier) throws -> Digest {
        switch digestIdentifier {
        case .sha1, .sha1UsingNil:
            return .insecureSHA1(Insecure.SHA1.hash(data: bytes))
        case .sha256, .sha256UsingNil:
            return .sha256(SHA256.hash(data: bytes))
        case .sha384, .sha384UsingNil:
            return .sha384(SHA384.hash(data: bytes))
        case .sha512, .sha512UsingNil:
            return .sha512(SHA512.hash(data: bytes))
        default:
            throw CertificateError.unsupportedDigestAlgorithm(reason: "Unknown digest algorithm: \(digestIdentifier)")
        }
    }
}

// MARK: Public key operations

extension P256.Signing.PublicKey {
    @inlinable
    func isValidSignature(_ signature: Certificate.Signature, for digest: Digest) -> Bool {
        guard case .ecdsa(let rawInnerSignature) = signature.backing,
              let innerSignature = P256.Signing.ECDSASignature(rawInnerSignature)
        else {
            // Signature mismatch
            return false
        }

        switch digest {
        case .insecureSHA1(let sha1):
            return self.isValidSignature(innerSignature, for: sha1)
        case .sha256(let sha256):
            return self.isValidSignature(innerSignature, for: sha256)
        case .sha384(let sha384):
            return self.isValidSignature(innerSignature, for: sha384)
        case .sha512(let sha512):
            return self.isValidSignature(innerSignature, for: sha512)
        }
    }
}

extension P384.Signing.PublicKey {
    @inlinable
    func isValidSignature(_ signature: Certificate.Signature, for digest: Digest) -> Bool {
        guard case .ecdsa(let rawInnerSignature) = signature.backing,
              let innerSignature = P384.Signing.ECDSASignature(rawInnerSignature)
        else {
            // Signature mismatch
            return false
        }

        switch digest {
        case .insecureSHA1(let sha1):
            return self.isValidSignature(innerSignature, for: sha1)
        case .sha256(let sha256):
            return self.isValidSignature(innerSignature, for: sha256)
        case .sha384(let sha384):
            return self.isValidSignature(innerSignature, for: sha384)
        case .sha512(let sha512):
            return self.isValidSignature(innerSignature, for: sha512)
        }
    }
}

extension P521.Signing.PublicKey {
    @inlinable
    func isValidSignature(_ signature: Certificate.Signature, for digest: Digest) -> Bool {
        guard case .ecdsa(let rawInnerSignature) = signature.backing,
              let innerSignature = P521.Signing.ECDSASignature(rawInnerSignature)
        else {
            // Signature mismatch
            return false
        }

        switch digest {
        case .insecureSHA1(let sha1):
            return self.isValidSignature(innerSignature, for: sha1)
        case .sha256(let sha256):
            return self.isValidSignature(innerSignature, for: sha256)
        case .sha384(let sha384):
            return self.isValidSignature(innerSignature, for: sha384)
        case .sha512(let sha512):
            return self.isValidSignature(innerSignature, for: sha512)
        }
    }
}

extension _RSA.Signing.PublicKey {
    @inlinable
    func isValidSignature(_ signature: Certificate.Signature, for digest: Digest, padding: _RSA.Signing.Padding) -> Bool {
        guard case .rsa(let innerSignature) = signature.backing else {
            // Signature mismatch
            return false
        }

        switch digest {
        case .insecureSHA1(let sha1):
            return self.isValidSignature(innerSignature, for: sha1, padding: padding)
        case .sha256(let sha256):
            return self.isValidSignature(innerSignature, for: sha256, padding: padding)
        case .sha384(let sha384):
            return self.isValidSignature(innerSignature, for: sha384, padding: padding)
        case .sha512(let sha512):
            return self.isValidSignature(innerSignature, for: sha512, padding: padding)
        }
    }
}

// MARK: Private key operations

extension P256.Signing.PrivateKey {
    @inlinable
    func signature<Bytes: DataProtocol>(for bytes: Bytes, digestAlgorithm: AlgorithmIdentifier) throws -> Certificate.Signature {
        let signature: P256.Signing.ECDSASignature

        switch try Digest.computeDigest(for: bytes, using: digestAlgorithm) {
        case .insecureSHA1(let sha1):
            signature = try self.signature(for: sha1)
        case .sha256(let sha256):
            signature = try self.signature(for: sha256)
        case .sha384(let sha384):
            signature = try self.signature(for: sha384)
        case .sha512(let sha512):
            signature = try self.signature(for: sha512)
        }

        return Certificate.Signature(backing: .ecdsa(.init(signature)))
    }
}

#if canImport(Darwin)
extension SecureEnclave.P256.Signing.PrivateKey {
    @inlinable
    func signature<Bytes: DataProtocol>(for bytes: Bytes, digestAlgorithm: AlgorithmIdentifier) throws -> Certificate.Signature {
        let signature: P256.Signing.ECDSASignature

        switch try Digest.computeDigest(for: bytes, using: digestAlgorithm) {
        case .insecureSHA1(let sha1):
            signature = try self.signature(for: sha1)
        case .sha256(let sha256):
            signature = try self.signature(for: sha256)
        case .sha384(let sha384):
            signature = try self.signature(for: sha384)
        case .sha512(let sha512):
            signature = try self.signature(for: sha512)
        }

        return Certificate.Signature(backing: .ecdsa(.init(signature)))
    }
}
#endif

extension P384.Signing.PrivateKey {
    @inlinable
    func signature<Bytes: DataProtocol>(for bytes: Bytes, digestAlgorithm: AlgorithmIdentifier) throws -> Certificate.Signature {
        let signature: P384.Signing.ECDSASignature

        switch try Digest.computeDigest(for: bytes, using: digestAlgorithm) {
        case .insecureSHA1(let sha1):
            signature = try self.signature(for: sha1)
        case .sha256(let sha256):
            signature = try self.signature(for: sha256)
        case .sha384(let sha384):
            signature = try self.signature(for: sha384)
        case .sha512(let sha512):
            signature = try self.signature(for: sha512)
        }

        return Certificate.Signature(backing: .ecdsa(.init(signature)))
    }
}

extension P521.Signing.PrivateKey {
    @inlinable
    func signature<Bytes: DataProtocol>(for bytes: Bytes, digestAlgorithm: AlgorithmIdentifier) throws -> Certificate.Signature {
        let signature: P521.Signing.ECDSASignature

        switch try Digest.computeDigest(for: bytes, using: digestAlgorithm) {
        case .insecureSHA1(let sha1):
            signature = try self.signature(for: sha1)
        case .sha256(let sha256):
            signature = try self.signature(for: sha256)
        case .sha384(let sha384):
            signature = try self.signature(for: sha384)
        case .sha512(let sha512):
            signature = try self.signature(for: sha512)
        }

        return Certificate.Signature(backing: .ecdsa(.init(signature)))
    }
}

extension _RSA.Signing.PrivateKey {
    @inlinable
    func signature<Bytes: DataProtocol>(for bytes: Bytes, digestAlgorithm: AlgorithmIdentifier, padding: _RSA.Signing.Padding) throws -> Certificate.Signature {
        let signature: _RSA.Signing.RSASignature

        switch try Digest.computeDigest(for: bytes, using: digestAlgorithm) {
        case .insecureSHA1(let sha1):
            signature = try self.signature(for: sha1, padding: padding)
        case .sha256(let sha256):
            signature = try self.signature(for: sha256, padding: padding)
        case .sha384(let sha384):
            signature = try self.signature(for: sha384, padding: padding)
        case .sha512(let sha512):
            signature = try self.signature(for: sha512, padding: padding)
        }

        return Certificate.Signature(backing: .rsa(signature))
    }
}
