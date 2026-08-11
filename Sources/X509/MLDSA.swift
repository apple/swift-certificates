//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCertificates open source project
//
// Copyright (c) 2026 Apple Inc. and the SwiftCertificates project authors
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
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// The ML-DSA parameter sets this library can name.
///
/// This type deliberately stores no key material and names no swift-crypto ML-DSA type,
/// so it can be declared without an availability annotation: enum cases can't carry
/// `@available`, so keeping this payload free of macOS-26-only types is what lets
/// certificates *signed* with ML-DSA be parsed and re-serialized unconditionally.
@usableFromInline
enum MLDSAVariant: Hashable, Sendable {
    case mldsa65
    case mldsa87
}

/// The raw bytes of an ML-DSA public key, plus its parameter set.
///
/// Reconstructing a swift-crypto ML-DSA public key from its raw representation costs ~0.4%
/// of a verification (measured in the design doc), so the key is stored as validated bytes
/// and rebuilt on each use. The payload is plain data so the enum case that carries it can
/// be declared without an availability annotation (macOS-26-only types can't appear in an
/// unannotated enum payload); only the *initializers* need swift-crypto's ML-DSA API.
@usableFromInline
struct MLDSAPublicKeyBytes: Hashable, Sendable {
    @usableFromInline
    var variant: MLDSAVariant

    @usableFromInline
    var bytes: Data

    /// Validates and stores SPKI subjectPublicKey bytes for the given parameter set.
    ///
    /// Throws ``CertificateError/unsupportedPublicKeyAlgorithm(reason:)`` at runtime on
    /// Darwin platforms older than macOS 26 (where CryptoKit has no ML-DSA).
    @usableFromInline
    init(spkiBytes: ArraySlice<UInt8>, variant: MLDSAVariant) throws {
        guard #available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
        else {
            throw CertificateError.unsupportedPublicKeyAlgorithm(
                reason: "ML-DSA requires macOS 26, iOS 26, watchOS 26, tvOS 26, or visionOS 26"
            )
        }
        // Let swift-crypto validate the encoding; we store the validated raw bytes.
        switch variant {
        case .mldsa65:
            self.bytes = try MLDSA65.PublicKey(rawRepresentation: spkiBytes).rawRepresentation
        case .mldsa87:
            self.bytes = try MLDSA87.PublicKey(rawRepresentation: spkiBytes).rawRepresentation
        }
        self.variant = variant
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension MLDSAPublicKeyBytes {
    @usableFromInline
    func isValidSignature<Bytes: DataProtocol>(
        _ signature: Certificate.Signature,
        for bytes: Bytes,
        signatureAlgorithm: Certificate.SignatureAlgorithm
    ) -> Bool {
        guard case .mldsa(let signatureVariant, let rawSignature) = signature.backing,
            signatureVariant == self.variant
        else {
            // Signature mismatch, including an ML-DSA signature under the other parameter set.
            return false
        }
        return self.isValidSignature(rawSignature, for: bytes, signatureAlgorithm: signatureAlgorithm)
    }

    @usableFromInline
    func isValidSignature<SignatureBytes: DataProtocol, Bytes: DataProtocol>(
        _ signature: SignatureBytes,
        for bytes: Bytes,
        signatureAlgorithm: Certificate.SignatureAlgorithm
    ) -> Bool {
        switch (self.variant, signatureAlgorithm) {
        case (.mldsa65, .mldsa65), (.mldsa87, .mldsa87):
            break
        default:
            return false
        }
        guard #available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
        else {
            return false
        }
        switch self.variant {
        case .mldsa65:
            guard let key = try? MLDSA65.PublicKey(rawRepresentation: self.bytes) else {
                return false
            }
            return key.isValidSignature(signature, for: bytes)
        case .mldsa87:
            guard let key = try? MLDSA87.PublicKey(rawRepresentation: self.bytes) else {
                return false
            }
            return key.isValidSignature(signature, for: bytes)
        }
    }
}

@available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
extension MLDSAPublicKeyBytes {
    @usableFromInline
    init(_ mldsa65: MLDSA65.PublicKey) {
        self.variant = .mldsa65
        self.bytes = mldsa65.rawRepresentation
    }

    @usableFromInline
    init(_ mldsa87: MLDSA87.PublicKey) {
        self.variant = .mldsa87
        self.bytes = mldsa87.rawRepresentation
    }
}

@available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
extension Certificate.PublicKey {
    /// Construct a public key wrapping an ML-DSA-65 public key.
    /// - Parameter mldsa65: The ML-DSA-65 public key to wrap.
    @inlinable
    public init(_ mldsa65: MLDSA65.PublicKey) {
        self.init(backing: .mldsa(MLDSAPublicKeyBytes(mldsa65)))
    }

    /// Construct a public key wrapping an ML-DSA-87 public key.
    /// - Parameter mldsa87: The ML-DSA-87 public key to wrap.
    @inlinable
    public init(_ mldsa87: MLDSA87.PublicKey) {
        self.init(backing: .mldsa(MLDSAPublicKeyBytes(mldsa87)))
    }
}

@available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
extension MLDSA65.PublicKey {
    /// Create an ML-DSA-65 public key from a given ``Certificate/PublicKey-swift.struct``.
    ///
    /// Fails if the key is not an ML-DSA-65 key.
    ///
    /// - Parameters:
    ///     - key: The key to unwrap.
    public init?(_ key: Certificate.PublicKey) {
        guard case .mldsa(let backing) = key.backing, backing.variant == .mldsa65,
            let key = try? MLDSA65.PublicKey(rawRepresentation: backing.bytes)
        else {
            return nil
        }
        self = key
    }
}

@available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
extension MLDSA87.PublicKey {
    /// Create an ML-DSA-87 public key from a given ``Certificate/PublicKey-swift.struct``.
    ///
    /// Fails if the key is not an ML-DSA-87 key.
    ///
    /// - Parameters:
    ///     - key: The key to unwrap.
    public init?(_ key: Certificate.PublicKey) {
        guard case .mldsa(let backing) = key.backing, backing.variant == .mldsa87,
            let key = try? MLDSA87.PublicKey(rawRepresentation: backing.bytes)
        else {
            return nil
        }
        self = key
    }
}
