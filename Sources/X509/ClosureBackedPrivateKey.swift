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

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import SwiftASN1

/// A ``CustomPrivateKey`` that signs by calling a closure.
///
/// Use this when the signing backend has no type of its own to conform, such as a call into a
/// key service or a token library. The key material is not extractable, so PEM serialization
/// throws. Closures cannot be compared, so two keys are equal when they have the same public key
/// and signature algorithms.
///
/// A key built with the synchronous initializer runs its closure inline, even when signing
/// through ``signAsynchronously(bytes:signatureAlgorithm:)``. Use the asynchronous initializer
/// if the closure blocks.
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public struct ClosureBackedPrivateKey: CustomPrivateKey {

    public let publicKey: Certificate.PublicKey

    public let defaultSignatureAlgorithm: Certificate.SignatureAlgorithm

    public let supportedSignatureAlgorithms: [Certificate.SignatureAlgorithm]

    @usableFromInline
    let signer: Signer

    @usableFromInline
    enum Signer: Sendable {
        case synchronous(@Sendable (Data, Certificate.SignatureAlgorithm) throws -> Certificate.Signature)
        case asynchronous(@Sendable (Data, Certificate.SignatureAlgorithm) async throws -> Certificate.Signature)
    }

    /// Construct a private key that signs synchronously.
    ///
    /// - Parameters:
    ///   - publicKey: The public key corresponding to this private key.
    ///   - defaultSignatureAlgorithm: The default signature algorithm, which is always supported.
    ///   - additionalSupportedSignatureAlgorithms: Any further algorithms the closure can produce.
    ///   - sign: Signs the bytes. It is only called with a supported algorithm, and its result is
    ///       checked to be a signature of the matching kind.
    /// - Throws: If a signature algorithm does not suit `publicKey`.
    @inlinable
    public init(
        publicKey: Certificate.PublicKey,
        defaultSignatureAlgorithm: Certificate.SignatureAlgorithm,
        additionalSupportedSignatureAlgorithms: [Certificate.SignatureAlgorithm] = [],
        sign: @escaping @Sendable (Data, Certificate.SignatureAlgorithm) throws -> Certificate.Signature
    ) throws {
        try self.init(
            publicKey: publicKey,
            defaultSignatureAlgorithm: defaultSignatureAlgorithm,
            additionalSupportedSignatureAlgorithms: additionalSupportedSignatureAlgorithms,
            signer: .synchronous(sign)
        )
    }

    /// Construct a private key that signs asynchronously.
    ///
    /// ``signSynchronously(bytes:signatureAlgorithm:)`` throws on keys built this way.
    ///
    /// - Parameters:
    ///   - publicKey: The public key corresponding to this private key.
    ///   - defaultSignatureAlgorithm: The default signature algorithm, which is always supported.
    ///   - additionalSupportedSignatureAlgorithms: Any further algorithms the closure can produce.
    ///   - signAsynchronously: Signs the bytes. It is only called with a supported algorithm, and
    ///       its result is checked to be a signature of the matching kind.
    /// - Throws: If a signature algorithm does not suit `publicKey`.
    @inlinable
    public init(
        publicKey: Certificate.PublicKey,
        defaultSignatureAlgorithm: Certificate.SignatureAlgorithm,
        additionalSupportedSignatureAlgorithms: [Certificate.SignatureAlgorithm] = [],
        signAsynchronously sign:
            @escaping @Sendable (Data, Certificate.SignatureAlgorithm) async throws ->
            Certificate.Signature
    ) throws {
        try self.init(
            publicKey: publicKey,
            defaultSignatureAlgorithm: defaultSignatureAlgorithm,
            additionalSupportedSignatureAlgorithms: additionalSupportedSignatureAlgorithms,
            signer: .asynchronous(sign)
        )
    }

    @inlinable
    init(
        publicKey: Certificate.PublicKey,
        defaultSignatureAlgorithm: Certificate.SignatureAlgorithm,
        additionalSupportedSignatureAlgorithms: [Certificate.SignatureAlgorithm],
        signer: Signer
    ) throws {
        // The default leads, and each algorithm appears once, so two keys that advertise the
        // same set compare equal however the caller happened to list it.
        var supported = [defaultSignatureAlgorithm]
        for algorithm in additionalSupportedSignatureAlgorithms where !supported.contains(algorithm) {
            supported.append(algorithm)
        }

        for algorithm in supported where !Self.algorithm(algorithm, suits: publicKey) {
            throw CertificateError.unsupportedSignatureAlgorithm(
                reason: "\(algorithm) cannot be used with public key \(publicKey)"
            )
        }

        self.publicKey = publicKey
        self.defaultSignatureAlgorithm = defaultSignatureAlgorithm
        self.supportedSignatureAlgorithms = supported
        self.signer = signer
    }

    @inlinable
    public func signSynchronously(
        bytes: some DataProtocol,
        signatureAlgorithm: Certificate.SignatureAlgorithm
    ) throws -> Certificate.Signature {
        try self.validate(signatureAlgorithm)

        switch self.signer {
        case .synchronous(let sign):
            return try Self.validate(sign(Data(bytes), signatureAlgorithm), for: signatureAlgorithm)
        case .asynchronous:
            throw CertificateError.unsupportedPrivateKey(
                reason: "this closure-backed private key can only sign asynchronously"
            )
        }
    }

    @inlinable
    public func signAsynchronously(
        bytes: some DataProtocol & Sendable,
        signatureAlgorithm: Certificate.SignatureAlgorithm
    ) async throws -> Certificate.Signature {
        try self.validate(signatureAlgorithm)

        let signature: Certificate.Signature
        switch self.signer {
        case .synchronous(let sign):
            signature = try sign(Data(bytes), signatureAlgorithm)
        case .asynchronous(let sign):
            signature = try await sign(Data(bytes), signatureAlgorithm)
        }
        return try Self.validate(signature, for: signatureAlgorithm)
    }

    @inlinable
    func validate(_ signatureAlgorithm: Certificate.SignatureAlgorithm) throws {
        guard self.supportedSignatureAlgorithms.contains(signatureAlgorithm) else {
            throw CertificateError.unsupportedSignatureAlgorithm(
                reason: "\(signatureAlgorithm) is not supported by this key, "
                    + "which supports \(self.supportedSignatureAlgorithms)"
            )
        }
    }

    @inlinable
    static func validate(
        _ signature: Certificate.Signature,
        for signatureAlgorithm: Certificate.SignatureAlgorithm
    ) throws -> Certificate.Signature {
        let matches: Bool
        switch signature.backing {
        case .ecdsa:
            matches = signatureAlgorithm.isECDSA
        case .rsa:
            matches = signatureAlgorithm.isRSA
        case .ed25519:
            matches = signatureAlgorithm == .ed25519
        }

        guard matches else {
            throw CertificateError.invalidSignatureForCertificate(
                reason: "signing closure returned a \(signature) signature for \(signatureAlgorithm)"
            )
        }
        return signature
    }

    @inlinable
    static func algorithm(
        _ signatureAlgorithm: Certificate.SignatureAlgorithm,
        suits publicKey: Certificate.PublicKey
    ) -> Bool {
        switch publicKey.backing {
        case .p256, .p384, .p521:
            return signatureAlgorithm.isECDSA
        case .rsa:
            return signatureAlgorithm.isRSA
        case .ed25519:
            return signatureAlgorithm == .ed25519
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension ClosureBackedPrivateKey {

    @inlinable
    public static func == (lhs: ClosureBackedPrivateKey, rhs: ClosureBackedPrivateKey) -> Bool {
        lhs.publicKey == rhs.publicKey
            && lhs.defaultSignatureAlgorithm == rhs.defaultSignatureAlgorithm
            && lhs.supportedSignatureAlgorithms == rhs.supportedSignatureAlgorithms
    }

    @inlinable
    public func hash(into hasher: inout Hasher) {
        hasher.combine(self.publicKey)
        hasher.combine(self.defaultSignatureAlgorithm)
        hasher.combine(self.supportedSignatureAlgorithms)
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension ClosureBackedPrivateKey {

    public static let defaultPEMDiscriminator: String = "PRIVATE KEY"

    @inlinable
    public func serialize(into coder: inout DER.Serializer) throws {
        throw CertificateError.unsupportedPrivateKey(
            reason: "closure-backed private keys hold no serializable key material"
        )
    }

    @inlinable
    public func serializeAsPEM(discriminator: String) throws -> PEMDocument {
        throw CertificateError.unsupportedPrivateKey(
            reason: "closure-backed private keys hold no serializable key material"
        )
    }
}
