//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCertificates open source project
//
// Copyright (c) 2025 Apple Inc. and the SwiftCertificates project authors
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

/// Implement ``CustomPrivateKey`` if you need custom signing logic.
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public protocol CustomPrivateKey: Sendable, Hashable, PEMSerializable {

    /// Obtain the ``Certificate/PublicKey-swift.struct`` corresponding to
    /// this private key.
    var publicKey: Certificate.PublicKey { get }

    /// The default signature algorithm to use for signing.
    var defaultSignatureAlgorithm: Certificate.SignatureAlgorithm { get }

    /// Return a list of all supported signature types for this private key. The ordering is not a comment on the
    /// preference or security of the contained algorithms.
    var supportedSignatureAlgorithms: [Certificate.SignatureAlgorithm] { get }

    /// Use the private key to sign the provided bytes with a given signature algorithm.
    ///
    /// - Parameters:
    ///   - bytes: The data to create the signature for.
    ///   - signatureAlgorithm: The signature algorithm to use.
    /// - Returns: The signature.
    /// - Throws: If signing fails or synchronous signing is unsupported.
    func signSynchronously(
        bytes: some DataProtocol,
        signatureAlgorithm: Certificate.SignatureAlgorithm
    ) throws -> Certificate.Signature

    /// Use the private key to sign the provided bytes asynchronously with a given signature algorithm.
    ///
    /// The default implementation calls ``signSynchronously(bytes:signatureAlgorithm:)`` and returns the result.
    /// Conforming types may override this method to provide a specialized asynchronous implementation.
    ///
    /// - Parameters:
    ///   - bytes: The data to create the signature for.
    ///   - signatureAlgorithm: The signature algorithm to use.
    /// - Returns: The signature.
    /// - Throws: If signing fails or asynchronous signing is unsupported.
    func signAsynchronously(
        bytes: some DataProtocol & Sendable,
        signatureAlgorithm: Certificate.SignatureAlgorithm
    ) async throws -> Certificate.Signature

}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension CustomPrivateKey {

    @inlinable
    public func signAsynchronously(
        bytes: some DataProtocol & Sendable,
        signatureAlgorithm: Certificate.SignatureAlgorithm
    ) async throws -> Certificate.Signature {
        try self.signSynchronously(bytes: bytes, signatureAlgorithm: signatureAlgorithm)
    }

}
