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

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
import SwiftASN1
#endif

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public protocol CustomPrivateKey: Sendable, Hashable, PEMSerializable {

    /// Obtain the ``Certificate/PublicKey-swift.struct`` corresponding to
    /// this private key.
    var publicKey: Certificate.PublicKey { get }

    var defaultSignatureAlgorithm: Certificate.SignatureAlgorithm { get }

    /// Use the private key to sign the provided bytes with a given signature algorithm.
    ///
    /// - Parameters:
    ///   - bytes: The data to create the signature for.
    ///   - signatureAlgorithm: The signature algorithm to use.
    /// - Returns: The signature.
    @inlinable
    func signSynchronously(
        bytes: some DataProtocol,
        signatureAlgorithm: Certificate.SignatureAlgorithm
    ) throws -> Certificate.Signature

    /// Use the private key to sign the provided bytes asynchronously with a given signature algorithm.
    ///
    /// - Parameters:
    ///   - bytes: The data to create the signature for.
    ///   - signatureAlgorithm: The signature algorithm to use.
    /// - Returns: The signature.
    @inlinable
    func signAsynchronously(
        bytes: some DataProtocol,
        signatureAlgorithm: Certificate.SignatureAlgorithm
    ) async throws -> Certificate.Signature

}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension CustomPrivateKey {

    func signAsynchronously(
        bytes: some DataProtocol,
        signatureAlgorithm: Certificate.SignatureAlgorithm
    ) async throws -> Certificate.Signature {
        try signSynchronously(bytes: bytes, signatureAlgorithm: signatureAlgorithm)
    }

}
