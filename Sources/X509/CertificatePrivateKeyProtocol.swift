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
#endif

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate {

    public protocol PrivateKeyProtocol: Sendable, Hashable {

        /// Obtain the ``Certificate/PublicKey-swift.struct`` corresponding to
        /// this private key.
        var publicKey: PublicKey { get }

        /// Use the private key to sign the provided bytes with a given signature algorithm.
        ///
        /// - Parameters:
        ///   - bytes: The data to create the signature for.
        ///   - signatureAlgorithm: The signature algorithm to use.
        /// - Returns: The signature.
        @inlinable
        func sign(
            bytes: some DataProtocol,
            signatureAlgorithm: SignatureAlgorithm
        ) throws -> Signature

    }

}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate {

    public protocol AsyncPrivateKeyProtocol: Sendable, Hashable {

        /// Obtain the ``Certificate/PublicKey-swift.struct`` corresponding to
        /// this private key.
        var publicKey: PublicKey { get }

        /// Use the private key to sign the provided bytes with a given signature algorithm.
        ///
        /// - Parameters:
        ///   - bytes: The data to create the signature for.
        ///   - signatureAlgorithm: The signature algorithm to use.
        /// - Returns: The signature.
        @inlinable
        func sign(
            bytes: some DataProtocol,
            signatureAlgorithm: SignatureAlgorithm
        ) async throws -> Signature

    }

}
