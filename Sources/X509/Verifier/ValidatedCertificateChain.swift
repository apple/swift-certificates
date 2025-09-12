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

/// A validated certificate chain that traces the trust from a leaf to a root certificate. This type does not perform any validation
/// itself. It is a container that gives information about the contained certificates. The safe method to acquire it goes through
/// the certificate validation processes in a `Verifier`.
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public struct ValidatedCertificateChain: Sendable, Collection, RandomAccessCollection, Hashable {
    @usableFromInline
    let validatedChain: [Certificate]

    public typealias Index = Int
    public typealias Element = Certificate

    @inlinable
    public var startIndex: Index { self.validatedChain.startIndex }

    @inlinable
    public var endIndex: Index { self.validatedChain.endIndex }

    @inlinable
    public subscript(index: Index) -> Element {
        self.validatedChain[index]
    }

    /// Creates a `ValidatedCertificateChain` that represents a chain of trust. The chain should be ordered
    /// from leaf to root and (with the exception of the root) each certificate should be issued by the owner of the subsequent
    /// certificate. Since the leaf and root certificate can be identical, a certificate chain must have at least one element.
    ///
    /// It is recommended to go through the verification process using `X509/Verifier/Verifier` with a
    /// `X509/Verifier/RFC5280/RFC5280Policy` to safely initialize a `ValidatedCertificateChain`.
    ///
    /// - Parameter uncheckedCertificateChain: An already validated certificate chain ordered from leaf to root certificate.
    ///
    /// - Warning: Only initialize this type with a *validated* certificate chain containing at least one
    ///     certificate. This type does not perform checks to verify the input.
    ///
    /// - Precondition: The `uncheckedCertificateChain` must contain at least one element.
    @inlinable
    public init(uncheckedCertificateChain: [Certificate]) {
        precondition(
            uncheckedCertificateChain.count > 0,
            "A valid certificate chain contains at least one certificate."
        )
        self.validatedChain = uncheckedCertificateChain
    }

    /// Creates a `ValidatedCertificateChain` that represents a verified chain of trust from leaf to root.
    /// - Parameter validatedChain: The validated certificate chain.
    /// - Precondition: The `validatedChain` must contain at least one certificate.
    @inlinable
    init(_ validatedChain: [Certificate]) {
        precondition(validatedChain.count > 0, "A valid certificate chain contains at least one certificate.")
        self.validatedChain = validatedChain
    }

    /// Returns the leaf certificate. If the chain contains a single certificate, the leaf and root are equal.
    @inlinable
    public var leaf: Certificate {
        // Safe due to the precondition in the initializer.
        self.validatedChain.first!
    }

    /// Returns the root certificate. If the chain contains a single certificate, the leaf and root are equal.
    @inlinable
    public var root: Certificate {
        // Safe due to the precondition in the initializer.
        self.validatedChain.last!
    }
}
