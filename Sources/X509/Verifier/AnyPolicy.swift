//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCertificates open source project
//
// Copyright (c) 2022-2023 Apple Inc. and the SwiftCertificates project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCertificates project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
import SwiftASN1

/// ``AnyPolicy`` can be used to erase the concrete type of some ``VerifierPolicy``.
///  Only use ``AnyPolicy`` if type erasure is necessary.
///  Instead try to use conditional inclusion of different policies using ``PolicyBuilder``.
///
/// Use ``AnyPolicy`` at the top level during construction of a ``Verifier`` to get a ``Verifier`` of type `Verifier<AnyPolicy>` e.g.:
/// ```swift
/// let verifier = Verifier(rootCertificates: CertificateStore()) {
///     AnyPolicy {
///         RFC5280Policy()
///     }
/// }
/// ```
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public struct AnyPolicy: VerifierPolicy {
    @usableFromInline
    var policy: any VerifierPolicy

    @inlinable
    /// Erases the type of some ``VerifierPolicy`` to ``AnyPolicy``.
    /// - Parameter policy: the concrete ``VerifierPolicy``
    public init(_ policy: some VerifierPolicy) {
        self.policy = policy
    }

    /// Erases the type of some ``VerifierPolicy`` to ``AnyPolicy``.
    /// - Parameter makePolicy: the ``VerifierPolicy`` constructed using the ``PolicyBuilder`` DSL.
    @inlinable
    public init(@PolicyBuilder makePolicy: () throws -> some VerifierPolicy) rethrows {
        self.init(try makePolicy())
    }

    @inlinable
    public var verifyingCriticalExtensions: [SwiftASN1.ASN1ObjectIdentifier] {
        policy.verifyingCriticalExtensions
    }

    @inlinable
    public mutating func chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain) async -> PolicyEvaluationResult
    {
        await policy.chainMeetsPolicyRequirements(chain: chain)
    }
}

@available(*, unavailable)
extension AnyPolicy: Sendable {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
struct LegacyPolicySet: VerifierPolicy {
    let verifyingCriticalExtensions: [ASN1ObjectIdentifier]

    var policies: [any VerifierPolicy]

    init(policies: [any VerifierPolicy]) {
        self.policies = policies

        var extensions: [ASN1ObjectIdentifier] = []
        extensions.reserveCapacity(policies.reduce(into: 0, { $0 += $1.verifyingCriticalExtensions.count }))

        for policy in policies {
            extensions.append(contentsOf: policy.verifyingCriticalExtensions)
        }

        self.verifyingCriticalExtensions = extensions
    }

    mutating func chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain) async -> PolicyEvaluationResult {
        var policyIndex = self.policies.startIndex

        while policyIndex < self.policies.endIndex {
            switch await self.policies[policyIndex].chainMeetsPolicyRequirements(chain: chain) {
            case .meetsPolicy:
                ()
            case .failsToMeetPolicy(reason: let reason):
                return .failsToMeetPolicy(reason: reason)
            }

            self.policies.formIndex(after: &policyIndex)
        }

        return .meetsPolicy
    }
}
