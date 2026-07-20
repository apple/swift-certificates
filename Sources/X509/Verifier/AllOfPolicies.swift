//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCertificates open source project
//
// Copyright (c) 2024 Apple Inc. and the SwiftCertificates project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCertificates project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import SwiftASN1

/// Use this to build a policy where all of the sub-policies must be met for the overall policy to be met.
/// This is only useful within a OneOfPolicies block, because at the top-level, it is already required for all policies
/// to be met, so adding this at the top-level is redundant.
/// For example, the following policy requires that RFC5280Policy is always met, and then either policy C is met, or
/// A and B are both met. If A and B are both met, then C does not have to be met. If C is met, then neither A nor B
/// need to be met.
/// ```swift
/// let verifier = Verifier(rootCertificates: CertificateStore()) {
///     RFC5280Policy()
///     OneOfPolicies {
///         AllOfPolicies {
///             PolicyA()
///             PolicyB()
///         }
///         PolicyC()
///     }
/// }
/// ```
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public struct AllOfPolicies<Policy: VerifierPolicy>: VerifierPolicy {
    @usableFromInline
    var policy: Policy

    @inlinable
    public init(@PolicyBuilder policy: () throws -> Policy) throws {
        self.policy = try policy()
    }

    @inlinable
    public init(@PolicyBuilder policy: () -> Policy) {
        self.policy = policy()
    }

    @inlinable
    public var verifyingCriticalExtensions: [ASN1ObjectIdentifier] {
        self.policy.verifyingCriticalExtensions
    }

    @inlinable
    public mutating func chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain) async -> PolicyEvaluationResult
    {
        await self.policy.chainMeetsPolicyRequirements(chain: chain)
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension AllOfPolicies: Sendable where Policy: Sendable {}
