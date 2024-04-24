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

import SwiftASN1

/// Provides a result-builder style DSL for constructing a ``VerifierPolicy`` in which one of the specified policies must match
///
/// This DSL allows us to construct dynamic ``VerifierPolicy`` at runtime without using type erasure.
/// The resulting ``VerifierPolicy`` will use the listed policy in the order of declaration to check if a chain meets any one policy
@resultBuilder
public struct OneOfPolicyBuilder {}

extension OneOfPolicyBuilder {
    @inlinable
    public static func buildLimitedAvailability<Policy: VerifierPolicy>(_ component: Policy) -> Policy {
        component
    }
}

// MARK: empty policy
extension OneOfPolicyBuilder {
    @usableFromInline
    struct Empty: VerifierPolicy {
        @inlinable
        var verifyingCriticalExtensions: [SwiftASN1.ASN1ObjectIdentifier] { [] }

        @inlinable
        init() {}

        @inlinable
        mutating func chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain) async -> PolicyEvaluationResult {
            .failsToMeetPolicy(reason: "No policies specified in OneOfPolicies block")
        }
    }

    @inlinable
    public static func buildBlock() -> some VerifierPolicy {
        Empty()
    }
}

// MARK: concatenated policies
extension OneOfPolicyBuilder {
    @usableFromInline
    struct Tuple2<First: VerifierPolicy, Second: VerifierPolicy>: VerifierPolicy {
        @usableFromInline
        var first: First

        @usableFromInline
        var second: Second

        @inlinable
        init(first: First, second: Second) {
            self.first = first
            self.second = second
        }

        @inlinable
        var verifyingCriticalExtensions: [SwiftASN1.ASN1ObjectIdentifier] {
            let firstExtensions = first.verifyingCriticalExtensions
            let secondExtensions = second.verifyingCriticalExtensions
            return firstExtensions.filter { secondExtensions.contains($0) }
        }

        @inlinable
        mutating func chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain) async -> PolicyEvaluationResult {
            let firstResult = await self.first.chainMeetsPolicyRequirements(chain: chain)
            switch firstResult {
            case .meetsPolicy:
                return .meetsPolicy
            case .failsToMeetPolicy(let firstReason):
                let secondResult = await self.second.chainMeetsPolicyRequirements(chain: chain)
                switch secondResult {
                case .meetsPolicy:
                    return .meetsPolicy
                case .failsToMeetPolicy(let secondReason):
                    return .failsToMeetPolicy(reason: "\(firstReason) and \(secondReason)")
                }
            }
        }
    }

    @inlinable
    public static func buildPartialBlock<Policy: VerifierPolicy>(first: Policy) -> Policy {
        first
    }

    @inlinable
    public static func buildPartialBlock(
        accumulated: some VerifierPolicy,
        next: some VerifierPolicy
    ) -> some VerifierPolicy {
        Tuple2(first: accumulated, second: next)
    }
}

// MARK: if
extension OneOfPolicyBuilder {
    @inlinable
    public static func buildOptional(_ component: (some VerifierPolicy)?) -> some VerifierPolicy {
        PolicyBuilder.WrappedOptional(component)
    }
}

// MARK: if/else and switch
extension OneOfPolicyBuilder {
    @inlinable
    public static func buildEither<First: VerifierPolicy, Second: VerifierPolicy>(
        first component: First
    ) -> PolicyBuilder._Either<First, Second> {
        PolicyBuilder._Either<First, Second>(storage: .first(component))
    }

    @inlinable
    public static func buildEither<First: VerifierPolicy, Second: VerifierPolicy>(
        second component: Second
    ) -> PolicyBuilder._Either<First, Second> {
        PolicyBuilder._Either<First, Second>(storage: .second(component))
    }
}

extension OneOfPolicyBuilder {
    @inlinable
    public static func buildFinalResult(_ component: some VerifierPolicy) -> some VerifierPolicy {
        PolicyBuilder.CachedVerifyingCriticalExtensions(wrapped: component)
    }

    @inlinable
    public static func buildFinalResult(_ component: AnyPolicy) -> AnyPolicy {
        func unwrapExistentialAndCache(policy: some VerifierPolicy) -> some VerifierPolicy {
            PolicyBuilder.CachedVerifyingCriticalExtensions(wrapped: policy)
        }
        let cachedPolicy = unwrapExistentialAndCache(policy: component.policy)
        return AnyPolicy(cachedPolicy)
    }
}

/// Use this to build a policy where any one of the sub-policies must be met for the overall policy to be met
/// For example, the following policy requires that RFC5280Policy is always met, and either PolicyA or PolicyB is met
/// It does not require that both PolicyA and PolicyB are met
/// let verifier = Verifier(rootCertificates: CertificateStore()) {
///     RFC5280Policy(validationTime: Date())
///     OneOfPolicies {
///         PolicyA()
///         PolicyB()
///     }
/// }
public struct OneOfPolicies<Policy: VerifierPolicy>: VerifierPolicy {
    private var policy: Policy

    public init(@OneOfPolicyBuilder policy: () -> Policy) {
        self.policy = policy()
    }

    public var verifyingCriticalExtensions: [ASN1ObjectIdentifier] {
        policy.verifyingCriticalExtensions
    }

    public mutating func chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain) async -> PolicyEvaluationResult
    {
        await self.policy.chainMeetsPolicyRequirements(chain: chain)
    }
}

/// Use this to build a policy where all of the sub-policies must be met for the overall policy to be met
/// This is only useful within a OneOfPolicies block, because at the top-level, it is already required for all policies
/// to be met, so adding this at the top-level is redundant
/// For example, the following policy requires that RFC5280Policy is always met, and then either policy C is met, or
/// A and B are both met. If A and B are both met, then C does not have to be met. If C is met, then neither A nor B
/// need to be met
/// let verifier = Verifier(rootCertificates: CertificateStore()) {
///     RFC5280Policy(validationTime: Date())
///     OneOfPolicies {
///         AllOfPolicies {
///             PolicyA()
///             PolicyB()
///         }
///         PolicyC()
///     }
/// }
public struct AllOfPolicies<Policy: VerifierPolicy>: VerifierPolicy {
    private var policy: Policy

    public init(@PolicyBuilder policy: () -> Policy) {
        self.policy = policy()
    }

    public var verifyingCriticalExtensions: [ASN1ObjectIdentifier] {
        policy.verifyingCriticalExtensions
    }

    public mutating func chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain) async -> PolicyEvaluationResult
    {
        await self.policy.chainMeetsPolicyRequirements(chain: chain)
    }
}
