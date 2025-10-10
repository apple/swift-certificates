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

/// Provides a result-builder style DSL for constructing a ``VerifierPolicy``.
///
/// This DSL allows us to construct dynamic ``VerifierPolicy`` at runtime without using type erasure.
/// The resulting ``VerifierPolicy`` will use the listed policy in the order of declaration to check if a chain meets all policies.
/// For Example, a simple ``Verifier`` with a simple policy can be constructed like this:
/// ```swift
/// let verifier = Verifier(rootCertificates: roots) {
///     RFC5280Policy()
///     OCSPVerifierPolicy(failureMode: .soft, requester: requester)
/// }
/// ```
@resultBuilder
public struct PolicyBuilder: Sendable {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension PolicyBuilder {
    @inlinable
    public static func buildLimitedAvailability<Policy: VerifierPolicy>(_ component: Policy) -> Policy {
        component
    }
}

// MARK: empty policy
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension PolicyBuilder {
    @usableFromInline
    struct Empty: VerifierPolicy, Sendable {
        @inlinable
        var verifyingCriticalExtensions: [SwiftASN1.ASN1ObjectIdentifier] { [] }

        @inlinable
        init() {}

        @inlinable
        mutating func chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain) async -> PolicyEvaluationResult {
            .meetsPolicy
        }
    }

    @inlinable
    public static func buildBlock() -> some VerifierPolicy {
        Empty()
    }
}

// MARK: concatenated policies
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension PolicyBuilder {
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
            first.verifyingCriticalExtensions + second.verifyingCriticalExtensions
        }

        @inlinable
        mutating func chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain) async -> PolicyEvaluationResult {
            switch await first.chainMeetsPolicyRequirements(chain: chain) {
            case .meetsPolicy:
                break
            case .failsToMeetPolicy(let reason):
                return .failsToMeetPolicy(reason: reason)
            }

            return await second.chainMeetsPolicyRequirements(chain: chain)
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

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension PolicyBuilder.Tuple2: Sendable where First: Sendable, Second: Sendable {}

// MARK: if
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension PolicyBuilder {
    @usableFromInline
    struct WrappedOptional<Wrapped>: VerifierPolicy where Wrapped: VerifierPolicy {
        @usableFromInline
        var wrapped: Wrapped?

        @inlinable
        init(_ wrapped: Wrapped?) {
            self.wrapped = wrapped
        }

        @inlinable
        var verifyingCriticalExtensions: [SwiftASN1.ASN1ObjectIdentifier] {
            self.wrapped?.verifyingCriticalExtensions ?? []
        }

        @inlinable
        mutating func chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain) async -> PolicyEvaluationResult {
            await self.wrapped?.chainMeetsPolicyRequirements(chain: chain) ?? .meetsPolicy
        }
    }

    @inlinable
    public static func buildOptional(_ component: (some VerifierPolicy)?) -> some VerifierPolicy {
        WrappedOptional(component)
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension PolicyBuilder.WrappedOptional: Sendable where Wrapped: Sendable {}

// MARK: if/else and switch
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension PolicyBuilder {
    /// implementation detail of ``PolicyBuilder`` which should not be used outside the implementation of ``PolicyBuilder``.
    public struct _Either<First: VerifierPolicy, Second: VerifierPolicy>: VerifierPolicy {
        @usableFromInline
        enum Storage {
            case first(First)
            case second(Second)
        }

        @usableFromInline
        var storage: Storage

        @inlinable
        init(storage: Storage) {
            self.storage = storage
        }

        @inlinable
        public var verifyingCriticalExtensions: [ASN1ObjectIdentifier] {
            switch self.storage {
            case .first(let first): return first.verifyingCriticalExtensions
            case .second(let second): return second.verifyingCriticalExtensions
            }
        }

        @inlinable
        public mutating func chainMeetsPolicyRequirements(
            chain: UnverifiedCertificateChain
        ) async -> PolicyEvaluationResult {
            switch self.storage {
            case .first(var first):
                defer { self.storage = .first(first) }
                return await first.chainMeetsPolicyRequirements(chain: chain)
            case .second(var second):
                defer { self.storage = .second(second) }
                return await second.chainMeetsPolicyRequirements(chain: chain)
            }
        }
    }

    @inlinable
    public static func buildEither<First: VerifierPolicy, Second: VerifierPolicy>(
        first component: First
    ) -> _Either<First, Second> {
        _Either<First, Second>(storage: .first(component))
    }

    @inlinable
    public static func buildEither<First: VerifierPolicy, Second: VerifierPolicy>(
        second component: Second
    ) -> _Either<First, Second> {
        _Either<First, Second>(storage: .second(component))
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension PolicyBuilder._Either: Sendable where First: Sendable, Second: Sendable {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension PolicyBuilder._Either.Storage: Sendable where First: Sendable, Second: Sendable {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension PolicyBuilder {
    @usableFromInline
    struct CachedVerifyingCriticalExtensions<Wrapped: VerifierPolicy>: VerifierPolicy {
        @usableFromInline
        let verifyingCriticalExtensions: [ASN1ObjectIdentifier]

        @usableFromInline
        var wrapped: Wrapped

        @inlinable
        init(wrapped: Wrapped) {
            self.verifyingCriticalExtensions = wrapped.verifyingCriticalExtensions
            self.wrapped = wrapped
        }

        @inlinable
        mutating func chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain) async -> PolicyEvaluationResult {
            await wrapped.chainMeetsPolicyRequirements(chain: chain)
        }
    }

    @inlinable
    public static func buildFinalResult(_ component: some VerifierPolicy) -> some VerifierPolicy {
        CachedVerifyingCriticalExtensions(wrapped: component)
    }

    @inlinable
    public static func buildFinalResult(_ component: AnyPolicy) -> AnyPolicy {
        func unwrapExistentialAndCache(policy: some VerifierPolicy) -> some VerifierPolicy {
            CachedVerifyingCriticalExtensions(wrapped: policy)
        }
        let cachedPolicy = unwrapExistentialAndCache(policy: component.policy)
        return AnyPolicy(cachedPolicy)
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension PolicyBuilder.CachedVerifyingCriticalExtensions: Sendable where Wrapped: Sendable {}
