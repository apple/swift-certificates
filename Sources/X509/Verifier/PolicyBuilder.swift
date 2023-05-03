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

@resultBuilder
public struct PolicyBuilder {
    @inlinable
    public static func buildBlock(_ components: some VerifierPolicy) -> some VerifierPolicy {
        components
    }
    
    @inlinable
    public static func buildExpression(_ expression: some VerifierPolicy) -> some VerifierPolicy {
        expression
    }
}


// MARK: empty policy
extension PolicyBuilder {
    @usableFromInline
    struct Empty: VerifierPolicy {
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
    public static func buildPartialBlock(first: some VerifierPolicy) -> some VerifierPolicy {
        first
    }
    
    @inlinable
    public static func buildPartialBlock(accumulated: some VerifierPolicy, next: some VerifierPolicy) -> some VerifierPolicy {
        Tuple2(first: accumulated, second: next)
    }
}


// MARK: if
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
    public static func buildOptional<Policy: VerifierPolicy>(_ component: Optional<Policy>) -> some VerifierPolicy {
        WrappedOptional(component)
    }
}

// MARK: if/else and switch
extension PolicyBuilder {
    public struct Either<First: VerifierPolicy, Second: VerifierPolicy>: VerifierPolicy {
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
        public mutating func chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain) async -> PolicyEvaluationResult {
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
    public static func buildEither<First: VerifierPolicy, Second: VerifierPolicy>(first component: First) -> Either<First, Second> {
        Either<First, Second>(storage: .first(component))
    }
    
    @inlinable
    public static func buildEither<First: VerifierPolicy, Second: VerifierPolicy>(second component: Second) -> Either<First, Second> {
        Either<First, Second>(storage: .second(component))
    }
}

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
}
