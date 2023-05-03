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

public struct AnyPolicy: VerifierPolicy {
    @usableFromInline
    var policy: any VerifierPolicy
    
    @inlinable
    public init(_ policy: some VerifierPolicy) {
        self.policy = policy
    }
    
    @inlinable
    public init(@PolicyBuilder makePolicy: () -> some VerifierPolicy) {
        self.init(makePolicy())
    }
    
    @inlinable
    public var verifyingCriticalExtensions: [SwiftASN1.ASN1ObjectIdentifier] {
        policy.verifyingCriticalExtensions
    }
    
    @inlinable
    public mutating func chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain) async -> PolicyEvaluationResult {
        await policy.chainMeetsPolicyRequirements(chain: chain)
    }
}

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

@available(*, deprecated, message: "use PolicyBuilder to construct a custom policy")
public typealias PolicySet = AnyPolicy

extension AnyPolicy {
    @available(*, deprecated, message: "use PolicyBuilder to construct a custom policy")
    public init(policies: [any VerifierPolicy]) {
        self.init(LegacyPolicySet(policies: policies))
    }
}
