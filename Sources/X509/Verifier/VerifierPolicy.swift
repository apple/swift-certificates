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

public protocol VerifierPolicy: Sendable {
    mutating func chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain) async -> PolicyEvaluationResult
}

public enum PolicyEvaluationResult: Sendable {
    case meetsPolicy
    case failsToMeetPolicy(reason: String)
}

// TODO: Several enhancements.
//
// This type should properly be a variadic generic over `VerifierPolicy` to allow proper composition.
// Additionally, we should add conditional Sendable, Equatable, and Hashable conformances as needed.
// This will also allow equivalent conditional conformances on `Verifier`.
public struct PolicySet: VerifierPolicy {
    @usableFromInline var policies: [any VerifierPolicy]

    @inlinable
    public init(policies: [any VerifierPolicy]) {
        self.policies = policies
    }

    public mutating func chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain) async -> PolicyEvaluationResult {
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

