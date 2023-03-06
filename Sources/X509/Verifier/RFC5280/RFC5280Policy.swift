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
import Foundation

/// A ``VerifierPolicy`` that implements the core chain verifying policies from RFC 5280.
///
/// Almost all verifiers should use this policy as the initial component of their ``PolicySet``. The policy checks the
/// following things:
///
/// 1. Expiry. Expired certificates are rejected.
public struct RFC5280Policy: VerifierPolicy {
    @usableFromInline
    let validationTime: Date

    @inlinable
    public init(validationTime: Date) {
        self.validationTime = validationTime
    }

    @inlinable
    public func chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain) -> PolicyEvaluationResult {
        if case .failsToMeetPolicy(let reason) = self._validateExpiry(chain) {
            return .failsToMeetPolicy(reason: reason)
        }

        return .meetsPolicy
    }

    @inlinable
    func _validateExpiry(_ chain: UnverifiedCertificateChain) -> PolicyEvaluationResult {
        // This is an easy check: confirm all the certs are valid.
        for cert in chain {
            if cert.notValidBefore > cert.notValidAfter {
                return .failsToMeetPolicy(reason: "RFC5280Policy: Certificate \(cert) has invalid expiry, notValidAfter is earlier than notValidBefore")
            }

            if self.validationTime < cert.notValidBefore {
                return .failsToMeetPolicy(reason: "RFC5280Policy: Certificate \(cert) is not yet valid")
            }

            if self.validationTime > cert.notValidAfter {
                return .failsToMeetPolicy(reason: "RFC5280Policy: Certificate \(cert) has expired")
            }
        }

        return .meetsPolicy
    }
}
