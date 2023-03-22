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
import SwiftASN1

/// A ``VerifierPolicy`` that implements the core chain verifying policies from RFC 5280.
///
/// Almost all verifiers should use this policy as the initial component of their ``PolicySet``. The policy checks the
/// following things:
///
/// 1. Expiry. Expired certificates are rejected.
public struct RFC5280Policy: VerifierPolicy {
    public let verifyingCriticalExtensions: [ASN1ObjectIdentifier] = [
        .X509ExtensionID.basicConstraints,
        .X509ExtensionID.nameConstraints,

        // The presence of keyUsage here requires some explanation, becuase this policy doesn't _actually_ compute
        // on it in any way.
        //
        // The unfortunate reality of keyUsage is that, while RFC 5280 requires us to validate it, CAs have historically
        // done a very poor job of actually implementing it. The result is that policing KeyUsage produces minimal value
        // in terms of increased security, but produces a substantial uptick in the number of unbuildable chains. So
        // we _pretend_ to police the key usage, and just...don't.
        .X509ExtensionID.keyUsage
    ]

    @usableFromInline
    let expiryPolicy: ExpiryPolicy

    @usableFromInline
    let basicConstraintsPolicy: BasicConstraintsPolicy

    @usableFromInline
    let nameConstraintsPolicy: NameConstraintsPolicy

    @inlinable
    public init(validationTime: Date) {
        self.expiryPolicy = ExpiryPolicy(validationTime: validationTime)
        self.basicConstraintsPolicy = BasicConstraintsPolicy()
        self.nameConstraintsPolicy = NameConstraintsPolicy()
    }

    @inlinable
    public func chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain) -> PolicyEvaluationResult {
        if case .failsToMeetPolicy(let reason) = self.expiryPolicy.chainMeetsPolicyRequirements(chain: chain) {
            return .failsToMeetPolicy(reason: reason)
        }

        if case .failsToMeetPolicy(let reason) = self.basicConstraintsPolicy.chainMeetsPolicyRequirements(chain: chain) {
            return .failsToMeetPolicy(reason: reason)
        }

        if case .failsToMeetPolicy(let reason) = self.nameConstraintsPolicy.chainMeetsPolicyRequirements(chain: chain) {
            return .failsToMeetPolicy(reason: reason)
        }

        return .meetsPolicy
    }
}
