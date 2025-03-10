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

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import SwiftASN1

/// A sub-policy of the ``RFC5280Policy`` that polices expiry.
@usableFromInline
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, *)
struct ExpiryPolicy: VerifierPolicy {
    @usableFromInline
    let verifyingCriticalExtensions: [ASN1ObjectIdentifier] = []

    @usableFromInline
    let validationTime: GeneralizedTime

    @inlinable
    init(validationTime: Date) {
        self.validationTime = GeneralizedTime(validationTime)
    }

    @inlinable
    func chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain) -> PolicyEvaluationResult {
        // This is an easy check: confirm all the certs are valid.
        //
        // Note that we do this computation on the TBSCertificate Validity struct, not the public Date fields. This is
        // to avoid expensive repeated transformations into Date fields.
        for cert in chain {
            let notValidBefore = GeneralizedTime(cert.tbsCertificate.validity.notBefore)
            let notValidAfter = GeneralizedTime(cert.tbsCertificate.validity.notAfter)

            if notValidBefore > notValidAfter {
                return .failsToMeetPolicy(
                    reason:
                        "RFC5280Policy: Certificate \(cert) has invalid expiry, notValidAfter is earlier than notValidBefore"
                )
            }

            if self.validationTime < notValidBefore {
                return .failsToMeetPolicy(reason: "RFC5280Policy: Certificate \(cert) is not yet valid")
            }

            if self.validationTime > notValidAfter {
                return .failsToMeetPolicy(reason: "RFC5280Policy: Certificate \(cert) has expired")
            }
        }

        return .meetsPolicy
    }
}
