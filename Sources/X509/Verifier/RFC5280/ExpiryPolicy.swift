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
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
struct ExpiryPolicy: VerifierPolicy, Sendable {
    @usableFromInline
    let verifyingCriticalExtensions: [ASN1ObjectIdentifier] = []

    @usableFromInline
    let fixedValidationTime: GeneralizedTime?

    /// Creates an instance that will use the the current time (evaluated *at the point of validation*) to verify
    /// whether the certificates in the chain have not expired
    @inlinable
    init() {
        self.fixedValidationTime = nil
    }

    /// Creates an instance with a *fixed* expiry validation time.
    ///
    /// - Parameter fixedValidationTime: The *fixed* time to compare against when determining if the certificates in the
    ///   chain have expired. A fixed time is a *specific* time, either in the past or future, but **not** the current
    ///   time. To compare against the current time *at the point of validation*, use ``init()``.
    ///
    /// - Warning: Only use this initializer if you want to validate the certificates against a *fixed* time (a
    ///   predetermined time *either* in the past or future). Most users should use ``init()``: the expiry of the
    ///   certificates will be validated against the current time (evaluated at the point of validation) when using that
    ///   initializer.
    @inlinable
    init(fixedValidationTime: Date) {
        self.fixedValidationTime = GeneralizedTime(fixedValidationTime)
    }

    @inlinable
    func chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain) -> PolicyEvaluationResult {
        // Obtain the current time if self.fixedValidationTime is nil.
        let validationTime = self.fixedValidationTime ?? GeneralizedTime(Date())

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

            if validationTime < notValidBefore {
                return .failsToMeetPolicy(reason: "RFC5280Policy: Certificate \(cert) is not yet valid")
            }

            if validationTime > notValidAfter {
                return .failsToMeetPolicy(reason: "RFC5280Policy: Certificate \(cert) has expired")
            }
        }

        return .meetsPolicy
    }
}
