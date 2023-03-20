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

/// A sub-policy of the ``RFC5280Policy`` that polices expiry.
@usableFromInline
struct ExpiryPolicy: VerifierPolicy {
    @usableFromInline
    let processedExtensions: [ASN1ObjectIdentifier] = []

    @usableFromInline
    let validationTime: Date

    @inlinable
    init(validationTime: Date) {
        self.validationTime = validationTime
    }

    @inlinable
    func chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain) -> PolicyEvaluationResult {
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
