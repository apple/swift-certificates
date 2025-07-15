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

/// A sub-policy of the ``RFC5280Policy`` that polices that version 1 certificates do not contain extensions.
@usableFromInline
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
struct VersionPolicy: VerifierPolicy, Sendable {
    @inlinable
    var verifyingCriticalExtensions: [SwiftASN1.ASN1ObjectIdentifier] { [] }

    @inlinable
    init() {}

    @inlinable
    func chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain) -> PolicyEvaluationResult {
        for certificate in chain {
            if certificate.version == .v1 && certificate.extensions.isEmpty == false {
                return .failsToMeetPolicy(
                    reason: "version 1 certificate contains extensions but should not: \(certificate)"
                )
            }
        }
        return .meetsPolicy
    }
}
