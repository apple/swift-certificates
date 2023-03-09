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

/// A sub-policy of the ``RFC5280Policy`` that polices the nameConstraints extension.
@usableFromInline
struct NameConstraintsPolicy: VerifierPolicy {
    @inlinable
    init() { }

    @inlinable
    func chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain) -> PolicyEvaluationResult {
        // For now we don't implement this, we'll add support later.
        return .meetsPolicy
    }
}
