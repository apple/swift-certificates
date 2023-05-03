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

/// A ``VerifierPolicy`` implements a series of checks on an ``UnverifiedCertificateChain`` in order to determine
/// whether that chain should be trusted.
///
/// Certificate verification is split into two parts: chain building and policy enforcement. Chain building is general:
/// regardless of policy, we use the same chain building algorithm. This will generate a sequence of candidate chains in
/// the form of ``UnverifiedCertificateChain``.
///
/// Each of these candidate chains is then handed to a ``PolicySet`` to be checked against the certificate policy.
/// The reason for this is to allow different use-cases to share the same chain building code, but to enforce
/// different requirements on the chain.
///
/// Some ``VerifierPolicy`` objects are used frequently and are very common, such as ``RFC5280Policy`` which implements
/// the basic checks from that RFC. Other objects are less common, such as ``OCSPVerifierPolicy``, which performs live
/// revocation checking. Users can also implement their own policies to enable swift-certificates to support other
/// use-cases.
public protocol VerifierPolicy {
    /// The X.509 extension types that this policy understands and enforces.
    ///
    /// X.509 certificates can have extensions marked as `critical`. These extensions _must_ be understood and enforced by the
    /// verifier. If they aren't understood or processed, then verifying the chain must fail.
    ///
    /// ``Verifier`` uses the ``VerifierPolicy/verifyingCriticalExtensions`` field to determine what extensions are understood by a given
    /// ``PolicySet``. A ``PolicySet`` understands the union of all the understood extensions of its contained ``VerifierPolicy``
    /// objects.
    ///
    /// This may be an empty array, if the policy does not concern itself with any particular extensions. Users must only put
    /// an extension value in this space if they are actually enforcing the rules of that particular extension value.
    var verifyingCriticalExtensions: [ASN1ObjectIdentifier] { get }

    /// Called to determine whether a given ``UnverifiedCertificateChain`` meets the requirements of this policy.
    ///
    /// Certificate verification is split into two parts: chain building and policy enforcement. Chain building is general:
    /// regardless of policy, we use the same chain building algorithm. This will generate a sequence of candidate chains in
    /// the form of ``UnverifiedCertificateChain``.
    ///
    /// Each of these candidate chains is then handed to a ``PolicySet`` to be checked against the certificate policy.
    /// The checking is done in this method.
    mutating func chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain) async -> PolicyEvaluationResult
}

public enum PolicyEvaluationResult: Sendable {
    case meetsPolicy
    case failsToMeetPolicy(reason: String)
}
