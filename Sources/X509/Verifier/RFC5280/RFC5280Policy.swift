//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCertificates open source project
//
// Copyright (c) 2025 Apple Inc. and the SwiftCertificates project authors
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

/// A ``VerifierPolicy`` that implements the core chain verifying policies from RFC 5280.
///
/// Almost all verifiers should use this policy as the initial component of their policy set. The policy checks the
/// following things:
///
/// 1. Version. ``Certificate/Version-swift.struct/v1`` ``Certificate``s with ``Certificate/Extensions-swift.struct`` are rejected.
/// 2. Expiry. Expired certificates are rejected.
/// 3. Basic Constraints. Police the constraints contained in the ``BasicConstraints`` extension.
/// 4. Name Constraints. Police the constraints contained in the ``NameConstraints`` extension.
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public struct RFC5280Policy: VerifierPolicy, Sendable {
    public let verifyingCriticalExtensions: [ASN1ObjectIdentifier] = [
        .X509ExtensionID.basicConstraints,
        .X509ExtensionID.nameConstraints,

        // The presence of keyUsage here requires some explanation, because this policy doesn't _actually_ compute
        // on it in any way.
        //
        // The unfortunate reality of keyUsage is that, while RFC 5280 requires us to validate it, CAs have historically
        // done a very poor job of actually implementing it. The result is that policing KeyUsage produces minimal value
        // in terms of increased security, but produces a substantial uptick in the number of unbuildable chains. So
        // we _pretend_ to police the key usage, and just...don't.
        .X509ExtensionID.keyUsage,
    ]

    @usableFromInline
    let versionPolicy: VersionPolicy

    @usableFromInline
    let expiryPolicy: ExpiryPolicy?

    @usableFromInline
    let basicConstraintsPolicy: BasicConstraintsPolicy

    @usableFromInline
    let nameConstraintsPolicy: NameConstraintsPolicy

    @inlinable
    // private but @inlinable
    init(expiryPolicy: ExpiryPolicy?) {
        self.versionPolicy = VersionPolicy()
        self.expiryPolicy = expiryPolicy
        self.basicConstraintsPolicy = BasicConstraintsPolicy()
        self.nameConstraintsPolicy = NameConstraintsPolicy()
    }

    @inlinable
    @available(
        *,
        deprecated,
        message:
            "Use init() to validated expiry against the current time. Otherwise, to validate against a fixed time, import with @_spi(FixedExpiryValidationTime) and use init(fixedExpiryValidationTime:)."
    )
    public init(validationTime: Date) {
        self.init(expiryPolicy: ExpiryPolicy(fixedValidationTime: validationTime))
    }

    /// Creates an instance with an optional *fixed* expiry validation time.
    ///
    /// - Parameter fixedValidationTime: The *fixed* time to compare against when determining if the certificates in the chain have expired. A fixed
    ///   time is a *specific* time, either in the past or future, but **not** the current time. To compare against the current time *at the point of validation*,
    ///   pass `nil` to `fixedValidationTime`.
    ///
    /// - Important: Pass `nil` to `fixedValidationTime` for the current time to be obtained at the time of validation and then used for the
    ///   comparison; the validation method may be invoked long after initialization.
    @inlinable
    @available(
        *,
        deprecated,
        message:
            "Use init() to validated expiry against the current time. Otherwise, to validate against a fixed time, import with @_spi(FixedExpiryValidationTime) and use init(fixedExpiryValidationTime:)."
    )
    public init(fixedValidationTime: Date? = nil) {
        if let fixedValidationTime {
            self.init(expiryPolicy: ExpiryPolicy(fixedValidationTime: fixedValidationTime))
        } else {
            self.init(expiryPolicy: ExpiryPolicy())
        }
    }

    /// - Note: Certificate expiry is validated against the *current* time (evaluated at the point of validation)
    @inlinable
    public init() {
        self.init(expiryPolicy: ExpiryPolicy())
    }

    /// Creates an instance with a **fixed** time to validate certificate expiry against (a predetermined time *either*
    /// in the past or future)
    ///
    /// - Parameter fixedExpiryValidationTime: The *fixed* time to compare against when determining if the certificates
    ///   in the chain have expired. A fixed time is a predetermined time, either in the past or future, but **not** the
    ///   current time. To compare against the current time *at the point of validation*, use ``init()``.
    ///
    /// - Warning: Only use this initializer if you want to validate the certificates against a *fixed* time. Most users
    ///   should use ``init()``: the expiry of the certificates will be validated against the current time (evaluated at
    ///   the point of validation) when using that initializer.
    @inlinable
    @_spi(FixedExpiryValidationTime)
    public init(fixedExpiryValidationTime: Date) {
        self.init(expiryPolicy: ExpiryPolicy(fixedValidationTime: fixedExpiryValidationTime))
    }

    @_spi(DisableValidityCheck)
    public static func withValidityCheckDisabled() -> RFC5280Policy {
        return RFC5280Policy(expiryPolicy: nil)
    }

    @inlinable
    public func chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain) -> PolicyEvaluationResult {
        if case .failsToMeetPolicy(let reason) = self.versionPolicy.chainMeetsPolicyRequirements(chain: chain) {
            return .failsToMeetPolicy(reason: reason)
        }
        if let expiryPolicy = self.expiryPolicy,
            case .failsToMeetPolicy(let reason) = expiryPolicy.chainMeetsPolicyRequirements(chain: chain)
        {
            return .failsToMeetPolicy(reason: reason)
        }

        if case .failsToMeetPolicy(let reason) = self.basicConstraintsPolicy.chainMeetsPolicyRequirements(chain: chain)
        {
            return .failsToMeetPolicy(reason: reason)
        }

        if case .failsToMeetPolicy(let reason) = self.nameConstraintsPolicy.chainMeetsPolicyRequirements(chain: chain) {
            return .failsToMeetPolicy(reason: reason)
        }

        return .meetsPolicy
    }
}
