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

/// A sub-policy of the ``RFC5280Policy`` that polices the basicConstraints extension.
@usableFromInline
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
struct BasicConstraintsPolicy: VerifierPolicy, Sendable {
    @usableFromInline
    let verifyingCriticalExtensions: [ASN1ObjectIdentifier] = [
        .X509ExtensionID.basicConstraints
    ]

    @inlinable
    init() {}

    @inlinable
    func chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain) -> PolicyEvaluationResult {
        // The rules for BasicConstraints come from https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.9,
        // but roughly can be summarised as:
        //
        // 0. If the cert is a v1 cert then shrug our shoulders, it can do whatever.
        // 1. If basicConstraints is absent, the cert must not be used as an issuing certificate.
        // 2. If basicConstraints is present and does not assert that this is a CA, this must not be used
        //        as an issuing certificate.
        // 3. If basic constraints is present, and the CA bit is present, and there is a path length constraint,
        //        then this certificate may not have more sub CAs than the path length constraint allows.
        //
        // RFC 5280 also wants us to enforce key usage. Unfortunately, as a practical matter, browsers don't. That
        // means that other implementations, like Go and webpki, also don't. To maximise compatibility, we don't either.
        var chain = chain[...]
        guard let leaf = chain.popFirst() else {
            // This is conceptually impossible, but we'll tolerate it.
            return .failsToMeetPolicy(reason: "RFC5280Policy: Empty certificate chain")
        }

        // We check for the special-case of a trust root being presented as the end entity cert. If that's what's
        // happening, we require that this cert be marked as a CA.
        if chain.count == 0 && leaf.version != .v1 {
            do {
                switch try leaf.extensions.basicConstraints {
                case .some(.isCertificateAuthority):
                    return .meetsPolicy
                case .some(.notCertificateAuthority), .none:
                    return .failsToMeetPolicy(reason: "RFC5280Policy: Self-signed cert \(leaf) is not marked as a CA")
                }
            } catch {
                return .failsToMeetPolicy(
                    reason: "RFC5280Policy: Error processing basic constraints for \(leaf): \(error)"
                )
            }
        }

        // Now we check the chain.
        var subCACount = 0

        for cert in chain {
            do {
                switch try (cert.extensions.basicConstraints, cert.version) {
                case (_, .v1):
                    // Is a v1 cert. Basic constraints don't apply here. Continue to the next cert.
                    // Note that we _do_ include this in the path length, in case there are basic constraints further along
                    // the path.
                    ()
                case (.some(.isCertificateAuthority(.some(let maxPathLength))), _) where maxPathLength < subCACount:
                    // Is a CA, but the max path length is smaller than the number of sub CAs we have.
                    let subCACount = subCACount
                    return .failsToMeetPolicy(
                        reason:
                            "RFC5280Policy: CA \(cert) has maximum path length \(maxPathLength), but chain has \(subCACount) subCAs"
                    )

                case (.some(.isCertificateAuthority), _):
                    // Is a CA, but either the max path length is at least as large as our current set of sub CAs, or there isn't one.
                    // Continue to the next cert.
                    ()

                case (.some(.notCertificateAuthority), _), (.none, _):
                    return .failsToMeetPolicy(reason: "RFC5280Policy: Certificate \(cert) is not marked as a CA")
                }
            } catch {
                return .failsToMeetPolicy(
                    reason: "RFC5280Policy: Error processing basic constraints for \(cert): \(error)"
                )
            }

            if cert.issuer != cert.subject {
                // only non-self-issued certificates count against the maxPathLength limit
                //
                // RFC Section 4.2.1.9.  Basic Constraints
                // [...]
                // The pathLenConstraint field is meaningful only if the cA boolean is
                // asserted and the key usage extension, if present, asserts the
                // keyCertSign bit (Section 4.2.1.3).  In this case, it gives the
                // maximum number of non-self-issued intermediate certificates that may
                // follow this certificate in a valid certification path.  (Note: The
                // last certificate in the certification path is not an intermediate
                // certificate, and is not included in this limit.  Usually, the last
                // certificate is an end entity certificate, but it can be a CA
                // certificate.)  A pathLenConstraint of zero indicates that no non-
                // self-issued intermediate CA certificates may follow in a valid
                // certification path.  Where it appears, the pathLenConstraint field
                // MUST be greater than or equal to zero.  Where pathLenConstraint does
                // not appear, no limit is imposed.
                // [...]
                // https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.9

                subCACount += 1
            }
        }

        return .meetsPolicy
    }
}
