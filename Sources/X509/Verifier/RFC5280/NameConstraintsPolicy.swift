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

/// A sub-policy of the ``RFC5280Policy`` that polices the nameConstraints extension.
@usableFromInline
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
struct NameConstraintsPolicy: VerifierPolicy, Sendable {
    @usableFromInline
    let verifyingCriticalExtensions: [ASN1ObjectIdentifier] = [
        .X509ExtensionID.nameConstraints
    ]

    @inlinable
    init() {}

    @inlinable
    func chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain) -> PolicyEvaluationResult {
        // The rules for name constraints come from https://www.rfc-editor.org/rfc/rfc5280#section-4.2.1.10.
        //
        // Some notes:
        //
        // - RFC 5280 says we MUST validate directoryName constraints, and SHOULD validate rfc822Name,
        //       URI, dNSName, and iPAddress constraints.
        // - If there's a constraint we don't support and can't validate, we MUST reject the cert.
        //
        // Our algorithm is recursive: starting from the root and moving towards the leaf, for each CA
        // cert we apply the name constraints to all of the other certificates in the chain. The one exception
        // is for self-signed certs where, much like with basic constraints, we briefly pretend that the
        // self-signed cert issued itself and enforce its own name constraints on it.
        if chain.count == 1 {
            return Self._validateNameConstraints(chain[...], issuer: chain.first!)
        }

        var issuedCerts = chain[...]
        while let issuer = issuedCerts.popLast(), issuedCerts.count > 0 {
            if case .failsToMeetPolicy(let reason) = Self._validateNameConstraints(issuedCerts, issuer: issuer) {
                return .failsToMeetPolicy(reason: reason)
            }
        }

        return .meetsPolicy
    }

    @inlinable
    static func _validateNameConstraints(
        _ issuedCerts: UnverifiedCertificateChain.SubSequence,
        issuer: Certificate
    ) -> PolicyEvaluationResult {
        let maybeConstraints: NameConstraints?

        do {
            maybeConstraints = try issuer.extensions.nameConstraints
        } catch {
            // We couldn't decode these! Fail validation.
            return .failsToMeetPolicy(reason: "RFC5280Policy: Unable to decode name constraints from \(issuer)")
        }

        guard let constraints = maybeConstraints else {
            // No name constraints to enforce, we're done.
            return .meetsPolicy
        }

        for cert in issuedCerts {
            let names: Certificate.NameSequence

            do {
                names = try cert.names
            } catch {
                return .failsToMeetPolicy(reason: "RFC5280Policy: Unable to decode SAN field of \(cert): \(error)")
            }

            for name in names {
                if case .failsToMeetPolicy(let reason) = Self._validatePermittedSubtrees(
                    constraints.permittedSubtrees,
                    name
                ) {
                    return .failsToMeetPolicy(reason: reason)
                }

                if case .failsToMeetPolicy(let reason) = Self._validateExcludedSubtrees(
                    constraints.excludedSubtrees,
                    name
                ) {
                    return .failsToMeetPolicy(reason: reason)
                }
            }
        }

        return .meetsPolicy
    }

    @inlinable
    static func _validateExcludedSubtrees(
        _ excludedSubtrees: [GeneralName],
        _ name: GeneralName
    ) -> PolicyEvaluationResult {
        // For excluded trees, if _any_ match then the name is forbidden.
        for excludedSubtree in excludedSubtrees {
            switch (excludedSubtree, name) {
            case (.directoryName(let constraint), .directoryName(let presentedName)):
                if directoryNameMatchesConstraint(directoryName: presentedName, constraint: constraint) {
                    return .failsToMeetPolicy(
                        reason:
                            "RFC5280Policy: directoryName \(presentedName) is excluded by \(excludedSubtree) in name constraints"
                    )
                }
            case (.dnsName(let constraint), .dnsName(let presentedName)):
                if dnsNameMatchesConstraint(dnsName: presentedName.utf8, constraint: constraint.utf8) {
                    return .failsToMeetPolicy(
                        reason:
                            "RFC5280Policy: dnsName \(presentedName) is excluded by \(excludedSubtree) in name constraints"
                    )
                }
            case (.ipAddress(let constraint), .ipAddress(let presentedName)):
                if ipAddressMatchesConstraint(ipAddress: presentedName, constraint: constraint) {
                    return .failsToMeetPolicy(
                        reason:
                            "RFC5280Policy: ipAddress \(presentedName) is excluded by \(excludedSubtree) in name constraints"
                    )
                }
            case (.uniformResourceIdentifier(let constraint), .uniformResourceIdentifier(let presentedName)):
                if uriNameMatchesConstraint(uriName: presentedName, constraint: constraint) {
                    return .failsToMeetPolicy(
                        reason:
                            "RFC5280Policy: URI \(presentedName) is excluded by \(excludedSubtree) in name constraints"
                    )
                }
            case (.directoryName, _), (.dnsName, _), (.ipAddress, _), (.uniformResourceIdentifier, _):
                // We support these, but the current name isn't of that type.
                continue
            default:
                // We don't support constraints on these!
                //
                // Of the set that's currently unsupported, we should probably support rfc822Name (a.k.a. email address).
                // For now we're omitting it, but at some point someone is going to run into this limitation and we'll want to come
                // back and fix it.
                return .failsToMeetPolicy(
                    reason:
                        "RFC5280Policy: Unable to validate excluded subtree for name \(excludedSubtree), unsupported constraint"
                )
            }
        }

        // No policy rejected this.
        return .meetsPolicy
    }

    @inlinable
    static func _validatePermittedSubtrees(
        _ permittedSubtrees: [GeneralName],
        _ name: GeneralName
    ) -> PolicyEvaluationResult {
        var evaluatedAtLeastOneConstraint = false

        for permittedSubtree in permittedSubtrees {
            switch (permittedSubtree, name) {
            case (.directoryName(let constraint), .directoryName(let presentedName)):
                evaluatedAtLeastOneConstraint = true

                if directoryNameMatchesConstraint(directoryName: presentedName, constraint: constraint) {
                    // This is a match, we're good.
                    return .meetsPolicy
                }

            case (.dnsName(let constraint), .dnsName(let presentedName)):
                evaluatedAtLeastOneConstraint = true

                if dnsNameMatchesConstraint(dnsName: presentedName.utf8, constraint: constraint.utf8) {
                    // This is a match, we're good.
                    return .meetsPolicy
                }
            case (.ipAddress(let constraint), .ipAddress(let presentedName)):
                evaluatedAtLeastOneConstraint = true

                if ipAddressMatchesConstraint(ipAddress: presentedName, constraint: constraint) {
                    // This is a match, we're good.
                    return .meetsPolicy
                }
            case (.uniformResourceIdentifier(let constraint), .uniformResourceIdentifier(let presentedName)):
                evaluatedAtLeastOneConstraint = true

                if uriNameMatchesConstraint(uriName: presentedName, constraint: constraint) {
                    // This is a match, we're good.
                    return .meetsPolicy
                }
            case (.directoryName, _), (.dnsName, _), (.ipAddress, _), (.uniformResourceIdentifier, _):
                // We support these, but the current name isn't of that type. This means we didn't evaluate
                // this constraint.
                continue
            default:
                // We don't support constraints on these!
                //
                // Of the set that's currently unsupported, we should probably support rfc822Name (a.k.a. email address).
                // For now we're omitting it, but at some point someone is going to run into this limitation and we'll want to come
                // back and fix it.
                return .failsToMeetPolicy(
                    reason:
                        "RFC5280Policy: Unable to validate permitted subtree for name \(permittedSubtree), unsupported constraint"
                )
            }
        }

        // Uh-oh, nothing matched! This is only a problem if we have at least one constraint for the given type.
        guard evaluatedAtLeastOneConstraint else {
            return .meetsPolicy
        }
        return .failsToMeetPolicy(
            reason: "RFC5280Policy: Unable to validate permitted subtree for \(permittedSubtrees), no matches!"
        )
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate {
    @inlinable
    var names: NameSequence {
        get throws {
            return try NameSequence(self)
        }
    }

    @usableFromInline
    struct NameSequence: Sequence, Sendable {
        @usableFromInline
        var subject: DistinguishedName

        @usableFromInline
        var alternativeNames: SubjectAlternativeNames

        @inlinable
        init(_ certificate: Certificate) throws {
            self.subject = certificate.subject
            self.alternativeNames = try certificate.extensions.subjectAlternativeNames ?? .init()
        }

        @inlinable
        func makeIterator() -> Iterator {
            return Iterator(self.subject, self.alternativeNames)
        }

        @usableFromInline
        struct Iterator: IteratorProtocol, Sendable {
            @usableFromInline
            var subject: DistinguishedName?

            @usableFromInline
            var alternativeNames: SubjectAlternativeNames.SubSequence

            @inlinable
            init(_ subject: DistinguishedName, _ alternativeNames: SubjectAlternativeNames) {
                self.subject = subject
                self.alternativeNames = alternativeNames[...]
            }

            @inlinable
            mutating func next() -> GeneralName? {
                guard let subject = self.subject else {
                    return self.alternativeNames.popFirst()
                }
                self.subject = nil
                return .directoryName(subject)
            }
        }
    }
}
