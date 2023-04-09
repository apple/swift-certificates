//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCertificates open source project
//
// Copyright (c) 2022 Apple Inc. and the SwiftCertificates project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCertificates project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
import SwiftASN1

public struct Verifier {
    public var rootCertificates: CertificateStore

    public var policy: PolicySet

    @inlinable
    public init(rootCertificates: CertificateStore, policy: PolicySet) {
        self.rootCertificates = rootCertificates
        self.policy = policy
    }

    public mutating func validate(leafCertificate: Certificate, intermediates: CertificateStore, diagnosticCallback: ((String) -> Void)? = nil) async -> VerificationResult {
        var partialChains: [CandidatePartialChain] = [CandidatePartialChain(leaf: leafCertificate)]

        var policyFailures: [VerificationResult.PolicyFailure] = []

        // First check: does this leaf certificate contain critical extensions that are not satisfied by the policyset?
        // If so, reject the chain.
        if leafCertificate.hasUnhandledCriticalExtensions(handledExtensions: self.policy.verifyingCriticalExtensions) {
            return .couldNotValidate([])
        }

        // Second check: is this leaf _already in_ the certificate store? If it is, we can just trust it directly.
        //
        // Note that this requires an _exact match_: if there isn't an exact match, we'll fall back to chain building,
        // which may let us chain through another variant of this certificate and build a valid chain. This is a very
        // deliberate choice: certificates that assert the same combination of (subject, public key, SAN) but different
        // extensions or policies should not be tolerated by this check, and will be ignored.
        if self.rootCertificates.contains(leafCertificate) {
            let unverifiedChain = UnverifiedCertificateChain([leafCertificate])

            switch await self.policy.chainMeetsPolicyRequirements(chain: unverifiedChain) {
            case .meetsPolicy:
                // We're good!
                return .validCertificate(unverifiedChain.certificates)

            case .failsToMeetPolicy(reason: let reason):
                policyFailures.append(VerificationResult.PolicyFailure(chain: unverifiedChain, policyFailureReason: reason))
            }
        }

        // This is essentially a DFS of the certificate tree. We attempt to iteratively build up possible chains.
        while let nextPartialCandidate = partialChains.popLast() {
            // We want to search for parents. Our preferred parent comes from the root store, as this will potentially
            // produce smaller chains.
            if var rootParents = rootCertificates[nextPartialCandidate.currentTip.issuer] {
                // We then want to sort by suitability.
                rootParents.sortBySuitabilityForIssuing(certificate: nextPartialCandidate.currentTip)

                // Each of these is now potentially a valid unverified chain.
                for root in rootParents {
                    if self.shouldSkipAddingCertificate(partialChain: nextPartialCandidate, nextCertificate: root) {
                        continue
                    }

                    let unverifiedChain = UnverifiedCertificateChain(chain: nextPartialCandidate, root: root)

                    switch await self.policy.chainMeetsPolicyRequirements(chain: unverifiedChain) {
                    case .meetsPolicy:
                        // We're good!
                        return .validCertificate(unverifiedChain.certificates)

                    case .failsToMeetPolicy(reason: let reason):
                        policyFailures.append(VerificationResult.PolicyFailure(chain: unverifiedChain, policyFailureReason: reason))
                    }
                }
            }

            if var intermediateParents = intermediates[nextPartialCandidate.currentTip.issuer] {
                // We then want to sort by suitability.
                intermediateParents.sortBySuitabilityForIssuing(certificate: nextPartialCandidate.currentTip)

                for parent in intermediateParents {
                    if self.shouldSkipAddingCertificate(partialChain: nextPartialCandidate, nextCertificate: parent) {
                        continue
                    }

                    let nextChain = nextPartialCandidate.appending(parent)
                    partialChains.append(nextChain)
                }
            }
        }

        return .couldNotValidate(policyFailures)
    }

    private func shouldSkipAddingCertificate(partialChain: CandidatePartialChain, nextCertificate: Certificate) -> Bool {
        // We want to confirm that the certificate has no unhandled critical extensions. If it does, we can't build the chain.
        if nextCertificate.hasUnhandledCriticalExtensions(handledExtensions: self.policy.verifyingCriticalExtensions) {
            return true
        }

        // We don't want to re-add the same certificate to the chain: that will always produce a chain that
        // could have been shorter.
        if partialChain.contains(certificate: nextCertificate) {
            return true
        }

        // We check the signature here: if the signature isn't valid, don't try to apply policy.
        guard nextCertificate.publicKey.isValidSignature(partialChain.currentTip.signature, for: partialChain.currentTip) else {
            return true
        }

        return false
    }
}

public enum VerificationResult: Hashable, Sendable {
    case validCertificate([Certificate])
    case couldNotValidate([PolicyFailure])
}

extension VerificationResult {
    public struct PolicyFailure: Hashable, Sendable {
        public var chain: UnverifiedCertificateChain
        public var policyFailureReason: String

        @inlinable
        public init(chain: UnverifiedCertificateChain, policyFailureReason: String) {
            self.chain = chain
            self.policyFailureReason = policyFailureReason
        }
    }
}

fileprivate struct CandidatePartialChain {
    var chain: [Certificate]

    var currentTip: Certificate

    init(leaf: Certificate) {
        self.chain = []
        self.currentTip = leaf
    }

    /// Whether this partial chain already contains this certificate.
    func contains(certificate: Certificate) -> Bool {
        // We don't do direct equality, as RFC 4158 § 2.4.1 notes that even certs that aren't
        // bytewise equal can cause arbitrarily long trust paths and weird loops. In particular, we're
        // worried about mutual cross-signatures, where CA X and CA Y have cross-signed one another. In such
        // a case, we can end up producing inefficient chains that pass through either or both CAs multiple times,
        // when they only needed to do so once.
        //
        // Instead, we consider a path to "contain" a certificate when the following things match:
        //
        // 1. Subject
        // 2. Public Key
        // 3. SAN (including presence or absence)
        //
        // This criteria is motivated by RFC 4158 § 5.2 (loop detection)
        func match(_ left: Certificate, _ right: Certificate) -> Bool {
            (
                left.subject == right.subject &&
                left.publicKey == right.publicKey &&
                left.extensions.subjectAlternativeNameBytes == right.extensions.subjectAlternativeNameBytes
            )
        }

        return (
            self.chain.contains(where: { match($0, certificate) }) ||
            match(self.currentTip, certificate)
        )
    }

    func appending(_ newElement: Certificate) -> CandidatePartialChain {
        var newChain = self
        newChain.chain.append(newChain.currentTip)
        newChain.currentTip = newElement
        return newChain
    }
}

extension Array where Element == Certificate {
    fileprivate mutating func sortBySuitabilityForIssuing(certificate: Certificate) {
        // First, an early exit. If the subject doesn't have an AKI extension, we don't need
        // to do anything.
        guard let aki = try? certificate.extensions.authorityKeyIdentifier else {
            return
        }

        self.sort(by: { $0.issuerPreference(subjectAKI: aki) < $1.issuerPreference(subjectAKI: aki) })
    }
}

extension Certificate {
    func issuerPreference(subjectAKI: AuthorityKeyIdentifier) -> Int {
        guard let ski = try? self.extensions.subjectKeyIdentifier else {
            // Medium preference: we have no SKI.
            return 0
        }

        // The SKI is present. If the two match, this is higher preference: if they don't match, it's lower.
        return subjectAKI.keyIdentifier == ski.keyIdentifier ? 1 : -1
    }

    func hasUnhandledCriticalExtensions(handledExtensions: [ASN1ObjectIdentifier]) -> Bool {
        for ext in self.extensions where ext.critical {
            guard handledExtensions.contains(ext.oid) else {
                return true
            }
        }

        return false
    }
}

extension UnverifiedCertificateChain {
    fileprivate init(chain: CandidatePartialChain, root: Certificate) {
        var certificates = chain.chain
        certificates.append(chain.currentTip)
        certificates.append(root)
        self = .init(certificates)
    }
}

extension Certificate.Extensions {
    fileprivate var subjectAlternativeNameBytes: ArraySlice<UInt8>? {
        return self[oid: .X509ExtensionID.subjectAlternativeName].map { $0.value }
    }
}
