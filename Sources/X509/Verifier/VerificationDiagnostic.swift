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

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public struct VerificationDiagnostic: Sendable {
    struct LeafCertificateHasUnhandledCriticalExtensions: Hashable, Sendable {
        var leafCertificate: Certificate
        var handledCriticalExtensions: [ASN1ObjectIdentifier]
    }

    struct LeafCertificateIsInTheRootStoreButDoesNotMeetPolicy: Hashable, Sendable {
        var leafCertificate: Certificate
        var failsToMeetPolicyReason: PolicyFailureReason
    }

    struct ChainFailsToMeetPolicy: Hashable, Sendable {
        var chain: UnverifiedCertificateChain
        var failsToMeetPolicyReason: PolicyFailureReason
    }

    struct IssuerHasUnhandledCriticalExtension: Hashable, Sendable {
        var issuer: Certificate
        var partialChain: [Certificate]
        var handledCriticalExtensions: [ASN1ObjectIdentifier]
    }

    struct IssuerHasNotSignedCertificate: Hashable, Sendable {
        var issuer: Certificate
        var partialChain: [Certificate]
    }

    struct SearchingForIssuerOfPartialChain: Hashable, Sendable {
        var partialChain: [Certificate]
    }

    struct FoundCandidateIssuersOfPartialChainInRootStore: Hashable, Sendable {
        var partialChain: [Certificate]
        var issuersInRootStore: [Certificate]
    }

    struct FoundCandidateIssuersOfPartialChainInIntermediateStore: Hashable, Sendable {
        var partialChain: [Certificate]
        var issuersInIntermediateStore: [Certificate]
    }

    struct FoundValidCertificateChain: Hashable, Sendable {
        var validCertificateChain: [Certificate]
    }

    struct CouldNotValidateLeafCertificate: Hashable, Sendable {
        var leaf: Certificate
    }

    struct IssuerIsAlreadyInTheChain: Hashable, Sendable {
        var partialChain: [Certificate]
        var issuer: Certificate
    }

    /// - Note: all ``LoadingTrustRootsFailed`` are considered equal,
    /// best we can because the underlying storage type ``Error`` doesn't conform to Eqautable
    struct LoadingTrustRootsFailed: Hashable, Sendable {
        var error: any Error

        static func == (lhs: Self, rhs: Self) -> Bool {
            true
        }
        func hash(into hasher: inout Hasher) {}
    }

    enum Storage: Hashable, Sendable {
        case leafCertificateHasUnhandledCriticalExtension(LeafCertificateHasUnhandledCriticalExtensions)
        case leafCertificateIsInTheRootStoreButDoesNotMeetPolicy(LeafCertificateIsInTheRootStoreButDoesNotMeetPolicy)
        case chainFailsToMeetPolicy(ChainFailsToMeetPolicy)
        case issuerHashUnhandledCriticalExtension(IssuerHasUnhandledCriticalExtension)
        case issuerHasNotSignedCertificate(IssuerHasNotSignedCertificate)
        case searchingForIssuerOfPartialChain(SearchingForIssuerOfPartialChain)
        case foundCandidateIssuersOfPartialChainInRootStore(FoundCandidateIssuersOfPartialChainInRootStore)
        case foundCandidateIssuersOfPartialChainInIntermediateStore(
            FoundCandidateIssuersOfPartialChainInIntermediateStore
        )
        case foundValidCertificateChain(FoundValidCertificateChain)
        case couldNotValidateLeafCertificate(CouldNotValidateLeafCertificate)
        case issuerIsAlreadyInTheChain(IssuerIsAlreadyInTheChain)
        case loadingTrustRootsFailed(LoadingTrustRootsFailed)
    }

    var storage: Storage
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension VerificationDiagnostic {
    static func leafCertificateHasUnhandledCriticalExtension(
        _ leafCertificate: Certificate,
        handledCriticalExtensions: [ASN1ObjectIdentifier]
    ) -> Self {
        self.init(
            storage: .leafCertificateHasUnhandledCriticalExtension(
                leafCertificate,
                handledCriticalExtensions: handledCriticalExtensions
            )
        )
    }

    static func leafCertificateIsInTheRootStoreButDoesNotMeetPolicy(
        _ leafCertificate: Certificate,
        reason failsToMeetPolicyReason: PolicyFailureReason
    ) -> Self {
        self.init(
            storage: .leafCertificateIsInTheRootStoreButDoesNotMeetPolicy(
                leafCertificate,
                reason: failsToMeetPolicyReason
            )
        )
    }

    static func chainFailsToMeetPolicy(
        _ chain: UnverifiedCertificateChain,
        reason failsToMeetPolicyReason: PolicyFailureReason
    ) -> Self {
        self.init(
            storage: .chainFailsToMeetPolicy(
                chain,
                reason: failsToMeetPolicyReason
            )
        )
    }

    static func issuerHasUnhandledCriticalExtension(
        issuer: Certificate,
        chain: CandidatePartialChain,
        handledCriticalExtensions: [ASN1ObjectIdentifier]
    ) -> Self {
        self.init(
            storage: .issuerHasUnhandledCriticalExtension(
                issuer: issuer,
                partialChain: chain.chain + CollectionOfOne(chain.currentTip),
                handledCriticalExtensions: handledCriticalExtensions
            )
        )
    }

    static func issuerHasNotSignedCertificate(
        _ issuer: Certificate,
        chain: CandidatePartialChain
    ) -> Self {
        self.init(
            storage: .issuerHasNotSignedCertificate(
                issuer,
                partialChain: chain.chain + CollectionOfOne(chain.currentTip)
            )
        )
    }

    static func searchingForIssuerOfPartialChain(
        _ partialChain: CandidatePartialChain
    ) -> Self {
        .init(storage: .searchingForIssuerOfPartialChain(partialChain.chain + CollectionOfOne(partialChain.currentTip)))
    }

    static func foundCandidateIssuersOfPartialChainInRootStore(
        _ partialChain: CandidatePartialChain,
        issuers issuersInRootStore: [Certificate]
    ) -> Self {
        .init(
            storage: .foundCandidateIssuersOfPartialChainInRootStore(
                partialChain.chain + CollectionOfOne(partialChain.currentTip),
                issuers: issuersInRootStore
            )
        )
    }

    static func foundCandidateIssuersOfPartialChainInIntermediateStore(
        _ partialChain: CandidatePartialChain,
        issuers issuersInIntermediateStore: [Certificate]
    ) -> Self {
        .init(
            storage: .foundCandidateIssuersOfPartialChainInIntermediateStore(
                partialChain.chain + CollectionOfOne(partialChain.currentTip),
                issuers: issuersInIntermediateStore
            )
        )
    }

    static func foundValidCertificateChain(
        _ validCertificateChain: [Certificate]
    ) -> Self {
        .init(storage: .foundValidCertificateChain(validCertificateChain))
    }

    static func couldNotValidateLeafCertificate(
        _ leaf: Certificate
    ) -> Self {
        .init(storage: .couldNotValidateLeafCertificate(leaf))
    }

    static func issuerIsAlreadyInTheChain(
        _ partialChain: CandidatePartialChain,
        issuer: Certificate
    ) -> Self {
        .init(
            storage: .issuerIsAlreadyInTheChain(
                partialChain.chain + CollectionOfOne(partialChain.currentTip),
                issuer: issuer
            )
        )
    }

    @usableFromInline
    static func loadingTrustRootsFailed(
        _ error: any Error
    ) -> Self {
        .init(storage: .loadingTrustRootsFailed(error))
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension VerificationDiagnostic.Storage {
    static func leafCertificateHasUnhandledCriticalExtension(
        _ leafCertificate: Certificate,
        handledCriticalExtensions: [ASN1ObjectIdentifier]
    ) -> Self {
        .leafCertificateHasUnhandledCriticalExtension(
            .init(
                leafCertificate: leafCertificate,
                handledCriticalExtensions: handledCriticalExtensions
            )
        )
    }

    static func leafCertificateIsInTheRootStoreButDoesNotMeetPolicy(
        _ leafCertificate: Certificate,
        reason failsToMeetPolicyReason: PolicyFailureReason
    ) -> Self {
        .leafCertificateIsInTheRootStoreButDoesNotMeetPolicy(
            .init(
                leafCertificate: leafCertificate,
                failsToMeetPolicyReason: failsToMeetPolicyReason
            )
        )
    }

    static func chainFailsToMeetPolicy(
        _ chain: UnverifiedCertificateChain,
        reason failsToMeetPolicyReason: PolicyFailureReason
    ) -> Self {
        .chainFailsToMeetPolicy(
            .init(
                chain: chain,
                failsToMeetPolicyReason: failsToMeetPolicyReason
            )
        )
    }

    static func issuerHasUnhandledCriticalExtension(
        issuer: Certificate,
        partialChain: [Certificate],
        handledCriticalExtensions: [ASN1ObjectIdentifier]
    ) -> Self {
        .issuerHashUnhandledCriticalExtension(
            .init(
                issuer: issuer,
                partialChain: partialChain,
                handledCriticalExtensions: handledCriticalExtensions
            )
        )
    }

    static func issuerHasNotSignedCertificate(
        _ issuer: Certificate,
        partialChain: [Certificate]
    ) -> Self {
        .issuerHasNotSignedCertificate(
            .init(
                issuer: issuer,
                partialChain: partialChain
            )
        )
    }

    static func searchingForIssuerOfPartialChain(
        _ partialChain: [Certificate]
    ) -> Self {
        .searchingForIssuerOfPartialChain(.init(partialChain: partialChain))
    }

    static func foundCandidateIssuersOfPartialChainInRootStore(
        _ partialChain: [Certificate],
        issuers issuersInRootStore: [Certificate]
    ) -> Self {
        .foundCandidateIssuersOfPartialChainInRootStore(
            .init(
                partialChain: partialChain,
                issuersInRootStore: issuersInRootStore
            )
        )
    }

    static func foundCandidateIssuersOfPartialChainInIntermediateStore(
        _ partialChain: [Certificate],
        issuers issuersInIntermediateStore: [Certificate]
    ) -> Self {
        .foundCandidateIssuersOfPartialChainInIntermediateStore(
            .init(
                partialChain: partialChain,
                issuersInIntermediateStore: issuersInIntermediateStore
            )
        )
    }

    static func foundValidCertificateChain(
        _ validCertificateChain: [Certificate]
    ) -> Self {
        .foundValidCertificateChain(.init(validCertificateChain: validCertificateChain))
    }

    static func couldNotValidateLeafCertificate(
        _ leaf: Certificate
    ) -> Self {
        .couldNotValidateLeafCertificate(.init(leaf: leaf))
    }

    static func issuerIsAlreadyInTheChain(
        _ partialChain: [Certificate],
        issuer: Certificate
    ) -> Self {
        .issuerIsAlreadyInTheChain(.init(partialChain: partialChain, issuer: issuer))
    }

    static func loadingTrustRootsFailed(
        _ error: any Error
    ) -> Self {
        .loadingTrustRootsFailed(.init(error: error))
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.Extensions {
    @inlinable
    func unhandledCriticalExtensions(
        for handledCriticalExtensions: [ASN1ObjectIdentifier]
    ) -> some Sequence<Certificate.Extension> {
        self.lazy.filter { ext in
            ext.critical && !handledCriticalExtensions.contains(ext.oid)
        }
    }
}

// MARK: CustomStringConvertible

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension VerificationDiagnostic: CustomStringConvertible {
    /// Produces a human readable description of this ``VerificationDiagnostic`` that is potentially expensive to compute.
    public var description: String {
        String(describing: storage)
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension VerificationDiagnostic.Storage: CustomStringConvertible {
    var description: String {
        switch self {
        case .leafCertificateHasUnhandledCriticalExtension(let diagnostic): return String(describing: diagnostic)
        case .leafCertificateIsInTheRootStoreButDoesNotMeetPolicy(let diagnostic): return String(describing: diagnostic)
        case .chainFailsToMeetPolicy(let diagnostic): return String(describing: diagnostic)
        case .issuerHashUnhandledCriticalExtension(let diagnostic): return String(describing: diagnostic)
        case .issuerHasNotSignedCertificate(let diagnostic): return String(describing: diagnostic)
        case .searchingForIssuerOfPartialChain(let diagnostic): return String(describing: diagnostic)
        case .foundCandidateIssuersOfPartialChainInRootStore(let diagnostic): return String(describing: diagnostic)
        case .foundCandidateIssuersOfPartialChainInIntermediateStore(let diagnostic):
            return String(describing: diagnostic)
        case .foundValidCertificateChain(let diagnostic): return String(describing: diagnostic)
        case .couldNotValidateLeafCertificate(let diagnostic): return String(describing: diagnostic)
        case .issuerIsAlreadyInTheChain(let diagnostic): return String(describing: diagnostic)
        case .loadingTrustRootsFailed(let diagnostic): return String(describing: diagnostic)
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension VerificationDiagnostic.LeafCertificateHasUnhandledCriticalExtensions: CustomStringConvertible {
    var description: String {
        """
        The leaf certificate has critical extensions that the policy does not understand and therefore can't enforce. \
        Unhandled extensions: \
        [\(self.leafCertificate.extensions.unhandledCriticalExtensions(
            for: self.handledCriticalExtensions
        ).lazy.map { String(reflecting: $0) }.joined(separator: ", "))] \
        Leaf certificate: \
        \(String(describing: self.leafCertificate))
        """
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension VerificationDiagnostic.LeafCertificateIsInTheRootStoreButDoesNotMeetPolicy: CustomStringConvertible {
    var description: String {
        """
        Leaf certificate is in the root store of the verifier but it does by itself not meet the policy. \
        Reason: \
        \(String(reflecting: self.failsToMeetPolicyReason)) \
        Leaf Certificate: \
        \(String(reflecting: self.leafCertificate))
        """
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension VerificationDiagnostic.ChainFailsToMeetPolicy: CustomStringConvertible {
    var description: String {
        """
        A certificate chain to a certificate in the root store was found but it does not meet the policy. \
        Reason: \
        \(String(reflecting: self.failsToMeetPolicyReason)) \
        Chain (from leaf to root): \
        [\(self.chain.lazy.map { String(reflecting: $0) }.joined(separator: ","))]
        """
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension VerificationDiagnostic.IssuerHasUnhandledCriticalExtension: CustomStringConvertible {
    var description: String {
        """
        A candidate issuer of a certificate in the (partial) chain has critical extensions that the policy does not understand and therefore can't enforce. \
        Unhandled extensions: \
        [\(self.issuer.extensions.unhandledCriticalExtensions(
            for: self.handledCriticalExtensions
        ).lazy.map { "- \(String(reflecting: $0))" }.joined(separator: ", "))] \
        Chain (from leaf to candidate issuer that has critical extensions the policy doesn't enforce): \
        [\(self.partialChain.lazy.map { String(reflecting: $0) }.joined(separator: ", ")), \
        \(issuer.description)]
        """
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension VerificationDiagnostic.IssuerHasNotSignedCertificate: CustomStringConvertible {
    var description: String {
        """
        A candidate issuer of a certificate in the (partial) chain has not signed the previous certificate in the chain. \
        Chain (from leaf to candidate issuer that has not signed the certificate before it): \
        [\(self.partialChain.lazy.map { String(reflecting: $0) }.joined(separator: ", ")), \
        \(String(reflecting: issuer))]
        """
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension VerificationDiagnostic.SearchingForIssuerOfPartialChain: CustomStringConvertible {
    var description: String {
        """
        Searching for issuers of partial candidate chain. \
        Chain (from leaf to tip): \
        \(String(reflecting: self.partialChain))
        """
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension VerificationDiagnostic.FoundCandidateIssuersOfPartialChainInRootStore: CustomStringConvertible {
    var description: String {
        """
        Found candidate issuers in the root store of the partial chain. \
        Chain (from leaf to tip): \
        \(String(reflecting: self.partialChain)) \
        Candidate issuers in the root store: \
        \(String(reflecting: self.issuersInRootStore))
        """
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension VerificationDiagnostic.FoundCandidateIssuersOfPartialChainInIntermediateStore: CustomStringConvertible {
    var description: String {
        """
        Found candidate issuers in the intermediate store of the partial chain. \
        Chain (from leaf to tip): \
        \(String(reflecting: self.partialChain)) \
        Candidate issuers in the intermediate store: \
        \(String(reflecting: self.issuersInIntermediateStore))
        """
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension VerificationDiagnostic.FoundValidCertificateChain: CustomStringConvertible {
    var description: String {
        """
        Validation completed successfully. \
        Verified certificate chain (from leaf to root): \
        \(String(reflecting: self.validCertificateChain))
        """
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension VerificationDiagnostic.CouldNotValidateLeafCertificate: CustomStringConvertible {
    var description: String {
        """
        Could not validate leaf certificate: \
        \(String(reflecting: self.leaf))
        """
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension VerificationDiagnostic.IssuerIsAlreadyInTheChain: CustomStringConvertible {
    var description: String {
        """
        Candidate issuer is already in partial chain and is therefore skipped because it would always produce a chain that could have been shorter. \
        Partial chain (from leaf to tip): \
        \(String(reflecting: self.partialChain)) \
        Candidate issuer which is already in the chain above: \
        \(String(reflecting: self.issuer))
        """
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension VerificationDiagnostic.LoadingTrustRootsFailed: CustomStringConvertible {
    var description: String {
        """
        Loading system trust roots has failed: \(String(reflecting: self.error))
        """
    }
}

// MARK: CustomDebugStringConvertible

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension VerificationDiagnostic: CustomDebugStringConvertible {
    public var debugDescription: String {
        // this just adds quotes around the string and escapes any characters not suitable for displaying in a structural display.
        String(reflecting: String(describing: self))
    }
}

// MARK: Multiline Description

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension VerificationDiagnostic {
    /// Produces a human readable description of this ``VerificationDiagnostic`` over multiple lines for better readability
    /// but includes otherwise the same information as ``description``.
    public var multilineDescription: String {
        self.storage.multilineDescription
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension VerificationDiagnostic.Storage {
    var multilineDescription: String {
        switch self {
        case .leafCertificateHasUnhandledCriticalExtension(let diagnostic): return diagnostic.multilineDescription
        case .leafCertificateIsInTheRootStoreButDoesNotMeetPolicy(let diagnostic):
            return diagnostic.multilineDescription
        case .chainFailsToMeetPolicy(let diagnostic): return diagnostic.multilineDescription
        case .issuerHashUnhandledCriticalExtension(let diagnostic): return diagnostic.multilineDescription
        case .issuerHasNotSignedCertificate(let diagnostic): return diagnostic.multilineDescription
        case .searchingForIssuerOfPartialChain(let diagnostic): return diagnostic.multilineDescription
        case .foundCandidateIssuersOfPartialChainInRootStore(let diagnostic): return diagnostic.multilineDescription
        case .foundCandidateIssuersOfPartialChainInIntermediateStore(let diagnostic):
            return diagnostic.multilineDescription
        case .foundValidCertificateChain(let diagnostic): return diagnostic.multilineDescription
        case .couldNotValidateLeafCertificate(let diagnostic): return diagnostic.multilineDescription
        case .issuerIsAlreadyInTheChain(let diagnostic): return diagnostic.multilineDescription
        case .loadingTrustRootsFailed(let diagnostic): return diagnostic.multilineDescription
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension VerificationDiagnostic.LeafCertificateHasUnhandledCriticalExtensions {
    var multilineDescription: String {
        """
        The leaf certificate has critical extensions that the policy does not understand and therefore can't enforce.

        Unhandled extensions:
        \(self.leafCertificate.extensions.unhandledCriticalExtensions(
            for: self.handledCriticalExtensions
        ).lazy.map { String(reflecting: $0) }.joined(separator: "\n"))

        Leaf certificate:
        \(String(reflecting: self.leafCertificate))
        """
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension VerificationDiagnostic.LeafCertificateIsInTheRootStoreButDoesNotMeetPolicy {
    var multilineDescription: String {
        """
        Leaf certificate is in the root store of the verifier but it does by itself not meet the policy.

        Reason:
        \(String(reflecting: self.failsToMeetPolicyReason))

        Leaf Certificate:
        \(String(reflecting: self.leafCertificate))
        """
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension VerificationDiagnostic.ChainFailsToMeetPolicy {
    var multilineDescription: String {
        """
        A certificate chain to a certificate in the root store was found but it does not meet the policy.

        Reason:
        \(String(reflecting: self.failsToMeetPolicyReason))

        Chain (from leaf to root):
        \(self.chain.lazy.map { String(reflecting: $0) }.joined(separator: "\n"))
        """
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension VerificationDiagnostic.IssuerHasUnhandledCriticalExtension {
    var multilineDescription: String {
        """
        A candidate issuer of a certificate in the (partial) chain has critical extensions that the policy does not understand and therefore can't enforce.

        Unhandled extensions:
        \(self.issuer.extensions.unhandledCriticalExtensions(
            for: self.handledCriticalExtensions
        ).lazy.map { "- \(String(reflecting: $0))" }.joined(separator: "\n"))

        Chain (from leaf to candidate issuer that has critical extensions the policy doesn't enforce):
        \(self.partialChain.lazy.map { String(reflecting: $0) }.joined(separator: "\n"))
        \(String(reflecting: issuer))
        """
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension VerificationDiagnostic.IssuerHasNotSignedCertificate {
    var multilineDescription: String {
        """
        A candidate issuer of a certificate in the (partial) chain has not signed the previous certificate in the chain.

        Chain (from leaf to candidate issuer that has not signed the certificate before it):
        \(self.partialChain.lazy.map { String(reflecting: $0) }.joined(separator: "\n"))
        \(String(reflecting: self.issuer))
        """
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension VerificationDiagnostic.SearchingForIssuerOfPartialChain {
    var multilineDescription: String {
        """
        Searching for issuers of partial candidate chain.
        Chain (from leaf to tip):
        \(self.partialChain.lazy.map { String(reflecting: $0) }.joined(separator: "\n"))
        """
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension VerificationDiagnostic.FoundCandidateIssuersOfPartialChainInRootStore {
    var multilineDescription: String {
        """
        Found candidate issuers in the root store of the partial chain.
        Chain (from leaf to tip):
        \(self.partialChain.lazy.map { String(reflecting: $0) }.joined(separator: "\n"))
        Candidate issuers in the root store:
        \(self.issuersInRootStore.lazy.map { String(reflecting: $0) }.joined(separator: "\n"))
        """
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension VerificationDiagnostic.FoundCandidateIssuersOfPartialChainInIntermediateStore {
    var multilineDescription: String {
        """
        Found candidate issuers in the intermediate store of the partial chain.
        Chain (from leaf to tip):
        \(self.partialChain.lazy.map { String(reflecting: $0) }.joined(separator: "\n"))
        Candidate issuers in the intermediate store:
        \(self.issuersInIntermediateStore.lazy.map { String(reflecting: $0) }.joined(separator: "\n"))
        """
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension VerificationDiagnostic.FoundValidCertificateChain {
    var multilineDescription: String {
        """
        Validation completed successfully.
        Verified certificate chain (from leaf to root):
        \(self.validCertificateChain.lazy.map { String(reflecting: $0) }.joined(separator: "\n"))
        """
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension VerificationDiagnostic.CouldNotValidateLeafCertificate {
    var multilineDescription: String {
        """
        Could not validate leaf certificate:
        \(String(reflecting: self.leaf))
        """
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension VerificationDiagnostic.IssuerIsAlreadyInTheChain {
    var multilineDescription: String {
        """
        Candidate issuer is already in partial chain and is therefore skipped because it would always produce a chain that could have been shorter.
        Partial chain (from leaf to tip):
        \(self.partialChain.lazy.map { String(reflecting: $0) }.joined(separator: "\n"))
        Candidate issuer which is already in the chain above:
        \(String(reflecting: self.issuer))
        """
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension VerificationDiagnostic.LoadingTrustRootsFailed {
    var multilineDescription: String {
        """
        Loading system trust roots has failed: 
        \(String(reflecting: self.error))
        """
    }
}
