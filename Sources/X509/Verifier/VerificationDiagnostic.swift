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

public struct VerificationDiagnostic: Sendable {
    struct LeafCertificateHasUnhandledCriticalExtensions: Hashable, Sendable {
        var leafCertificate: Certificate
        var handledCriticalExtensions: [ASN1ObjectIdentifier]
    }
    
    struct LeafCertificateIsInTheRootStoreButDoesNotMeetPolicy: Hashable, Sendable {
        var leafCertificate: Certificate
        var failsToMeetPolicyReason: String
    }
    
    struct ChainFailsToMeetPolicy: Hashable, Sendable {
        var chain: UnverifiedCertificateChain
        var failsToMeetPolicyReason: String
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
    
    enum Storage: Hashable, Sendable {
        case leafCertificateHasUnhandledCriticalExtension(LeafCertificateHasUnhandledCriticalExtensions)
        case leafCertificateIsInTheRootStoreButDoesNotMeetPolicy(LeafCertificateIsInTheRootStoreButDoesNotMeetPolicy)
        case chainFailsToMeetPolicy(ChainFailsToMeetPolicy)
        case issuerHashUnhandledCriticalExtension(IssuerHasUnhandledCriticalExtension)
        case issuerHasNotSignedCertificate(IssuerHasNotSignedCertificate)
        case searchingForIssuerOfPartialChain(SearchingForIssuerOfPartialChain)
        case foundCandidateIssuersOfPartialChainInRootStore(FoundCandidateIssuersOfPartialChainInRootStore)
        case foundCandidateIssuersOfPartialChainInIntermediateStore(FoundCandidateIssuersOfPartialChainInIntermediateStore)
        case foundValidCertificateChain(FoundValidCertificateChain)
        case couldNotValidateLeafCertificate(CouldNotValidateLeafCertificate)
    }
    
    var storage: Storage
}

extension VerificationDiagnostic {
    static func leafCertificateHasUnhandledCriticalExtension(
        _ leafCertificate: Certificate,
        handledCriticalExtensions: [ASN1ObjectIdentifier]
    ) -> Self {
        self.init(storage: .leafCertificateHasUnhandledCriticalExtension(
            leafCertificate,
            handledCriticalExtensions: handledCriticalExtensions
        ))
    }
    
    static func leafCertificateIsInTheRootStoreButDoesNotMeetPolicy(
        _ leafCertificate: Certificate,
        reason failsToMeetPolicyReason: String
    ) -> Self {
        self.init(storage: .leafCertificateIsInTheRootStoreButDoesNotMeetPolicy(
            leafCertificate,
            reason: failsToMeetPolicyReason
        ))
    }
    
    static func chainFailsToMeetPolicy(
        _ chain: UnverifiedCertificateChain,
        reason failsToMeetPolicyReason: String
    ) -> Self {
        self.init(storage: .chainFailsToMeetPolicy(
            chain,
            reason: failsToMeetPolicyReason
        ))
    }
    
    static func issuerHasUnhandledCriticalExtension(
        issuer: Certificate,
        chain: CandidatePartialChain,
        handledCriticalExtensions: [ASN1ObjectIdentifier]
    ) -> Self {
        self.init(storage: .issuerHasUnhandledCriticalExtension(
            issuer: issuer,
            partialChain: chain.chain + CollectionOfOne(chain.currentTip),
            handledCriticalExtensions: handledCriticalExtensions
        ))
    }
    
    static func issuerHasNotSignedCertificate(
        _ issuer: Certificate,
        chain: CandidatePartialChain
    ) -> Self {
        self.init(storage: .issuerHasNotSignedCertificate(
            issuer,
            partialChain: chain.chain + CollectionOfOne(chain.currentTip)
        ))
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
        .init(storage: .foundCandidateIssuersOfPartialChainInRootStore(
            partialChain.chain + CollectionOfOne(partialChain.currentTip),
            issuers: issuersInRootStore
        ))
    }
    
    static func foundCandidateIssuersOfPartialChainInIntermediateStore(
        _ partialChain: CandidatePartialChain,
        issuers issuersInIntermediateStore: [Certificate]
    ) -> Self {
        .init(storage: .foundCandidateIssuersOfPartialChainInIntermediateStore(
            partialChain.chain + CollectionOfOne(partialChain.currentTip),
            issuers: issuersInIntermediateStore
        ))
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
}

extension VerificationDiagnostic.Storage {
    static func leafCertificateHasUnhandledCriticalExtension(
        _ leafCertificate: Certificate,
        handledCriticalExtensions: [ASN1ObjectIdentifier]
    ) -> Self {
        .leafCertificateHasUnhandledCriticalExtension(.init(
            leafCertificate: leafCertificate,
            handledCriticalExtensions: handledCriticalExtensions
        ))
    }
    
    static func leafCertificateIsInTheRootStoreButDoesNotMeetPolicy(
        _ leafCertificate: Certificate,
        reason failsToMeetPolicyReason: String
    ) -> Self {
        .leafCertificateIsInTheRootStoreButDoesNotMeetPolicy(.init(
            leafCertificate: leafCertificate,
            failsToMeetPolicyReason: failsToMeetPolicyReason
        ))
    }
    
    static func chainFailsToMeetPolicy(
        _ chain: UnverifiedCertificateChain,
        reason failsToMeetPolicyReason: String
    ) -> Self {
        .chainFailsToMeetPolicy(.init(
            chain: chain,
            failsToMeetPolicyReason: failsToMeetPolicyReason
        ))
    }
    
    static func issuerHasUnhandledCriticalExtension(
        issuer: Certificate,
        partialChain: [Certificate],
        handledCriticalExtensions: [ASN1ObjectIdentifier]
    ) -> Self {
        .issuerHashUnhandledCriticalExtension(.init(
            issuer: issuer,
            partialChain: partialChain,
            handledCriticalExtensions: handledCriticalExtensions
        ))
    }
    
    static func issuerHasNotSignedCertificate(
        _ issuer: Certificate,
        partialChain: [Certificate]
    ) -> Self {
        .issuerHasNotSignedCertificate(.init(
            issuer: issuer,
            partialChain: partialChain
        ))
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
        .foundCandidateIssuersOfPartialChainInRootStore(.init(
            partialChain: partialChain,
            issuersInRootStore: issuersInRootStore
        ))
    }
    
    static func foundCandidateIssuersOfPartialChainInIntermediateStore(
        _ partialChain: [Certificate],
        issuers issuersInIntermediateStore: [Certificate]
    ) -> Self {
        .foundCandidateIssuersOfPartialChainInIntermediateStore(.init(
            partialChain: partialChain,
            issuersInIntermediateStore: issuersInIntermediateStore
        ))
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
}

extension Certificate.Extensions {
    @inlinable
    func unhandledCriticalExtensions(for handledCriticalExtensions: [ASN1ObjectIdentifier]) -> some Sequence<Certificate.Extension> {
        self.lazy.filter { ext in
            ext.critical && !handledCriticalExtensions.contains(ext.oid)
        }
    }
}

// MARK: CustomStringConvertible

extension VerificationDiagnostic: CustomStringConvertible {
    /// Produces a human readable description of this ``VerificationDiagnostic`` that is potentially expensive to compute.
    public var description: String {
        String(describing: storage)
    }
}

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
        case .foundCandidateIssuersOfPartialChainInIntermediateStore(let diagnostic): return String(describing: diagnostic)
        case .foundValidCertificateChain(let diagnostic): return String(describing: diagnostic)
        case .couldNotValidateLeafCertificate(let diagnostic): return String(describing: diagnostic)
        }
    }
}

extension VerificationDiagnostic.LeafCertificateHasUnhandledCriticalExtensions: CustomStringConvertible {
    var description: String {
        """
        The leaf certificate has critical extensions that the policy does not understand and therefore can't enforce. \
        Unhandled extensions: \
        [\(self.leafCertificate.extensions.unhandledCriticalExtensions(
            for: self.handledCriticalExtensions
        ).lazy.map { String(describing: $0) }.joined(separator: ", "))] \
        Leaf certificate: \
        \(String(describing: self.leafCertificate))
        """
    }
}

extension VerificationDiagnostic.LeafCertificateIsInTheRootStoreButDoesNotMeetPolicy: CustomStringConvertible {
    var description: String {
        """
        Leaf certificate is in the root store of the verifier but it does by itself not meet the policy. \
        Reason: \
        \(self.failsToMeetPolicyReason) \
        Leaf Certificate: \
        \(String(describing: self.leafCertificate))
        """
    }
}

extension VerificationDiagnostic.ChainFailsToMeetPolicy: CustomStringConvertible {
    var description: String {
        """
        A certificate chain to a certificate in the root store was found but it does not meet the policy. \
        Reason: \
        \(self.failsToMeetPolicyReason) \
        Chain (from leaf to root): \
        [\(self.chain.lazy.map { String(describing: $0) }.joined(separator: ","))]
        """
    }
}

extension VerificationDiagnostic.IssuerHasUnhandledCriticalExtension: CustomStringConvertible {
    var description: String {
        """
        A candidate issuer of a certificate in the (partial) chain has critical extensions that the policy does not understand and therefore can't enforce. \
        Unhandled extensions: \
        [\(self.issuer.extensions.unhandledCriticalExtensions(
            for: self.handledCriticalExtensions
        ).lazy.map { "- \($0.description)" }.joined(separator: ", "))] \
        Chain (from leaf to candidate issuer that has critical extensions the policy doesn't enforce): \
        [\(self.partialChain.lazy.map { String(describing: $0) }.joined(separator: ", ")), \
        \(issuer.description)]
        """
    }
}

extension VerificationDiagnostic.IssuerHasNotSignedCertificate: CustomStringConvertible {
    var description: String {
        """
        A candidate issuer of a certificate in the (partial) chain has not signed the previous certificate in the chain. \
        Chain (from leaf to candidate issuer that has not signed the certificate before it): \
        [\(self.partialChain.lazy.map { String(describing: $0) }.joined(separator: ", ")), \
        \(issuer.description)]
        """
    }
}

extension VerificationDiagnostic.SearchingForIssuerOfPartialChain: CustomStringConvertible {
    var description: String {
        """
        Searching for issuers of partial candidate chain. \
        Chain (from leaf to tip): \
        \(self.partialChain)
        """
    }
}

extension VerificationDiagnostic.FoundCandidateIssuersOfPartialChainInRootStore: CustomStringConvertible {
    var description: String {
        """
        Found candidate issuers in the root store of the partial chain. \
        Chain (from leaf to tip): \
        \(self.partialChain) \
        Candidate issuers in the root store: \
        \(self.issuersInRootStore)
        """
    }
}

extension VerificationDiagnostic.FoundCandidateIssuersOfPartialChainInIntermediateStore: CustomStringConvertible {
    var description: String {
        """
        Found candidate issuers in the intermediate store of the partial chain. \
        Chain (from leaf to tip): \
        \(self.partialChain) \
        Candidate issuers in the intermediate store: \
        \(self.issuersInIntermediateStore)
        """
    }
}

extension VerificationDiagnostic.FoundValidCertificateChain: CustomStringConvertible {
    var description: String {
        """
        Validation completed successfully. \
        Verified certificate chain (from leaf to root): \
        \(self.validCertificateChain)
        """
    }
}


extension VerificationDiagnostic.CouldNotValidateLeafCertificate: CustomStringConvertible {
    var description: String {
        """
        Could not validate leaf certificate: \
        \(self.leaf)
        """
    }
}


// MARK: CustomDebugStringConvertible

extension VerificationDiagnostic: CustomDebugStringConvertible {
    /// Produces a human readable description of this ``VerificationDiagnostic`` that is potentially expensive to compute.
    public var debugDescription: String {
        String(reflecting: self.storage)
    }
}

extension VerificationDiagnostic.Storage: CustomDebugStringConvertible {
    var debugDescription: String {
        switch self {
        case .leafCertificateHasUnhandledCriticalExtension(let diagnostic): return String(reflecting: diagnostic)
        case .leafCertificateIsInTheRootStoreButDoesNotMeetPolicy(let diagnostic): return String(reflecting: diagnostic)
        case .chainFailsToMeetPolicy(let diagnostic): return String(reflecting: diagnostic)
        case .issuerHashUnhandledCriticalExtension(let diagnostic): return String(reflecting: diagnostic)
        case .issuerHasNotSignedCertificate(let diagnostic): return String(reflecting: diagnostic)
        case .searchingForIssuerOfPartialChain(let diagnostic): return String(reflecting: diagnostic)
        case .foundCandidateIssuersOfPartialChainInRootStore(let diagnostic): return String(reflecting: diagnostic)
        case .foundCandidateIssuersOfPartialChainInIntermediateStore(let diagnostic): return String(reflecting: diagnostic)
        case .foundValidCertificateChain(let diagnostic): return String(reflecting: diagnostic)
        case .couldNotValidateLeafCertificate(let diagnostic): return String(reflecting: diagnostic)
        }
    }
}

extension VerificationDiagnostic.LeafCertificateHasUnhandledCriticalExtensions: CustomDebugStringConvertible {
    var debugDescription: String {
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

extension VerificationDiagnostic.LeafCertificateIsInTheRootStoreButDoesNotMeetPolicy: CustomDebugStringConvertible {
    var debugDescription: String {
        """
        Leaf certificate is in the root store of the verifier but it does by itself not meet the policy.
        
        Reason:
        \(self.failsToMeetPolicyReason)
        
        Leaf Certificate:
        \(String(reflecting: self.leafCertificate))
        """
    }
}

extension VerificationDiagnostic.ChainFailsToMeetPolicy: CustomDebugStringConvertible {
    var debugDescription: String {
        """
        A certificate chain to a certificate in the root store was found but it does not meet the policy.
        
        Reason:
        \(self.failsToMeetPolicyReason)
        
        Chain (from leaf to root):
        \(self.chain.lazy.map { String(reflecting: $0) }.joined(separator: "\n"))
        """
    }
}

extension VerificationDiagnostic.IssuerHasUnhandledCriticalExtension: CustomDebugStringConvertible {
    var debugDescription: String {
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

extension VerificationDiagnostic.IssuerHasNotSignedCertificate: CustomDebugStringConvertible {
    var debugDescription: String {
        """
        A candidate issuer of a certificate in the (partial) chain has not signed the previous certificate in the chain.
        
        Chain (from leaf to candidate issuer that has not signed the certificate before it):
        \(self.partialChain.lazy.map { String(reflecting: $0) }.joined(separator: "\n"))
        \(String(reflecting: self.issuer))
        """
    }
}

extension VerificationDiagnostic.SearchingForIssuerOfPartialChain: CustomDebugStringConvertible {
    var debugDescription: String {
        """
        Searching for issuers of partial candidate chain.
        Chain (from leaf to tip):
        \(self.partialChain.lazy.map { String(reflecting: $0) }.joined(separator: "\n"))
        """
    }
}

extension VerificationDiagnostic.FoundCandidateIssuersOfPartialChainInRootStore: CustomDebugStringConvertible {
    var debugDescription: String {
        """
        Found candidate issuers in the root store of the partial chain.
        Chain (from leaf to tip):
        \(self.partialChain.lazy.map { String(reflecting: $0) }.joined(separator: "\n"))
        Candidate issuers in the root store:
        \(self.issuersInRootStore.lazy.map { String(reflecting: $0) }.joined(separator: "\n"))
        """
    }
}

extension VerificationDiagnostic.FoundCandidateIssuersOfPartialChainInIntermediateStore: CustomDebugStringConvertible {
    var debugDescription: String {
        """
        Found candidate issuers in the intermediate store of the partial chain.
        Chain (from leaf to tip):
        \(self.partialChain.lazy.map { String(reflecting: $0) }.joined(separator: "\n"))
        Candidate issuers in the intermediate store:
        \(self.issuersInIntermediateStore.lazy.map { String(reflecting: $0) }.joined(separator: "\n"))
        """
    }
}

extension VerificationDiagnostic.FoundValidCertificateChain: CustomDebugStringConvertible {
    var debugDescription: String {
        """
        Validation completed successfully.
        Verified certificate chain (from leaf to root):
        \(self.validCertificateChain.lazy.map { String(reflecting: $0) }.joined(separator: "\n"))
        """
    }
}

extension VerificationDiagnostic.CouldNotValidateLeafCertificate: CustomDebugStringConvertible {
    var debugDescription: String {
        """
        Could not validate leaf certificate:
        \(String(reflecting: self.leaf))
        """
    }
}
