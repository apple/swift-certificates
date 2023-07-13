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
    struct LeafCertificateHasUnhandledCriticalExtensions: Hashable {
        var leafCertificate: Certificate
        var handledCriticalExtensions: [ASN1ObjectIdentifier]
    }
    
    struct LeafCertificateIsInTheRootStoreButDoesNotMeetPolicy: Hashable {
        var leafCertificate: Certificate
        var failsToMeetPolicyReason: String
    }
    
    struct ChainFailsToMeetPolicy: Hashable {
        var chain: UnverifiedCertificateChain
        var failsToMeetPolicyReason: String
    }
    
    struct IssuerHasUnhandledCriticalExtension: Hashable {
        var issuer: Certificate
        var partialChain: [Certificate]
        var handledCriticalExtensions: [ASN1ObjectIdentifier]
    }
    
    struct IssuerHasNotSignedCertificate: Hashable {
        var issuer: Certificate
        var partialChain: [Certificate]
    }
    
    enum Storage: Hashable {
        case leafCertificateHasUnhandledCriticalExtension(LeafCertificateHasUnhandledCriticalExtensions)
        case leafCertificateIsInTheRootStoreButDoesNotMeetPolicy(LeafCertificateIsInTheRootStoreButDoesNotMeetPolicy)
        case chainFailsToMeetPolicy(ChainFailsToMeetPolicy)
        case intermediateHashUnhandledCriticalExtension(IssuerHasUnhandledCriticalExtension)
        case issuerHasNotSignedCertificate(IssuerHasNotSignedCertificate)
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
        .intermediateHashUnhandledCriticalExtension(.init(
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
}

// MARK: CustomDebugStringConvertible

extension VerificationDiagnostic: CustomDebugStringConvertible {
    /// Produces a human readable description of this ``VerificationDiagnostic`` that is potentially expensive to compute.
    public var debugDescription: String {
        storage.debugDescription
    }
}

extension VerificationDiagnostic.Storage {
    var debugDescription: String {
        switch self {
        case .leafCertificateHasUnhandledCriticalExtension(let diagnostic): return diagnostic.debugDescription
        case .leafCertificateIsInTheRootStoreButDoesNotMeetPolicy(let diagnostic): return diagnostic.debugDescription
        case .chainFailsToMeetPolicy(let diagnostic): return diagnostic.debugDescription
        case .intermediateHashUnhandledCriticalExtension(let diagnostic): return diagnostic.debugDescription
        case .issuerHasNotSignedCertificate(let diagnostic): return diagnostic.debugDescription
        }
    }
}

extension VerificationDiagnostic.LeafCertificateHasUnhandledCriticalExtensions: CustomDebugStringConvertible {
    var debugDescription: String {
        """
        The leaf certificate has critical extensions that the policy does not understand and therefore can't enforce.
        
        Unhandled extensions:
        \(leafCertificate.extensions.unhandledCriticalExtensions(
            for: self.handledCriticalExtensions
        ).lazy.map { $0.debugDescription }.joined(separator: "\n"))
        
        Leaf certificate:
        \(leafCertificate)
        """
    }
}

extension VerificationDiagnostic.LeafCertificateIsInTheRootStoreButDoesNotMeetPolicy: CustomDebugStringConvertible {
    var debugDescription: String {
        """
        Leaf certificate is in the root store of the verifier but it does by itself not meet the policy.
        
        Reason: \(self.failsToMeetPolicyReason)
        
        Leaf Certificate:
        \(self.leafCertificate)
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
        \(self.chain.lazy.map { $0.debugDescription }.joined(separator: "\n"))
        """
    }
}

extension VerificationDiagnostic.IssuerHasUnhandledCriticalExtension: CustomDebugStringConvertible {
    var debugDescription: String {
        """
        An issuer of a certificate in the (partial) chain has critical extensions that the policy does not understand and therefore can't enforce.
        
        Unhandled extensions:
        \(self.issuer.extensions.unhandledCriticalExtensions(
            for: self.handledCriticalExtensions
        ).lazy.map { "- \($0.debugDescription)" }.joined(separator: "\n"))
        
        Chain (from leaf to issuer that has critical extensions the policy doesn't enforce):
        \(self.partialChain.lazy.map { $0.debugDescription }.joined(separator: "\n"))
        \(issuer.debugDescription)
        """
    }
}

extension VerificationDiagnostic.IssuerHasNotSignedCertificate: CustomDebugStringConvertible {
    var debugDescription: String {
        """
        An issuer of a certificate in the (partial) chain has not signed the previous certificate in the chain.
        
        Chain (from leaf to issuer that has not signed the certificate before it):
        \(self.partialChain.lazy.map { $0.debugDescription }.joined(separator: "\n"))
        \(issuer.debugDescription)
        """
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
