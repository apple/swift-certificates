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
    static func issuerHashUnhandledCriticalExtension(
        issuer: Certificate,
        chain: CandidatePartialChain,
        handledCriticalExtensions: [ASN1ObjectIdentifier]
    ) -> Self {
        self.init(storage: .issuerHashUnhandledCriticalExtension(
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
    static func issuerHashUnhandledCriticalExtension(
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

extension VerificationDiagnostic: CustomStringConvertible {
    /// Produces a human readable description of this ``VerificationDiagnostic`` that is potential expensive to compute.
    public var description: String {
        storage.description
    }
}

extension VerificationDiagnostic.Storage {
    var description: String {
        switch self {
        case .leafCertificateHasUnhandledCriticalExtension(let diagnostic): return diagnostic.description
        case .leafCertificateIsInTheRootStoreButDoesNotMeetPolicy(let diagnostic): return diagnostic.description
        case .chainFailsToMeetPolicy(let diagnostic): return diagnostic.description
        case .intermediateHashUnhandledCriticalExtension(let diagnostic): return diagnostic.description
        case .issuerHasNotSignedCertificate(let diagnostic): return diagnostic.description
        }
    }
}

extension VerificationDiagnostic.LeafCertificateHasUnhandledCriticalExtensions: CustomStringConvertible {
    var description: String {
        """
        The leaf certificate has critical extensions that the policy does not understand and therefore can't enforce.
        Unhandled extensions:
        \(leafCertificate.extensions.unhandledCriticalExtensions(
            for: self.handledCriticalExtensions
        ).lazy.map { $0.description }.joined(separator: "\n"))
        Leaf certificate:
        \(leafCertificate)
        """
    }
}

extension VerificationDiagnostic.LeafCertificateIsInTheRootStoreButDoesNotMeetPolicy: CustomStringConvertible {
    var description: String {
        """
        Leaf certificate is in the root store of the verifier but it does by itself not meet the policy.
        Reason: \(self.failsToMeetPolicyReason)
        Leaf Certificate:
        \(self.leafCertificate)
        """
    }
}

extension VerificationDiagnostic.ChainFailsToMeetPolicy: CustomStringConvertible {
    var description: String {
        """
        A certificate chain to a certificate in the root store was found but it does not meet the policy.
        Reason: \(self.failsToMeetPolicyReason)
        Chain (from leaf to root):
        \(self.chain.lazy.map { $0.description }.joined(separator: "\n"))
        """
    }
}

extension VerificationDiagnostic.IssuerHasUnhandledCriticalExtension: CustomStringConvertible {
    var description: String {
        """
        An issuer of a certificate in the (partial) chain has critical extensions that the policy does not understand and therefore can't enforce.
        Unhandled extensions:
        \(self.issuer.extensions.unhandledCriticalExtensions(
            for: self.handledCriticalExtensions
        ).lazy.map { $0.description }.joined(separator: "\n"))
        Chain (from leaf to issuer that has critical extensions the policy doesn't enforce):
        \(self.partialChain.lazy.map { $0.description }.joined(separator: "\n"))
        \(issuer.description)
        """
    }
}

extension VerificationDiagnostic.IssuerHasNotSignedCertificate: CustomStringConvertible {
    var description: String {
        """
        An issuer of a certificate in the (partial) chain has not signed the previous certificate in the chain.
        Chain (from leaf to issuer that has not signed the certificate before it):
        \(self.partialChain.lazy.map { $0.description }.joined(separator: "\n"))
        \(issuer.description)
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
