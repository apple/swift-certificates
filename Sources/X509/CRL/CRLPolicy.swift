//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCertificates open source project
//
// Copyright (c) 2024 Apple Inc. and the SwiftCertificates project authors
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

/// A ``VerifierPolicy`` that checks certificate revocation via CRL Distribution Points.
///
/// For each certificate in the chain (except the root), if a crlDistributionPoints extension
/// is present, this policy fetches and validates the CRL and checks the serial number.
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public struct CRLPolicy: VerifierPolicy {
    public let verifyingCriticalExtensions: [ASN1ObjectIdentifier] = [
        .X509ExtensionID.crlDistributionPoints
    ]

    private let fetcher: any CRLFetcher
    private let cache: CRLCache

    public init(fetcher: any CRLFetcher, cache: CRLCache = CRLCache()) {
        self.fetcher = fetcher
        self.cache = cache
    }

    public mutating func chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain) async -> PolicyEvaluationResult {
        // Check each cert except root (last in chain)
        for index in chain.dropLast().indices {
            let certificate = chain[index]
            let issuer = chain[chain.index(after: index)]
            switch await checkCertificate(certificate, issuer: issuer) {
            case .meetsPolicy:
                continue
            case .failsToMeetPolicy(let reason):
                return .failsToMeetPolicy(reason: reason)
            }
        }
        return .meetsPolicy
    }

    private func checkCertificate(_ certificate: Certificate, issuer: Certificate) async -> PolicyEvaluationResult {
        let cdps: CRLDistributionPoints?
        do {
            cdps = try certificate.extensions.crlDistributionPoints
        } catch {
            return .failsToMeetPolicy(reason: "CRLPolicy: failed to parse crlDistributionPoints: \(error)")
        }

        guard let cdps, !cdps.urls.isEmpty else {
            // No CDP extension — nothing to check
            return .meetsPolicy
        }

        for url in cdps.urls {
            let result = await cache.getCRL(url: url, fetcher: fetcher)
            switch result {
            case .parseError:
                return .failsToMeetPolicy(reason: "CRLPolicy: failed to parse CRL from \(url)")
            case .networkError:
                return .failsToMeetPolicy(reason: "CRLPolicy: unable to obtain CRL from \(url)")
            case .success(let crl):
                // Validate CRL timing
                let now = Date()
                if crl.thisUpdate > now {
                    return .failsToMeetPolicy(reason: "CRLPolicy: CRL thisUpdate is in the future for \(url)")
                }
                if let nextUpdate = crl.nextUpdate, now > nextUpdate {
                    return .failsToMeetPolicy(reason: "CRLPolicy: CRL has expired (nextUpdate passed) for \(url)")
                }

                // Verify CRL signature with issuer public key
                if !crl.verifySignature(issuerPublicKey: issuer.publicKey) {
                    return .failsToMeetPolicy(reason: "CRLPolicy: CRL signature verification failed for \(url)")
                }

                // Check revocation
                if crl.isRevoked(certificate.serialNumber) {
                    return .failsToMeetPolicy(reason: "CRLPolicy: certificate is revoked")
                }
            }
        }
        return .meetsPolicy
    }
}
