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
import XCTest
import SwiftASN1
@testable import X509
@preconcurrency import Crypto

@available(macOS 11.0, iOS 14, tvOS 14, watchOS 7, macCatalyst 14, visionOS 1.0, *)
final class VerifierTests: XCTestCase {
    private static let referenceTime = Date()

    private static let ca1PrivateKey = P384.Signing.PrivateKey()
    private static let ca1Name = try! DistinguishedName {
        CountryName("US")
        OrganizationName("Apple")
        CommonName("Swift Certificate Test CA 1")
    }
    private static let ca1: Certificate = {
        return try! Certificate(
            version: .v3,
            serialNumber: .init(),
            publicKey: .init(ca1PrivateKey.publicKey),
            notValidBefore: referenceTime - .days(365),
            notValidAfter: referenceTime + .days(3650),
            issuer: ca1Name,
            subject: ca1Name,
            signatureAlgorithm: .ecdsaWithSHA384,
            extensions: Certificate.Extensions {
                Critical(
                    BasicConstraints.isCertificateAuthority(maxPathLength: nil)
                )
                KeyUsage(keyCertSign: true)
                SubjectKeyIdentifier(
                    keyIdentifier: ArraySlice(Insecure.SHA1.hash(data: ca1PrivateKey.publicKey.derRepresentation))
                )
            },
            issuerPrivateKey: .init(ca1PrivateKey)
        )
    }()
    private static let ca1WithoutSubjectKeyIdentifier: Certificate = {
        return try! Certificate(
            version: .v3,
            serialNumber: .init(),
            publicKey: .init(ca1PrivateKey.publicKey),
            notValidBefore: referenceTime - .days(365),
            notValidAfter: referenceTime + .days(3650),
            issuer: ca1Name,
            subject: ca1Name,
            signatureAlgorithm: .ecdsaWithSHA384,
            extensions: Certificate.Extensions {
                Critical(
                    BasicConstraints.isCertificateAuthority(maxPathLength: nil)
                )
                KeyUsage(keyCertSign: true)
            },
            issuerPrivateKey: .init(ca1PrivateKey)
        )
    }()
    private static let ca1CrossSignedByCA2: Certificate = {
        return try! Certificate(
            version: .v3,
            serialNumber: .init(),
            publicKey: .init(ca1PrivateKey.publicKey),
            notValidBefore: referenceTime - .days(365),
            notValidAfter: referenceTime + .days(365),
            issuer: ca2Name,
            subject: ca1Name,
            signatureAlgorithm: .ecdsaWithSHA384,
            extensions: Certificate.Extensions {
                Critical(
                    BasicConstraints.isCertificateAuthority(maxPathLength: nil)
                )
                KeyUsage(keyCertSign: true)
                AuthorityKeyIdentifier(keyIdentifier: try! ca2.extensions.subjectKeyIdentifier!.keyIdentifier)
                SubjectKeyIdentifier(
                    keyIdentifier: ArraySlice(Insecure.SHA1.hash(data: ca1PrivateKey.publicKey.derRepresentation))
                )
            },
            issuerPrivateKey: .init(ca2PrivateKey)
        )
    }()
    private static let ca1AlternativePrivateKey = P384.Signing.PrivateKey()
    private static let ca1WithAlternativePrivateKey: Certificate = {
        return try! Certificate(
            version: .v3,
            serialNumber: .init(),
            publicKey: .init(ca1AlternativePrivateKey.publicKey),
            notValidBefore: referenceTime - .days(365),
            notValidAfter: referenceTime + .days(3650),
            issuer: ca1Name,
            subject: ca1Name,
            signatureAlgorithm: .ecdsaWithSHA384,
            extensions: Certificate.Extensions {
                Critical(
                    BasicConstraints.isCertificateAuthority(maxPathLength: nil)
                )
                KeyUsage(keyCertSign: true)
                SubjectKeyIdentifier(
                    keyIdentifier: ArraySlice(
                        Insecure.SHA1.hash(data: ca1AlternativePrivateKey.publicKey.derRepresentation)
                    )
                )
            },
            issuerPrivateKey: .init(ca1PrivateKey)
        )
    }()

    private static let ca2PrivateKey = P384.Signing.PrivateKey()
    private static let ca2Name = try! DistinguishedName {
        CountryName("US")
        OrganizationName("Apple")
        CommonName("Swift Certificate Test CA 2")
    }
    private static let ca2: Certificate = {
        return try! Certificate(
            version: .v3,
            serialNumber: .init(),
            publicKey: .init(ca2PrivateKey.publicKey),
            notValidBefore: referenceTime - .days(365),
            notValidAfter: referenceTime + .days(3650),
            issuer: ca2Name,
            subject: ca2Name,
            signatureAlgorithm: .ecdsaWithSHA384,
            extensions: Certificate.Extensions {
                Critical(
                    BasicConstraints.isCertificateAuthority(maxPathLength: nil)
                )
                KeyUsage(keyCertSign: true)
                SubjectKeyIdentifier(
                    keyIdentifier: ArraySlice(Insecure.SHA1.hash(data: ca2PrivateKey.publicKey.derRepresentation))
                )
            },
            issuerPrivateKey: .init(ca2PrivateKey)
        )
    }()
    private static let ca2CrossSignedByCA1: Certificate = {
        return try! Certificate(
            version: .v3,
            serialNumber: .init(),
            publicKey: .init(ca2PrivateKey.publicKey),
            notValidBefore: referenceTime - .days(365),
            notValidAfter: referenceTime + .days(365),
            issuer: ca1Name,
            subject: ca2Name,
            signatureAlgorithm: .ecdsaWithSHA384,
            extensions: Certificate.Extensions {
                Critical(
                    BasicConstraints.isCertificateAuthority(maxPathLength: nil)
                )
                KeyUsage(keyCertSign: true)
                AuthorityKeyIdentifier(keyIdentifier: try! ca1.extensions.subjectKeyIdentifier!.keyIdentifier)
                SubjectKeyIdentifier(
                    keyIdentifier: ArraySlice(Insecure.SHA1.hash(data: ca2PrivateKey.publicKey.derRepresentation))
                )
            },
            issuerPrivateKey: .init(ca1PrivateKey)
        )
    }()

    private static let intermediate1PrivateKey = P256.Signing.PrivateKey()
    private static let intermediate1Name = try! DistinguishedName {
        CountryName("US")
        OrganizationName("Apple")
        CommonName("Swift Certificate Test Intermediate CA 1")
    }
    private static let intermediate1: Certificate = {
        return try! Certificate(
            version: .v3,
            serialNumber: .init(),
            publicKey: .init(intermediate1PrivateKey.publicKey),
            notValidBefore: referenceTime - .days(365),
            notValidAfter: referenceTime + .days(5 * 365),
            issuer: ca1.subject,
            subject: intermediate1Name,
            signatureAlgorithm: .ecdsaWithSHA384,
            extensions: Certificate.Extensions {
                Critical(
                    BasicConstraints.isCertificateAuthority(maxPathLength: 1)
                )
                KeyUsage(keyCertSign: true)
                AuthorityKeyIdentifier(keyIdentifier: try! ca1.extensions.subjectKeyIdentifier!.keyIdentifier)
                SubjectKeyIdentifier(
                    keyIdentifier: ArraySlice(
                        Insecure.SHA1.hash(data: intermediate1PrivateKey.publicKey.derRepresentation)
                    )
                )
            },
            issuerPrivateKey: .init(ca1PrivateKey)
        )
    }()
    private static let intermediate1WithoutSKIAKI: Certificate = {
        return try! Certificate(
            version: .v3,
            serialNumber: .init(),
            publicKey: .init(intermediate1PrivateKey.publicKey),
            notValidBefore: referenceTime - .days(365),
            notValidAfter: referenceTime + .days(5 * 365),
            issuer: ca1.subject,
            subject: intermediate1Name,
            signatureAlgorithm: .ecdsaWithSHA384,
            extensions: Certificate.Extensions {
                Critical(
                    BasicConstraints.isCertificateAuthority(maxPathLength: 1)
                )
                KeyUsage(keyCertSign: true)
            },
            issuerPrivateKey: .init(ca1PrivateKey)
        )
    }()
    private static let intermediate1WithIncorrectSKIAKI: Certificate = {
        return try! Certificate(
            version: .v3,
            serialNumber: .init(),
            publicKey: .init(intermediate1PrivateKey.publicKey),
            notValidBefore: referenceTime - .days(365),
            notValidAfter: referenceTime + .days(5 * 365),
            issuer: ca1.subject,
            subject: intermediate1Name,
            signatureAlgorithm: .ecdsaWithSHA384,
            extensions: Certificate.Extensions {
                Critical(
                    BasicConstraints.isCertificateAuthority(maxPathLength: 1)
                )
                KeyUsage(keyCertSign: true)
                AuthorityKeyIdentifier(keyIdentifier: try! ca2.extensions.subjectKeyIdentifier!.keyIdentifier)
                SubjectKeyIdentifier(
                    keyIdentifier: ArraySlice(Insecure.SHA1.hash(data: ca1PrivateKey.publicKey.derRepresentation))
                )
            },
            issuerPrivateKey: .init(ca1PrivateKey)
        )
    }()

    private static let localhostLeafPrivateKey = P256.Signing.PrivateKey()
    private static let localhostLeaf: Certificate = {
        let localhostLeafName = try! DistinguishedName {
            CountryName("US")
            OrganizationName("Apple")
            CommonName("localhost")
        }

        return try! Certificate(
            version: .v3,
            serialNumber: .init(),
            publicKey: .init(localhostLeafPrivateKey.publicKey),
            notValidBefore: referenceTime - .days(365),
            notValidAfter: referenceTime + .days(365),
            issuer: intermediate1.subject,
            subject: localhostLeafName,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: Certificate.Extensions {
                Critical(
                    BasicConstraints.notCertificateAuthority
                )
                KeyUsage(keyCertSign: true)
                AuthorityKeyIdentifier(keyIdentifier: try! intermediate1.extensions.subjectKeyIdentifier!.keyIdentifier)
            },
            issuerPrivateKey: .init(intermediate1PrivateKey)
        )
    }()

    private static let isolatedSelfSignedCertKey = P256.Signing.PrivateKey()
    private static let isolatedSelfSignedCert: Certificate = {
        let isolatedSelfSignedCertName = try! DistinguishedName {
            CountryName("US")
            OrganizationName("Apple")
            CommonName("Isolated Self-Signed Cert")
        }

        return try! Certificate(
            version: .v3,
            serialNumber: .init(),
            publicKey: .init(isolatedSelfSignedCertKey.publicKey),
            notValidBefore: referenceTime - .days(365),
            notValidAfter: referenceTime + .days(365),
            issuer: isolatedSelfSignedCertName,
            subject: isolatedSelfSignedCertName,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: Certificate.Extensions {
                Critical(
                    BasicConstraints.isCertificateAuthority(maxPathLength: nil)
                )
                KeyUsage(keyCertSign: true)
            },
            issuerPrivateKey: .init(isolatedSelfSignedCertKey)
        )
    }()

    private static let isolatedSelfSignedCertWithWeirdCriticalExtension: Certificate = {
        let isolatedSelfSignedCertName = try! DistinguishedName {
            CountryName("US")
            OrganizationName("Apple")
            CommonName("Isolated Self-Signed Cert")
        }

        return try! Certificate(
            version: .v3,
            serialNumber: .init(),
            publicKey: .init(isolatedSelfSignedCertKey.publicKey),
            notValidBefore: referenceTime - .days(365),
            notValidAfter: referenceTime + .days(365),
            issuer: isolatedSelfSignedCertName,
            subject: isolatedSelfSignedCertName,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: Certificate.Extensions {
                Critical(
                    BasicConstraints.isCertificateAuthority(maxPathLength: nil)
                )
                KeyUsage(keyCertSign: true)

                // An opaque extension that just so happens to be critical
                Certificate.Extension(oid: [1, 2, 3, 4, 5], critical: true, value: [1, 2, 3, 4, 5])
            },
            issuerPrivateKey: .init(isolatedSelfSignedCertKey)
        )
    }()

    // MARK: Deeply crazy PKI
    //
    // This section defines a deeply crazy PKI. The PKI has one root CA and two intermediate CAs, and looks roughly like this:
    //
    //                       ┌────────────────┐
    //                       │                │
    //             ┌─────────│    Root CA     │
    //             │         │                │
    //             │         └────────────────┘          ┌─────────────────────────────────────────────────────────────────┐
    //             │                  ┌──────────────────┼───────────────────┐                                             │
    //             │                  │                  │                ┌──┼──────────────┐        ┌─────────┐           │
    //┌ ─ ─ ─ ─ ─ ─│─ ─ ─ ─ ─ ─ ─ ─ ─ ┼ ─ ─ ─ ─ ─ ─ ─ ─ ─│─ ─ ─ ─ ─ ─     │  │   ┌ ─ ─ ─ ─ ─│─ ─ ─ ─ ┼ ─ ─ ─ ─ ┼ ─ ─ ─ ─ ┐ │
    //             ▼                  ▼                  ▼           │    │  │              ▼        │         ▼           │
    //│   ┌────────────────┐ ┌────────────────┐ ┌────────────────┐        │  │   │ ┌────────────────┐│┌────────────────┐ │ │
    //    │                │ │                │ │                │   │    │  │     │                │││                │   │
    //│   │       T1       │ │       T2       │ │       T3       │        │  └───┼─│       X1       │││       X2       │─┼─┘
    //    │                │ │                │ │                │   │    │        │                │││                │
    //│   └────────────────┘ └────────────────┘ └────────────────┘        │      │ └────────────────┘│└────────────────┘ │
    //             │                  │                  │           │    │                          │
    //└ ─ ─ ─ ─ ─ ─│─ ─ ─ ─ ─ ─ ─ ─ ─ ┼ ─ ─ ─ ─ ─ ─ ─ ─ ─│─ ─ ─ ─ ─ ─     │      └ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┼ ─ ─ ─ ─ ─ ─ ─ ─ ─ ┘
    //             └──────────────────┼──────────────────┼────────────────┘                          │
    //                                └──────────────────┼───────────────────────────────────────────┘
    //                                                   │
    //                                ┌──────────────────┘
    //                                │
    //                                ▼
    //                       ┌────────────────┐
    //                       │                │
    //                       │      Leaf      │
    //                       │                │
    //                       └────────────────┘
    //
    // T and X are both intermediate certificates. All certificates within their boxes have the same subject name. However, not all
    // of those certificates are the same.
    //
    // The goal of this PKI is to test our understanding of what certificates are "the same". We reject paths that pass through "the
    // same" certificate, so the goal of this test was to produce a path that would preferentially attempt to add "the same"
    // certificates from T again and again.
    //
    // Our criteria for "not the same" are "different subject name", "different public key", or "different subject alternative name".
    // That implies we need three certificates to test all the rejection criteria. Additionally, we need these certificates to appear
    // in a specific preference order, to force us to actually _try_ the Ts we already have in the path.
    //
    // Our goal is to ultimately build the chain: Leaf - T3 - X2 - T2 - X1 - T1 - Root. However, each time we return to T we want to
    // try all the prior Ts and reject them due to having previously visited them. We don't much care about the order of the Xs.
    //
    // To get the checking order correct, we'll have Leaf contain an AKI extension. T3 will contain a matching SKI, T2 will contain no
    // SKI, and T1 will contain an incorrect SKI. This will force a priority order of T3, T2, T1. To ensure this priority order is maintained
    // once we get to the X intermediate, we'll have both X certificates contain the same AKI as the Leaf. This means that X1 has an AKI
    // that doesn't match the SKI of its issuer: that's ok, we tolerate that!
    //
    // T2 and T1 will use a different key than T3. Additionally, each cert will contain different subject alternative names.
    //
    // Finally, we need two Xs that are considered "different" so that chain building doesn't fail. We differ them by using SAN.
    //
    // The following section builds this absolutely crazy PKI. We re-use `ca1` defined above as our root CA.
    private static let t1t2Key = P256.Signing.PrivateKey()
    private static let t3Key = P256.Signing.PrivateKey()
    private static let xKey = P256.Signing.PrivateKey()
    private static let insaneLeafKey = P256.Signing.PrivateKey()
    private static let tName = try! DistinguishedName {
        CountryName("US")
        OrganizationName("Apple")
        CommonName("T")
    }
    private static let xName = try! DistinguishedName {
        CountryName("US")
        OrganizationName("Apple")
        CommonName("X")
    }
    private static let leafName = try! DistinguishedName {
        CommonName("InsaneLeaf")
    }

    private static let t1: Certificate = {
        return try! Certificate(
            version: .v3,
            serialNumber: .init(),
            publicKey: .init(t1t2Key.publicKey),
            notValidBefore: referenceTime - .days(365),
            notValidAfter: referenceTime + .days(5 * 365),
            issuer: ca1.subject,
            subject: tName,
            signatureAlgorithm: .ecdsaWithSHA384,
            extensions: Certificate.Extensions {
                Critical(
                    BasicConstraints.isCertificateAuthority(maxPathLength: nil)
                )
                KeyUsage(keyCertSign: true)
                AuthorityKeyIdentifier(keyIdentifier: try! ca1.extensions.subjectKeyIdentifier!.keyIdentifier)

                // Note this is the SKI for the _wrong key_.
                SubjectKeyIdentifier(
                    keyIdentifier: ArraySlice(Insecure.SHA1.hash(data: ca1PrivateKey.publicKey.derRepresentation))
                )
                SubjectAlternativeNames([.dnsName("example.com")])
            },
            issuerPrivateKey: .init(ca1PrivateKey)
        )
    }()
    private static let t2: Certificate = {
        return try! Certificate(
            version: .v3,
            serialNumber: .init(),
            publicKey: .init(t1t2Key.publicKey),
            notValidBefore: referenceTime - .days(365),
            notValidAfter: referenceTime + .days(5 * 365),
            issuer: xName,
            subject: tName,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: Certificate.Extensions {
                Critical(
                    BasicConstraints.isCertificateAuthority(maxPathLength: nil)
                )
                KeyUsage(keyCertSign: true)
            },
            issuerPrivateKey: .init(xKey)
        )
    }()
    private static let t3: Certificate = {
        return try! Certificate(
            version: .v3,
            serialNumber: .init(),
            publicKey: .init(t3Key.publicKey),
            notValidBefore: referenceTime - .days(365),
            notValidAfter: referenceTime + .days(5 * 365),
            issuer: xName,
            subject: tName,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: Certificate.Extensions {
                Critical(
                    BasicConstraints.isCertificateAuthority(maxPathLength: 1)
                )
                KeyUsage(keyCertSign: true)
                SubjectKeyIdentifier(
                    keyIdentifier: ArraySlice(Insecure.SHA1.hash(data: t3Key.publicKey.derRepresentation))
                )
            },
            issuerPrivateKey: .init(xKey)
        )
    }()
    private static let x1: Certificate = {
        return try! Certificate(
            version: .v3,
            serialNumber: .init(),
            publicKey: .init(xKey.publicKey),
            notValidBefore: referenceTime - .days(365),
            notValidAfter: referenceTime + .days(5 * 365),
            issuer: tName,
            subject: xName,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: Certificate.Extensions {
                Critical(
                    BasicConstraints.isCertificateAuthority(maxPathLength: nil)
                )
                KeyUsage(keyCertSign: true)
                AuthorityKeyIdentifier(
                    keyIdentifier: ArraySlice(Insecure.SHA1.hash(data: t3Key.publicKey.derRepresentation))
                )
            },
            issuerPrivateKey: .init(t1t2Key)
        )
    }()
    private static let x2: Certificate = {
        return try! Certificate(
            version: .v3,
            serialNumber: .init(),
            publicKey: .init(xKey.publicKey),
            notValidBefore: referenceTime - .days(365),
            notValidAfter: referenceTime + .days(5 * 365),
            issuer: tName,
            subject: xName,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: Certificate.Extensions {
                Critical(
                    BasicConstraints.isCertificateAuthority(maxPathLength: nil)
                )
                KeyUsage(keyCertSign: true)
                AuthorityKeyIdentifier(
                    keyIdentifier: ArraySlice(Insecure.SHA1.hash(data: t3Key.publicKey.derRepresentation))
                )
                SubjectAlternativeNames([.dnsName("foo.example.com")])
            },
            issuerPrivateKey: .init(t1t2Key)
        )
    }()
    private static let insaneLeaf: Certificate = {
        return try! Certificate(
            version: .v3,
            serialNumber: .init(),
            publicKey: .init(insaneLeafKey.publicKey),
            notValidBefore: referenceTime - .days(365),
            notValidAfter: referenceTime + .days(5 * 365),
            issuer: tName,
            subject: leafName,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: Certificate.Extensions {
                Critical(
                    BasicConstraints.notCertificateAuthority
                )
                AuthorityKeyIdentifier(
                    keyIdentifier: ArraySlice(Insecure.SHA1.hash(data: t3Key.publicKey.derRepresentation))
                )
            },
            issuerPrivateKey: .init(t3Key)
        )
    }()

    @PolicyBuilder private static var defaultPolicy: some VerifierPolicy {
        RFC5280Policy()
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    func testTrivialChainBuildingDeprecated() async throws {
        let roots = CertificateStore([Self.ca1])
        let log = DiagnosticsLog()

        var verifier = Verifier(rootCertificates: roots) { Self.defaultPolicy }
        let result = await verifier.validate(
            leafCertificate: Self.localhostLeaf,
            intermediates: CertificateStore([Self.intermediate1]),
            diagnosticCallback: log.append(_:)
        )

        guard case .validCertificate(let chain) = result else {
            XCTFail("Failed to validate: \(result)")
            return
        }

        XCTAssertEqual(chain, [Self.localhostLeaf, Self.intermediate1, Self.ca1])

        XCTAssertEqual(
            log,
            [
                .searchingForIssuerOfPartialChain([Self.localhostLeaf]),
                .foundCandidateIssuersOfPartialChainInIntermediateStore(
                    [Self.localhostLeaf],
                    issuers: [Self.intermediate1]
                ),
                .searchingForIssuerOfPartialChain([Self.localhostLeaf, Self.intermediate1]),
                .foundCandidateIssuersOfPartialChainInRootStore(
                    [Self.localhostLeaf, Self.intermediate1],
                    issuers: [Self.ca1]
                ),
                .foundValidCertificateChain([Self.localhostLeaf, Self.intermediate1, Self.ca1]),
            ]
        )
    }

    func testTrivialChainBuilding() async throws {
        let roots = CertificateStore([Self.ca1])
        let log = DiagnosticsLog()

        var verifier = Verifier(rootCertificates: roots) { Self.defaultPolicy }
        let result = await verifier.validate(
            leaf: Self.localhostLeaf,
            intermediates: CertificateStore([Self.intermediate1]),
            diagnosticCallback: log.append(_:)
        )

        guard case .validCertificate(let chain) = result else {
            XCTFail("Failed to validate: \(result)")
            return
        }

        XCTAssertEqual(Array(chain), [Self.localhostLeaf, Self.intermediate1, Self.ca1])

        XCTAssertEqual(
            log,
            [
                .searchingForIssuerOfPartialChain([Self.localhostLeaf]),
                .foundCandidateIssuersOfPartialChainInIntermediateStore(
                    [Self.localhostLeaf],
                    issuers: [Self.intermediate1]
                ),
                .searchingForIssuerOfPartialChain([Self.localhostLeaf, Self.intermediate1]),
                .foundCandidateIssuersOfPartialChainInRootStore(
                    [Self.localhostLeaf, Self.intermediate1],
                    issuers: [Self.ca1]
                ),
                .foundValidCertificateChain([Self.localhostLeaf, Self.intermediate1, Self.ca1]),
            ]
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    func testRootsWithSKIArePreferredDeprecated() async throws {
        let roots = CertificateStore([Self.ca1WithoutSubjectKeyIdentifier, Self.ca1])
        let log = DiagnosticsLog()

        var verifier = Verifier(rootCertificates: roots) { Self.defaultPolicy }
        let result = await verifier.validate(
            leafCertificate: Self.localhostLeaf,
            intermediates: CertificateStore([Self.intermediate1]),
            diagnosticCallback: log.append(_:)
        )

        guard case .validCertificate(let chain) = result else {
            XCTFail("Failed to validate: \(result)")
            return
        }

        XCTAssertEqual(chain, [Self.localhostLeaf, Self.intermediate1, Self.ca1])

        XCTAssertEqual(
            log,
            [
                .searchingForIssuerOfPartialChain([Self.localhostLeaf]),
                .foundCandidateIssuersOfPartialChainInIntermediateStore(
                    [Self.localhostLeaf],
                    issuers: [Self.intermediate1]
                ),
                .searchingForIssuerOfPartialChain([Self.localhostLeaf, Self.intermediate1]),
                .foundCandidateIssuersOfPartialChainInRootStore(
                    [Self.localhostLeaf, Self.intermediate1],
                    issuers: [Self.ca1, Self.ca1WithoutSubjectKeyIdentifier]
                ),
                .foundValidCertificateChain([Self.localhostLeaf, Self.intermediate1, Self.ca1]),
            ]
        )
    }

    func testRootsWithSKIArePreferred() async throws {
        let roots = CertificateStore([Self.ca1WithoutSubjectKeyIdentifier, Self.ca1])
        let log = DiagnosticsLog()

        var verifier = Verifier(rootCertificates: roots) { Self.defaultPolicy }
        let result = await verifier.validate(
            leaf: Self.localhostLeaf,
            intermediates: CertificateStore([Self.intermediate1]),
            diagnosticCallback: log.append(_:)
        )

        guard case .validCertificate(let chain) = result else {
            XCTFail("Failed to validate: \(result)")
            return
        }

        XCTAssertEqual(Array(chain), [Self.localhostLeaf, Self.intermediate1, Self.ca1])

        XCTAssertEqual(
            log,
            [
                .searchingForIssuerOfPartialChain([Self.localhostLeaf]),
                .foundCandidateIssuersOfPartialChainInIntermediateStore(
                    [Self.localhostLeaf],
                    issuers: [Self.intermediate1]
                ),
                .searchingForIssuerOfPartialChain([Self.localhostLeaf, Self.intermediate1]),
                .foundCandidateIssuersOfPartialChainInRootStore(
                    [Self.localhostLeaf, Self.intermediate1],
                    issuers: [Self.ca1, Self.ca1WithoutSubjectKeyIdentifier]
                ),
                .foundValidCertificateChain([Self.localhostLeaf, Self.intermediate1, Self.ca1]),
            ]
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    func testMissingIntermediateFailsToBuildDeprecated() async throws {
        let roots = CertificateStore([Self.ca1])
        let log = DiagnosticsLog()

        var verifier = Verifier(rootCertificates: roots) { Self.defaultPolicy }
        let result = await verifier.validate(
            leafCertificate: Self.localhostLeaf,
            intermediates: CertificateStore(),
            diagnosticCallback: log.append(_:)
        )

        guard case .couldNotValidate(let policyResults) = result else {
            XCTFail("Accidentally validated: \(result)")
            return
        }

        XCTAssertEqual(policyResults, [])
        print(log)
        XCTAssertEqual(
            log,
            [
                .searchingForIssuerOfPartialChain([Self.localhostLeaf]),
                .couldNotValidateLeafCertificate(Self.localhostLeaf),
            ]
        )
    }

    func testMissingIntermediateFailsToBuild() async throws {
        let roots = CertificateStore([Self.ca1])
        let log = DiagnosticsLog()

        var verifier = Verifier(rootCertificates: roots) { Self.defaultPolicy }
        let result = await verifier.validate(
            leaf: Self.localhostLeaf,
            intermediates: CertificateStore(),
            diagnosticCallback: log.append(_:)
        )

        guard case .couldNotValidate(let policyResults) = result else {
            XCTFail("Accidentally validated: \(result)")
            return
        }

        XCTAssertEqual(policyResults, [])
        print(log)
        XCTAssertEqual(
            log,
            [
                .searchingForIssuerOfPartialChain([Self.localhostLeaf]),
                .couldNotValidateLeafCertificate(Self.localhostLeaf),
            ]
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    func testMissingRootFailsToBuildDeprecated() async throws {
        let roots = CertificateStore()
        let log = DiagnosticsLog()

        var verifier = Verifier(rootCertificates: roots) { Self.defaultPolicy }
        let result = await verifier.validate(
            leafCertificate: Self.localhostLeaf,
            intermediates: CertificateStore([Self.intermediate1]),
            diagnosticCallback: log.append(_:)
        )

        guard case .couldNotValidate(let policyResults) = result else {
            XCTFail("Accidentally validated: \(result)")
            return
        }

        XCTAssertEqual(policyResults, [])
        XCTAssertEqual(
            log,
            [
                .searchingForIssuerOfPartialChain([Self.localhostLeaf]),
                .foundCandidateIssuersOfPartialChainInIntermediateStore(
                    [Self.localhostLeaf],
                    issuers: [Self.intermediate1]
                ),
                .searchingForIssuerOfPartialChain([Self.localhostLeaf, Self.intermediate1]),
                .couldNotValidateLeafCertificate(Self.localhostLeaf),
            ]
        )
    }

    func testMissingRootFailsToBuild() async throws {
        let roots = CertificateStore()
        let log = DiagnosticsLog()

        var verifier = Verifier(rootCertificates: roots) { Self.defaultPolicy }
        let result = await verifier.validate(
            leaf: Self.localhostLeaf,
            intermediates: CertificateStore([Self.intermediate1]),
            diagnosticCallback: log.append(_:)
        )

        guard case .couldNotValidate(let policyResults) = result else {
            XCTFail("Accidentally validated: \(result)")
            return
        }

        XCTAssertEqual(policyResults, [])
        XCTAssertEqual(
            log,
            [
                .searchingForIssuerOfPartialChain([Self.localhostLeaf]),
                .foundCandidateIssuersOfPartialChainInIntermediateStore(
                    [Self.localhostLeaf],
                    issuers: [Self.intermediate1]
                ),
                .searchingForIssuerOfPartialChain([Self.localhostLeaf, Self.intermediate1]),
                .couldNotValidateLeafCertificate(Self.localhostLeaf),
            ]
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    func testExtraRootsAreIgnoredDeprecated() async throws {
        let roots = CertificateStore([Self.ca1, Self.ca2])
        let log = DiagnosticsLog()

        var verifier = Verifier(rootCertificates: roots) { Self.defaultPolicy }
        let result = await verifier.validate(
            leafCertificate: Self.localhostLeaf,
            intermediates: CertificateStore([Self.intermediate1]),
            diagnosticCallback: log.append(_:)
        )

        guard case .validCertificate(let chain) = result else {
            XCTFail("Failed to validate: \(result)")
            return
        }

        XCTAssertEqual(chain, [Self.localhostLeaf, Self.intermediate1, Self.ca1])
        XCTAssertEqual(
            log,
            [
                .searchingForIssuerOfPartialChain([Self.localhostLeaf]),
                .foundCandidateIssuersOfPartialChainInIntermediateStore(
                    [Self.localhostLeaf],
                    issuers: [Self.intermediate1]
                ),
                .searchingForIssuerOfPartialChain([Self.localhostLeaf, Self.intermediate1]),
                .foundCandidateIssuersOfPartialChainInRootStore(
                    [Self.localhostLeaf, Self.intermediate1],
                    issuers: [Self.ca1]
                ),
                .foundValidCertificateChain([Self.localhostLeaf, Self.intermediate1, Self.ca1]),
            ]
        )
    }

    func testExtraRootsAreIgnored() async throws {
        let roots = CertificateStore([Self.ca1, Self.ca2])
        let log = DiagnosticsLog()

        var verifier = Verifier(rootCertificates: roots) { Self.defaultPolicy }
        let result = await verifier.validate(
            leaf: Self.localhostLeaf,
            intermediates: CertificateStore([Self.intermediate1]),
            diagnosticCallback: log.append(_:)
        )

        guard case .validCertificate(let chain) = result else {
            XCTFail("Failed to validate: \(result)")
            return
        }

        XCTAssertEqual(Array(chain), [Self.localhostLeaf, Self.intermediate1, Self.ca1])
        XCTAssertEqual(
            log,
            [
                .searchingForIssuerOfPartialChain([Self.localhostLeaf]),
                .foundCandidateIssuersOfPartialChainInIntermediateStore(
                    [Self.localhostLeaf],
                    issuers: [Self.intermediate1]
                ),
                .searchingForIssuerOfPartialChain([Self.localhostLeaf, Self.intermediate1]),
                .foundCandidateIssuersOfPartialChainInRootStore(
                    [Self.localhostLeaf, Self.intermediate1],
                    issuers: [Self.ca1]
                ),
                .foundValidCertificateChain([Self.localhostLeaf, Self.intermediate1, Self.ca1]),
            ]
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    func testPuttingRootsInTheIntermediariesIsntAProblemDeprecated() async throws {
        let roots = CertificateStore([Self.ca1, Self.ca2])
        let log = DiagnosticsLog()

        var verifier = Verifier(rootCertificates: roots) { Self.defaultPolicy }
        let result = await verifier.validate(
            leafCertificate: Self.localhostLeaf,
            intermediates: CertificateStore([Self.intermediate1, Self.ca1, Self.ca2]),
            diagnosticCallback: log.append(_:)
        )

        guard case .validCertificate(let chain) = result else {
            XCTFail("Failed to validate: \(result)")
            return
        }

        XCTAssertEqual(chain, [Self.localhostLeaf, Self.intermediate1, Self.ca1])
        XCTAssertEqual(
            log,
            [
                .searchingForIssuerOfPartialChain([Self.localhostLeaf]),
                .foundCandidateIssuersOfPartialChainInIntermediateStore(
                    [Self.localhostLeaf],
                    issuers: [Self.intermediate1]
                ),
                .searchingForIssuerOfPartialChain([Self.localhostLeaf, Self.intermediate1]),
                .foundCandidateIssuersOfPartialChainInRootStore(
                    [Self.localhostLeaf, Self.intermediate1],
                    issuers: [Self.ca1]
                ),
                .foundValidCertificateChain([Self.localhostLeaf, Self.intermediate1, Self.ca1]),
            ]
        )
    }

    func testPuttingRootsInTheIntermediariesIsntAProblem() async throws {
        let roots = CertificateStore([Self.ca1, Self.ca2])
        let log = DiagnosticsLog()

        var verifier = Verifier(rootCertificates: roots) { Self.defaultPolicy }
        let result = await verifier.validate(
            leaf: Self.localhostLeaf,
            intermediates: CertificateStore([Self.intermediate1, Self.ca1, Self.ca2]),
            diagnosticCallback: log.append(_:)
        )

        guard case .validCertificate(let chain) = result else {
            XCTFail("Failed to validate: \(result)")
            return
        }

        XCTAssertEqual(Array(chain), [Self.localhostLeaf, Self.intermediate1, Self.ca1])
        XCTAssertEqual(
            log,
            [
                .searchingForIssuerOfPartialChain([Self.localhostLeaf]),
                .foundCandidateIssuersOfPartialChainInIntermediateStore(
                    [Self.localhostLeaf],
                    issuers: [Self.intermediate1]
                ),
                .searchingForIssuerOfPartialChain([Self.localhostLeaf, Self.intermediate1]),
                .foundCandidateIssuersOfPartialChainInRootStore(
                    [Self.localhostLeaf, Self.intermediate1],
                    issuers: [Self.ca1]
                ),
                .foundValidCertificateChain([Self.localhostLeaf, Self.intermediate1, Self.ca1]),
            ]
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    func testSupportsCrossSignedRootWithoutTroubleDeprecated() async throws {
        let roots = CertificateStore([Self.ca2])
        let log = DiagnosticsLog()

        var verifier = Verifier(rootCertificates: roots) { Self.defaultPolicy }
        let result = await verifier.validate(
            leafCertificate: Self.localhostLeaf,
            intermediates: CertificateStore([Self.intermediate1, Self.ca1CrossSignedByCA2]),
            diagnosticCallback: log.append(_:)
        )

        guard case .validCertificate(let chain) = result else {
            XCTFail("Failed to validate: \(result)")
            return
        }

        XCTAssertEqual(chain, [Self.localhostLeaf, Self.intermediate1, Self.ca1CrossSignedByCA2, Self.ca2])

        XCTAssertEqual(
            log,
            [
                .searchingForIssuerOfPartialChain([Self.localhostLeaf]),
                .foundCandidateIssuersOfPartialChainInIntermediateStore(
                    [Self.localhostLeaf],
                    issuers: [Self.intermediate1]
                ),
                .searchingForIssuerOfPartialChain([Self.localhostLeaf, Self.intermediate1]),
                .foundCandidateIssuersOfPartialChainInIntermediateStore(
                    [Self.localhostLeaf, Self.intermediate1],
                    issuers: [Self.ca1CrossSignedByCA2]
                ),
                .searchingForIssuerOfPartialChain([Self.localhostLeaf, Self.intermediate1, Self.ca1CrossSignedByCA2]),
                .foundCandidateIssuersOfPartialChainInRootStore(
                    [Self.localhostLeaf, Self.intermediate1, Self.ca1CrossSignedByCA2],
                    issuers: [Self.ca2]
                ),
                .foundValidCertificateChain([
                    Self.localhostLeaf, Self.intermediate1, Self.ca1CrossSignedByCA2, Self.ca2,
                ]),
            ]
        )
    }

    func testSupportsCrossSignedRootWithoutTrouble() async throws {
        let roots = CertificateStore([Self.ca2])
        let log = DiagnosticsLog()

        var verifier = Verifier(rootCertificates: roots) { Self.defaultPolicy }
        let result = await verifier.validate(
            leaf: Self.localhostLeaf,
            intermediates: CertificateStore([Self.intermediate1, Self.ca1CrossSignedByCA2]),
            diagnosticCallback: log.append(_:)
        )

        guard case .validCertificate(let chain) = result else {
            XCTFail("Failed to validate: \(result)")
            return
        }

        XCTAssertEqual(Array(chain), [Self.localhostLeaf, Self.intermediate1, Self.ca1CrossSignedByCA2, Self.ca2])

        XCTAssertEqual(
            log,
            [
                .searchingForIssuerOfPartialChain([Self.localhostLeaf]),
                .foundCandidateIssuersOfPartialChainInIntermediateStore(
                    [Self.localhostLeaf],
                    issuers: [Self.intermediate1]
                ),
                .searchingForIssuerOfPartialChain([Self.localhostLeaf, Self.intermediate1]),
                .foundCandidateIssuersOfPartialChainInIntermediateStore(
                    [Self.localhostLeaf, Self.intermediate1],
                    issuers: [Self.ca1CrossSignedByCA2]
                ),
                .searchingForIssuerOfPartialChain([Self.localhostLeaf, Self.intermediate1, Self.ca1CrossSignedByCA2]),
                .foundCandidateIssuersOfPartialChainInRootStore(
                    [Self.localhostLeaf, Self.intermediate1, Self.ca1CrossSignedByCA2],
                    issuers: [Self.ca2]
                ),
                .foundValidCertificateChain([
                    Self.localhostLeaf, Self.intermediate1, Self.ca1CrossSignedByCA2, Self.ca2,
                ]),
            ]
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    func testBuildsTheShorterPathInTheCaseOfCrossSignedRootsDeprecated() async throws {
        let roots = CertificateStore([Self.ca1, Self.ca2])
        let log = DiagnosticsLog()

        var verifier = Verifier(rootCertificates: roots) { Self.defaultPolicy }
        let result = await verifier.validate(
            leafCertificate: Self.localhostLeaf,
            intermediates: CertificateStore([Self.intermediate1, Self.ca2CrossSignedByCA1, Self.ca1CrossSignedByCA2]),
            diagnosticCallback: log.append(_:)
        )

        guard case .validCertificate(let chain) = result else {
            XCTFail("Failed to validate: \(result)")
            return
        }

        XCTAssertEqual(chain, [Self.localhostLeaf, Self.intermediate1, Self.ca1])
        XCTAssertEqual(
            log,
            [
                .searchingForIssuerOfPartialChain([Self.localhostLeaf]),
                .foundCandidateIssuersOfPartialChainInIntermediateStore(
                    [Self.localhostLeaf],
                    issuers: [Self.intermediate1]
                ),
                .searchingForIssuerOfPartialChain([Self.localhostLeaf, Self.intermediate1]),
                .foundCandidateIssuersOfPartialChainInRootStore(
                    [Self.localhostLeaf, Self.intermediate1],
                    issuers: [Self.ca1]
                ),
                .foundValidCertificateChain([Self.localhostLeaf, Self.intermediate1, Self.ca1]),
            ]
        )
    }

    func testBuildsTheShorterPathInTheCaseOfCrossSignedRoots() async throws {
        let roots = CertificateStore([Self.ca1, Self.ca2])
        let log = DiagnosticsLog()

        var verifier = Verifier(rootCertificates: roots) { Self.defaultPolicy }
        let result = await verifier.validate(
            leaf: Self.localhostLeaf,
            intermediates: CertificateStore([Self.intermediate1, Self.ca2CrossSignedByCA1, Self.ca1CrossSignedByCA2]),
            diagnosticCallback: log.append(_:)
        )

        guard case .validCertificate(let chain) = result else {
            XCTFail("Failed to validate: \(result)")
            return
        }

        XCTAssertEqual(Array(chain), [Self.localhostLeaf, Self.intermediate1, Self.ca1])
        XCTAssertEqual(
            log,
            [
                .searchingForIssuerOfPartialChain([Self.localhostLeaf]),
                .foundCandidateIssuersOfPartialChainInIntermediateStore(
                    [Self.localhostLeaf],
                    issuers: [Self.intermediate1]
                ),
                .searchingForIssuerOfPartialChain([Self.localhostLeaf, Self.intermediate1]),
                .foundCandidateIssuersOfPartialChainInRootStore(
                    [Self.localhostLeaf, Self.intermediate1],
                    issuers: [Self.ca1]
                ),
                .foundValidCertificateChain([Self.localhostLeaf, Self.intermediate1, Self.ca1]),
            ]
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    func testPrefersToUseIntermediatesWithSKIThatMatchesDeprecated() async throws {
        let roots = CertificateStore([Self.ca1])
        let log = DiagnosticsLog()

        var verifier = Verifier(rootCertificates: roots) { Self.defaultPolicy }
        let result = await verifier.validate(
            leafCertificate: Self.localhostLeaf,
            intermediates: CertificateStore([Self.intermediate1, Self.intermediate1WithoutSKIAKI]),
            diagnosticCallback: log.append(_:)
        )

        guard case .validCertificate(let chain) = result else {
            XCTFail("Failed to validate: \(result)")
            return
        }

        XCTAssertEqual(chain, [Self.localhostLeaf, Self.intermediate1, Self.ca1])
        XCTAssertEqual(
            log,
            [
                .searchingForIssuerOfPartialChain([Self.localhostLeaf]),
                .foundCandidateIssuersOfPartialChainInIntermediateStore(
                    [Self.localhostLeaf],
                    issuers: [Self.intermediate1, Self.intermediate1WithoutSKIAKI]
                ),
                .searchingForIssuerOfPartialChain([Self.localhostLeaf, Self.intermediate1]),
                .foundCandidateIssuersOfPartialChainInRootStore(
                    [Self.localhostLeaf, Self.intermediate1],
                    issuers: [Self.ca1]
                ),
                .foundValidCertificateChain([Self.localhostLeaf, Self.intermediate1, Self.ca1]),
            ]
        )
    }

    func testPrefersToUseIntermediatesWithSKIThatMatches() async throws {
        let roots = CertificateStore([Self.ca1])
        let log = DiagnosticsLog()

        var verifier = Verifier(rootCertificates: roots) { Self.defaultPolicy }
        let result = await verifier.validate(
            leaf: Self.localhostLeaf,
            intermediates: CertificateStore([Self.intermediate1, Self.intermediate1WithoutSKIAKI]),
            diagnosticCallback: log.append(_:)
        )

        guard case .validCertificate(let chain) = result else {
            XCTFail("Failed to validate: \(result)")
            return
        }

        XCTAssertEqual(Array(chain), [Self.localhostLeaf, Self.intermediate1, Self.ca1])
        XCTAssertEqual(
            log,
            [
                .searchingForIssuerOfPartialChain([Self.localhostLeaf]),
                .foundCandidateIssuersOfPartialChainInIntermediateStore(
                    [Self.localhostLeaf],
                    issuers: [Self.intermediate1, Self.intermediate1WithoutSKIAKI]
                ),
                .searchingForIssuerOfPartialChain([Self.localhostLeaf, Self.intermediate1]),
                .foundCandidateIssuersOfPartialChainInRootStore(
                    [Self.localhostLeaf, Self.intermediate1],
                    issuers: [Self.ca1]
                ),
                .foundValidCertificateChain([Self.localhostLeaf, Self.intermediate1, Self.ca1]),
            ]
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    func testPrefersNoSKIToNonMatchingSKIDeprecated() async throws {
        let roots = CertificateStore([Self.ca1])
        let log = DiagnosticsLog()

        var verifier = Verifier(rootCertificates: roots) { Self.defaultPolicy }
        let result = await verifier.validate(
            leafCertificate: Self.localhostLeaf,
            intermediates: CertificateStore([Self.intermediate1WithIncorrectSKIAKI, Self.intermediate1WithoutSKIAKI]),
            diagnosticCallback: log.append(_:)
        )

        guard case .validCertificate(let chain) = result else {
            XCTFail("Failed to validate: \(result)")
            return
        }

        XCTAssertEqual(chain, [Self.localhostLeaf, Self.intermediate1WithoutSKIAKI, Self.ca1])
        XCTAssertEqual(
            log,
            [
                .searchingForIssuerOfPartialChain([Self.localhostLeaf]),
                .foundCandidateIssuersOfPartialChainInIntermediateStore(
                    [Self.localhostLeaf],
                    issuers: [Self.intermediate1WithoutSKIAKI, Self.intermediate1WithIncorrectSKIAKI]
                ),
                .searchingForIssuerOfPartialChain([Self.localhostLeaf, Self.intermediate1WithoutSKIAKI]),
                .foundCandidateIssuersOfPartialChainInRootStore(
                    [Self.localhostLeaf, Self.intermediate1WithoutSKIAKI],
                    issuers: [Self.ca1]
                ),
                .foundValidCertificateChain([Self.localhostLeaf, Self.intermediate1WithoutSKIAKI, Self.ca1]),
            ]
        )
    }

    func testPrefersNoSKIToNonMatchingSKI() async throws {
        let roots = CertificateStore([Self.ca1])
        let log = DiagnosticsLog()

        var verifier = Verifier(rootCertificates: roots) { Self.defaultPolicy }
        let result = await verifier.validate(
            leaf: Self.localhostLeaf,
            intermediates: CertificateStore([Self.intermediate1WithIncorrectSKIAKI, Self.intermediate1WithoutSKIAKI]),
            diagnosticCallback: log.append(_:)
        )

        guard case .validCertificate(let chain) = result else {
            XCTFail("Failed to validate: \(result)")
            return
        }

        XCTAssertEqual(Array(chain), [Self.localhostLeaf, Self.intermediate1WithoutSKIAKI, Self.ca1])
        XCTAssertEqual(
            log,
            [
                .searchingForIssuerOfPartialChain([Self.localhostLeaf]),
                .foundCandidateIssuersOfPartialChainInIntermediateStore(
                    [Self.localhostLeaf],
                    issuers: [Self.intermediate1WithoutSKIAKI, Self.intermediate1WithIncorrectSKIAKI]
                ),
                .searchingForIssuerOfPartialChain([Self.localhostLeaf, Self.intermediate1WithoutSKIAKI]),
                .foundCandidateIssuersOfPartialChainInRootStore(
                    [Self.localhostLeaf, Self.intermediate1WithoutSKIAKI],
                    issuers: [Self.ca1]
                ),
                .foundValidCertificateChain([Self.localhostLeaf, Self.intermediate1WithoutSKIAKI, Self.ca1]),
            ]
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    func testRejectsRootsThatDidNotSignTheCertBeforeThemDeprecated() async throws {
        let roots = CertificateStore([Self.ca1WithAlternativePrivateKey, Self.ca2])
        let log = DiagnosticsLog()

        var verifier = Verifier(rootCertificates: roots) { Self.defaultPolicy }
        let result = await verifier.validate(
            leafCertificate: Self.localhostLeaf,
            intermediates: CertificateStore([Self.ca1CrossSignedByCA2, Self.ca2CrossSignedByCA1, Self.intermediate1]),
            diagnosticCallback: log.append(_:)
        )

        guard case .validCertificate(let chain) = result else {
            XCTFail("Failed to validate: \(result)")
            return
        }

        XCTAssertEqual(chain, [Self.localhostLeaf, Self.intermediate1, Self.ca1CrossSignedByCA2, Self.ca2])
        XCTAssertEqual(
            log,
            [
                .searchingForIssuerOfPartialChain([Self.localhostLeaf]),
                .foundCandidateIssuersOfPartialChainInIntermediateStore(
                    [Self.localhostLeaf],
                    issuers: [Self.intermediate1]
                ),
                .searchingForIssuerOfPartialChain([Self.localhostLeaf, Self.intermediate1]),
                .foundCandidateIssuersOfPartialChainInRootStore(
                    [Self.localhostLeaf, Self.intermediate1],
                    issuers: [Self.ca1WithAlternativePrivateKey]
                ),
                .issuerHasNotSignedCertificate(
                    Self.ca1WithAlternativePrivateKey,
                    partialChain: [Self.localhostLeaf, Self.intermediate1]
                ),
                .foundCandidateIssuersOfPartialChainInIntermediateStore(
                    [Self.localhostLeaf, Self.intermediate1],
                    issuers: [Self.ca1CrossSignedByCA2]
                ),
                .searchingForIssuerOfPartialChain([Self.localhostLeaf, Self.intermediate1, Self.ca1CrossSignedByCA2]),
                .foundCandidateIssuersOfPartialChainInRootStore(
                    [Self.localhostLeaf, Self.intermediate1, Self.ca1CrossSignedByCA2],
                    issuers: [Self.ca2]
                ),
                .foundValidCertificateChain([
                    Self.localhostLeaf, Self.intermediate1, Self.ca1CrossSignedByCA2, Self.ca2,
                ]),
            ]
        )
    }

    func testRejectsRootsThatDidNotSignTheCertBeforeThem() async throws {
        let roots = CertificateStore([Self.ca1WithAlternativePrivateKey, Self.ca2])
        let log = DiagnosticsLog()

        var verifier = Verifier(rootCertificates: roots) { Self.defaultPolicy }
        let result = await verifier.validate(
            leaf: Self.localhostLeaf,
            intermediates: CertificateStore([Self.ca1CrossSignedByCA2, Self.ca2CrossSignedByCA1, Self.intermediate1]),
            diagnosticCallback: log.append(_:)
        )

        guard case .validCertificate(let chain) = result else {
            XCTFail("Failed to validate: \(result)")
            return
        }

        XCTAssertEqual(Array(chain), [Self.localhostLeaf, Self.intermediate1, Self.ca1CrossSignedByCA2, Self.ca2])
        XCTAssertEqual(
            log,
            [
                .searchingForIssuerOfPartialChain([Self.localhostLeaf]),
                .foundCandidateIssuersOfPartialChainInIntermediateStore(
                    [Self.localhostLeaf],
                    issuers: [Self.intermediate1]
                ),
                .searchingForIssuerOfPartialChain([Self.localhostLeaf, Self.intermediate1]),
                .foundCandidateIssuersOfPartialChainInRootStore(
                    [Self.localhostLeaf, Self.intermediate1],
                    issuers: [Self.ca1WithAlternativePrivateKey]
                ),
                .issuerHasNotSignedCertificate(
                    Self.ca1WithAlternativePrivateKey,
                    partialChain: [Self.localhostLeaf, Self.intermediate1]
                ),
                .foundCandidateIssuersOfPartialChainInIntermediateStore(
                    [Self.localhostLeaf, Self.intermediate1],
                    issuers: [Self.ca1CrossSignedByCA2]
                ),
                .searchingForIssuerOfPartialChain([Self.localhostLeaf, Self.intermediate1, Self.ca1CrossSignedByCA2]),
                .foundCandidateIssuersOfPartialChainInRootStore(
                    [Self.localhostLeaf, Self.intermediate1, Self.ca1CrossSignedByCA2],
                    issuers: [Self.ca2]
                ),
                .foundValidCertificateChain([
                    Self.localhostLeaf, Self.intermediate1, Self.ca1CrossSignedByCA2, Self.ca2,
                ]),
            ]
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    func testPolicyFailuresCanFindLongerPathsDeprecated() async throws {
        let roots = CertificateStore([Self.ca1, Self.ca2])
        let log = DiagnosticsLog()

        var verifier = Verifier(rootCertificates: roots) {
            FailIfCertInChainPolicy(forbiddenCert: Self.ca1)
            Self.defaultPolicy
        }
        let result = await verifier.validate(
            leafCertificate: Self.localhostLeaf,
            intermediates: CertificateStore([Self.intermediate1, Self.ca2CrossSignedByCA1, Self.ca1CrossSignedByCA2]),
            diagnosticCallback: log.append(_:)
        )

        guard case .validCertificate(let chain) = result else {
            XCTFail("Failed to validate: \(result)")
            return
        }

        XCTAssertEqual(chain, [Self.localhostLeaf, Self.intermediate1, Self.ca1CrossSignedByCA2, Self.ca2])

        XCTAssertEqual(
            log,
            [
                .searchingForIssuerOfPartialChain([Self.localhostLeaf]),
                .foundCandidateIssuersOfPartialChainInIntermediateStore(
                    [Self.localhostLeaf],
                    issuers: [Self.intermediate1]
                ),
                .searchingForIssuerOfPartialChain([Self.localhostLeaf, Self.intermediate1]),
                .foundCandidateIssuersOfPartialChainInRootStore(
                    [Self.localhostLeaf, Self.intermediate1],
                    issuers: [Self.ca1]
                ),
                .chainFailsToMeetPolicy(
                    UnverifiedCertificateChain([Self.localhostLeaf, Self.intermediate1, Self.ca1]),
                    reason: .init("chain must not contain forbidden certificate")
                ),
                .foundCandidateIssuersOfPartialChainInIntermediateStore(
                    [Self.localhostLeaf, Self.intermediate1],
                    issuers: [Self.ca1CrossSignedByCA2]
                ),
                .searchingForIssuerOfPartialChain([Self.localhostLeaf, Self.intermediate1, Self.ca1CrossSignedByCA2]),
                .foundCandidateIssuersOfPartialChainInRootStore(
                    [Self.localhostLeaf, Self.intermediate1, Self.ca1CrossSignedByCA2],
                    issuers: [Self.ca2]
                ),
                .foundValidCertificateChain([
                    Self.localhostLeaf, Self.intermediate1, Self.ca1CrossSignedByCA2, Self.ca2,
                ]),
            ]
        )
    }

    func testPolicyFailuresCanFindLongerPaths() async throws {
        let roots = CertificateStore([Self.ca1, Self.ca2])
        let log = DiagnosticsLog()

        var verifier = Verifier(rootCertificates: roots) {
            FailIfCertInChainPolicy(forbiddenCert: Self.ca1)
            Self.defaultPolicy
        }
        let result = await verifier.validate(
            leaf: Self.localhostLeaf,
            intermediates: CertificateStore([Self.intermediate1, Self.ca2CrossSignedByCA1, Self.ca1CrossSignedByCA2]),
            diagnosticCallback: log.append(_:)
        )

        guard case .validCertificate(let chain) = result else {
            XCTFail("Failed to validate: \(result)")
            return
        }

        XCTAssertEqual(Array(chain), [Self.localhostLeaf, Self.intermediate1, Self.ca1CrossSignedByCA2, Self.ca2])

        XCTAssertEqual(
            log,
            [
                .searchingForIssuerOfPartialChain([Self.localhostLeaf]),
                .foundCandidateIssuersOfPartialChainInIntermediateStore(
                    [Self.localhostLeaf],
                    issuers: [Self.intermediate1]
                ),
                .searchingForIssuerOfPartialChain([Self.localhostLeaf, Self.intermediate1]),
                .foundCandidateIssuersOfPartialChainInRootStore(
                    [Self.localhostLeaf, Self.intermediate1],
                    issuers: [Self.ca1]
                ),
                .chainFailsToMeetPolicy(
                    UnverifiedCertificateChain([Self.localhostLeaf, Self.intermediate1, Self.ca1]),
                    reason: .init("chain must not contain forbidden certificate")
                ),
                .foundCandidateIssuersOfPartialChainInIntermediateStore(
                    [Self.localhostLeaf, Self.intermediate1],
                    issuers: [Self.ca1CrossSignedByCA2]
                ),
                .searchingForIssuerOfPartialChain([Self.localhostLeaf, Self.intermediate1, Self.ca1CrossSignedByCA2]),
                .foundCandidateIssuersOfPartialChainInRootStore(
                    [Self.localhostLeaf, Self.intermediate1, Self.ca1CrossSignedByCA2],
                    issuers: [Self.ca2]
                ),
                .foundValidCertificateChain([
                    Self.localhostLeaf, Self.intermediate1, Self.ca1CrossSignedByCA2, Self.ca2,
                ]),
            ]
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    func testInsanePKICanStillBuildDeprecated() async throws {
        let roots = CertificateStore([Self.ca1])
        let intermediates = CertificateStore([Self.t1, Self.t2, Self.t3, Self.x2, Self.x1])
        let log = DiagnosticsLog()

        var verifier = Verifier(rootCertificates: roots) { Self.defaultPolicy }
        let result = await verifier.validate(
            leafCertificate: Self.insaneLeaf,
            intermediates: intermediates,
            diagnosticCallback: log.append(_:)
        )

        guard case .validCertificate(let chain) = result else {
            XCTFail("Failed to validate: \(result)")
            return
        }

        XCTAssertEqual(chain, [Self.insaneLeaf, Self.t3, Self.x2, Self.t2, Self.x1, Self.t1, Self.ca1])

        XCTAssertEqual(
            log,
            [
                .searchingForIssuerOfPartialChain([Self.insaneLeaf]),
                .foundCandidateIssuersOfPartialChainInIntermediateStore(
                    [Self.insaneLeaf],
                    issuers: [Self.t3, Self.t2, Self.t1]
                ),
                .issuerHasNotSignedCertificate(Self.t1, partialChain: [Self.insaneLeaf]),
                .issuerHasNotSignedCertificate(Self.t2, partialChain: [Self.insaneLeaf]),
                .searchingForIssuerOfPartialChain([Self.insaneLeaf, Self.t3]),
                .foundCandidateIssuersOfPartialChainInIntermediateStore(
                    [Self.insaneLeaf, Self.t3],
                    issuers: [Self.x2, Self.x1]
                ),
                .searchingForIssuerOfPartialChain([Self.insaneLeaf, Self.t3, Self.x2]),
                .foundCandidateIssuersOfPartialChainInIntermediateStore(
                    [Self.insaneLeaf, Self.t3, Self.x2],
                    issuers: [Self.t3, Self.t2, Self.t1]
                ),
                .issuerIsAlreadyInTheChain([Self.insaneLeaf, Self.t3, Self.x2], issuer: Self.t3),
                .searchingForIssuerOfPartialChain([Self.insaneLeaf, Self.t3, Self.x2, Self.t2]),
                .foundCandidateIssuersOfPartialChainInIntermediateStore(
                    [Self.insaneLeaf, Self.t3, Self.x2, Self.t2],
                    issuers: [Self.x2, Self.x1]
                ),
                .issuerIsAlreadyInTheChain([Self.insaneLeaf, Self.t3, Self.x2, Self.t2], issuer: Self.x2),
                .searchingForIssuerOfPartialChain([Self.insaneLeaf, Self.t3, Self.x2, Self.t2, Self.x1]),
                .foundCandidateIssuersOfPartialChainInIntermediateStore(
                    [Self.insaneLeaf, Self.t3, Self.x2, Self.t2, Self.x1],
                    issuers: [Self.t3, Self.t2, Self.t1]
                ),
                .issuerIsAlreadyInTheChain([Self.insaneLeaf, Self.t3, Self.x2, Self.t2, Self.x1], issuer: Self.t2),
                .issuerIsAlreadyInTheChain([Self.insaneLeaf, Self.t3, Self.x2, Self.t2, Self.x1], issuer: Self.t3),
                .searchingForIssuerOfPartialChain([Self.insaneLeaf, Self.t3, Self.x2, Self.t2, Self.x1, Self.t1]),
                .foundCandidateIssuersOfPartialChainInRootStore(
                    [Self.insaneLeaf, Self.t3, Self.x2, Self.t2, Self.x1, Self.t1],
                    issuers: [Self.ca1]
                ),
                .foundValidCertificateChain([Self.insaneLeaf, Self.t3, Self.x2, Self.t2, Self.x1, Self.t1, Self.ca1]),
            ]
        )
    }

    func testInsanePKICanStillBuild() async throws {
        let roots = CertificateStore([Self.ca1])
        let intermediates = CertificateStore([Self.t1, Self.t2, Self.t3, Self.x2, Self.x1])
        let log = DiagnosticsLog()

        var verifier = Verifier(rootCertificates: roots) { Self.defaultPolicy }
        let result = await verifier.validate(
            leaf: Self.insaneLeaf,
            intermediates: intermediates,
            diagnosticCallback: log.append(_:)
        )

        guard case .validCertificate(let chain) = result else {
            XCTFail("Failed to validate: \(result)")
            return
        }

        XCTAssertEqual(Array(chain), [Self.insaneLeaf, Self.t3, Self.x2, Self.t2, Self.x1, Self.t1, Self.ca1])

        XCTAssertEqual(
            log,
            [
                .searchingForIssuerOfPartialChain([Self.insaneLeaf]),
                .foundCandidateIssuersOfPartialChainInIntermediateStore(
                    [Self.insaneLeaf],
                    issuers: [Self.t3, Self.t2, Self.t1]
                ),
                .issuerHasNotSignedCertificate(Self.t1, partialChain: [Self.insaneLeaf]),
                .issuerHasNotSignedCertificate(Self.t2, partialChain: [Self.insaneLeaf]),
                .searchingForIssuerOfPartialChain([Self.insaneLeaf, Self.t3]),
                .foundCandidateIssuersOfPartialChainInIntermediateStore(
                    [Self.insaneLeaf, Self.t3],
                    issuers: [Self.x2, Self.x1]
                ),
                .searchingForIssuerOfPartialChain([Self.insaneLeaf, Self.t3, Self.x2]),
                .foundCandidateIssuersOfPartialChainInIntermediateStore(
                    [Self.insaneLeaf, Self.t3, Self.x2],
                    issuers: [Self.t3, Self.t2, Self.t1]
                ),
                .issuerIsAlreadyInTheChain([Self.insaneLeaf, Self.t3, Self.x2], issuer: Self.t3),
                .searchingForIssuerOfPartialChain([Self.insaneLeaf, Self.t3, Self.x2, Self.t2]),
                .foundCandidateIssuersOfPartialChainInIntermediateStore(
                    [Self.insaneLeaf, Self.t3, Self.x2, Self.t2],
                    issuers: [Self.x2, Self.x1]
                ),
                .issuerIsAlreadyInTheChain([Self.insaneLeaf, Self.t3, Self.x2, Self.t2], issuer: Self.x2),
                .searchingForIssuerOfPartialChain([Self.insaneLeaf, Self.t3, Self.x2, Self.t2, Self.x1]),
                .foundCandidateIssuersOfPartialChainInIntermediateStore(
                    [Self.insaneLeaf, Self.t3, Self.x2, Self.t2, Self.x1],
                    issuers: [Self.t3, Self.t2, Self.t1]
                ),
                .issuerIsAlreadyInTheChain([Self.insaneLeaf, Self.t3, Self.x2, Self.t2, Self.x1], issuer: Self.t2),
                .issuerIsAlreadyInTheChain([Self.insaneLeaf, Self.t3, Self.x2, Self.t2, Self.x1], issuer: Self.t3),
                .searchingForIssuerOfPartialChain([Self.insaneLeaf, Self.t3, Self.x2, Self.t2, Self.x1, Self.t1]),
                .foundCandidateIssuersOfPartialChainInRootStore(
                    [Self.insaneLeaf, Self.t3, Self.x2, Self.t2, Self.x1, Self.t1],
                    issuers: [Self.ca1]
                ),
                .foundValidCertificateChain([Self.insaneLeaf, Self.t3, Self.x2, Self.t2, Self.x1, Self.t1, Self.ca1]),
            ]
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    func testSelfSignedCertsAreRejectedWhenNotInTheTrustStoreDeprecated() async throws {
        let roots = CertificateStore([Self.ca1])
        let log = DiagnosticsLog()

        var verifier = Verifier(rootCertificates: roots) { Self.defaultPolicy }
        let result = await verifier.validate(
            leafCertificate: Self.isolatedSelfSignedCert,
            intermediates: CertificateStore([Self.intermediate1]),
            diagnosticCallback: log.append(_:)
        )

        guard case .couldNotValidate = result else {
            XCTFail("Incorrectly validated: \(result)")
            return
        }

        XCTAssertEqual(
            log,
            [
                .searchingForIssuerOfPartialChain([Self.isolatedSelfSignedCert]),
                .couldNotValidateLeafCertificate(Self.isolatedSelfSignedCert),
            ]
        )
    }

    func testSelfSignedCertsAreRejectedWhenNotInTheTrustStore() async throws {
        let roots = CertificateStore([Self.ca1])
        let log = DiagnosticsLog()

        var verifier = Verifier(rootCertificates: roots) { Self.defaultPolicy }
        let result = await verifier.validate(
            leaf: Self.isolatedSelfSignedCert,
            intermediates: CertificateStore([Self.intermediate1]),
            diagnosticCallback: log.append(_:)
        )

        guard case .couldNotValidate = result else {
            XCTFail("Incorrectly validated: \(result)")
            return
        }

        XCTAssertEqual(
            log,
            [
                .searchingForIssuerOfPartialChain([Self.isolatedSelfSignedCert]),
                .couldNotValidateLeafCertificate(Self.isolatedSelfSignedCert),
            ]
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    func testSelfSignedCertsAreTrustedWhenInTrustStoreDeprecated() async throws {
        let roots = CertificateStore([Self.ca1, Self.isolatedSelfSignedCert])
        let log = DiagnosticsLog()

        var verifier = Verifier(rootCertificates: roots) { Self.defaultPolicy }
        let result = await verifier.validate(
            leafCertificate: Self.isolatedSelfSignedCert,
            intermediates: CertificateStore([Self.intermediate1]),
            diagnosticCallback: log.append(_:)
        )

        guard case .validCertificate(let chain) = result else {
            XCTFail("Failed to validate: \(result)")
            return
        }

        XCTAssertEqual(chain, [Self.isolatedSelfSignedCert])
        XCTAssertEqual(
            log,
            [
                .foundValidCertificateChain([Self.isolatedSelfSignedCert])
            ]
        )
    }

    func testSelfSignedCertsAreTrustedWhenInTrustStore() async throws {
        let roots = CertificateStore([Self.ca1, Self.isolatedSelfSignedCert])
        let log = DiagnosticsLog()

        var verifier = Verifier(rootCertificates: roots) { Self.defaultPolicy }
        let result = await verifier.validate(
            leaf: Self.isolatedSelfSignedCert,
            intermediates: CertificateStore([Self.intermediate1]),
            diagnosticCallback: log.append(_:)
        )

        guard case .validCertificate(let chain) = result else {
            XCTFail("Failed to validate: \(result)")
            return
        }

        XCTAssertEqual(Array(chain), [Self.isolatedSelfSignedCert])
        XCTAssertEqual(
            log,
            [
                .foundValidCertificateChain([Self.isolatedSelfSignedCert])
            ]
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    func testTrustRootsCanBeNonSelfSignedLeavesDeprecated() async throws {
        // we use a custom policy here to ignore the fact that the basic constraints extension is critical.
        struct IgnoreBasicConstraintsPolicy: VerifierPolicy {
            let verifyingCriticalExtensions: [ASN1ObjectIdentifier] = [.X509ExtensionID.basicConstraints]

            func chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain) async -> PolicyEvaluationResult {
                return .meetsPolicy
            }
        }

        let roots = CertificateStore([Self.localhostLeaf])
        let log = DiagnosticsLog()

        var verifier = Verifier(rootCertificates: roots) { IgnoreBasicConstraintsPolicy() }
        let result = await verifier.validate(
            leafCertificate: Self.localhostLeaf,
            intermediates: CertificateStore([Self.intermediate1]),
            diagnosticCallback: log.append(_:)
        )

        guard case .validCertificate(let chain) = result else {
            XCTFail("Failed to validate: \(result)")
            return
        }

        XCTAssertEqual(chain, [Self.localhostLeaf])
        XCTAssertEqual(
            log,
            [
                .foundValidCertificateChain([Self.localhostLeaf])
            ]
        )
    }

    func testTrustRootsCanBeNonSelfSignedLeaves() async throws {
        // we use a custom policy here to ignore the fact that the basic constraints extension is critical.
        struct IgnoreBasicConstraintsPolicy: VerifierPolicy {
            let verifyingCriticalExtensions: [ASN1ObjectIdentifier] = [.X509ExtensionID.basicConstraints]

            func chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain) async -> PolicyEvaluationResult {
                return .meetsPolicy
            }
        }

        let roots = CertificateStore([Self.localhostLeaf])
        let log = DiagnosticsLog()

        var verifier = Verifier(rootCertificates: roots) { IgnoreBasicConstraintsPolicy() }
        let result = await verifier.validate(
            leaf: Self.localhostLeaf,
            intermediates: CertificateStore([Self.intermediate1]),
            diagnosticCallback: log.append(_:)
        )

        guard case .validCertificate(let chain) = result else {
            XCTFail("Failed to validate: \(result)")
            return
        }

        XCTAssertEqual(Array(chain), [Self.localhostLeaf])
        XCTAssertEqual(
            log,
            [
                .foundValidCertificateChain([Self.localhostLeaf])
            ]
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    func testTrustRootsCanBeNonSelfSignedIntermediatesDeprecated() async throws {
        let roots = CertificateStore([Self.intermediate1])
        let log = DiagnosticsLog()

        var verifier = Verifier(rootCertificates: roots) { Self.defaultPolicy }
        let result = await verifier.validate(
            leafCertificate: Self.localhostLeaf,
            intermediates: CertificateStore([Self.intermediate1]),
            diagnosticCallback: log.append(_:)
        )

        guard case .validCertificate(let chain) = result else {
            XCTFail("Failed to validate: \(result)")
            return
        }

        XCTAssertEqual(chain, [Self.localhostLeaf, Self.intermediate1])
        XCTAssertEqual(
            log,
            [
                .searchingForIssuerOfPartialChain([Self.localhostLeaf]),
                .foundCandidateIssuersOfPartialChainInRootStore([Self.localhostLeaf], issuers: [Self.intermediate1]),
                .foundValidCertificateChain([Self.localhostLeaf, Self.intermediate1]),
            ]
        )
    }

    func testTrustRootsCanBeNonSelfSignedIntermediates() async throws {
        let roots = CertificateStore([Self.intermediate1])
        let log = DiagnosticsLog()

        var verifier = Verifier(rootCertificates: roots) { Self.defaultPolicy }
        let result = await verifier.validate(
            leaf: Self.localhostLeaf,
            intermediates: CertificateStore([Self.intermediate1]),
            diagnosticCallback: log.append(_:)
        )

        guard case .validCertificate(let chain) = result else {
            XCTFail("Failed to validate: \(result)")
            return
        }

        XCTAssertEqual(Array(chain), [Self.localhostLeaf, Self.intermediate1])
        XCTAssertEqual(
            log,
            [
                .searchingForIssuerOfPartialChain([Self.localhostLeaf]),
                .foundCandidateIssuersOfPartialChainInRootStore([Self.localhostLeaf], issuers: [Self.intermediate1]),
                .foundValidCertificateChain([Self.localhostLeaf, Self.intermediate1]),
            ]
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    func testWePoliceCriticalExtensionsOnLeafCertsDeprecated() async throws {
        let roots = CertificateStore([Self.ca1, Self.isolatedSelfSignedCertWithWeirdCriticalExtension])
        let log = DiagnosticsLog()

        var verifier = Verifier(rootCertificates: roots) { Self.defaultPolicy }
        let result = await verifier.validate(
            leafCertificate: Self.isolatedSelfSignedCertWithWeirdCriticalExtension,
            intermediates: CertificateStore([Self.intermediate1]),
            diagnosticCallback: log.append(_:)
        )

        guard case .couldNotValidate = result else {
            XCTFail("Incorrectly validated: \(result)")
            return
        }

        XCTAssertEqual(
            log,
            [
                .leafCertificateHasUnhandledCriticalExtension(
                    Self.isolatedSelfSignedCertWithWeirdCriticalExtension,
                    handledCriticalExtensions: Self.defaultPolicy.verifyingCriticalExtensions
                )
            ]
        )
    }

    func testWePoliceCriticalExtensionsOnLeafCerts() async throws {
        let roots = CertificateStore([Self.ca1, Self.isolatedSelfSignedCertWithWeirdCriticalExtension])
        let log = DiagnosticsLog()

        var verifier = Verifier(rootCertificates: roots) { Self.defaultPolicy }
        let result = await verifier.validate(
            leaf: Self.isolatedSelfSignedCertWithWeirdCriticalExtension,
            intermediates: CertificateStore([Self.intermediate1]),
            diagnosticCallback: log.append(_:)
        )

        guard case .couldNotValidate = result else {
            XCTFail("Incorrectly validated: \(result)")
            return
        }

        XCTAssertEqual(
            log,
            [
                .leafCertificateHasUnhandledCriticalExtension(
                    Self.isolatedSelfSignedCertWithWeirdCriticalExtension,
                    handledCriticalExtensions: Self.defaultPolicy.verifyingCriticalExtensions
                )
            ]
        )
    }

    func testVerificationDiagnosticDescriptionDoesNotIncludeNewLines() {
        let diagnostics: [VerificationDiagnostic] = [
            .init(
                storage: .leafCertificateHasUnhandledCriticalExtension(
                    Self.localhostLeaf,
                    handledCriticalExtensions: [.cmsData, .cmsSignedData]
                )
            ),
            .init(
                storage: .leafCertificateIsInTheRootStoreButDoesNotMeetPolicy(
                    Self.localhostLeaf,
                    reason: .init("policy failure reason")
                )
            ),
            .init(
                storage: .chainFailsToMeetPolicy(
                    .init([Self.localhostLeaf, Self.ca1]),
                    reason: .init("policy failure reason")
                )
            ),
            .init(storage: .issuerHasNotSignedCertificate(Self.intermediate1, partialChain: [Self.localhostLeaf])),
            .init(
                storage: .issuerHasUnhandledCriticalExtension(
                    issuer: Self.intermediate1,
                    partialChain: [Self.localhostLeaf],
                    handledCriticalExtensions: [.cmsData, .cmsSignedData]
                )
            ),
            .init(storage: .searchingForIssuerOfPartialChain([Self.localhostLeaf, Self.intermediate1])),
            .init(
                storage: .foundCandidateIssuersOfPartialChainInRootStore(
                    [Self.localhostLeaf, Self.intermediate1],
                    issuers: [Self.ca1, Self.ca1WithAlternativePrivateKey]
                )
            ),
            .init(
                storage: .foundCandidateIssuersOfPartialChainInIntermediateStore(
                    [Self.insaneLeaf, Self.t3],
                    issuers: [Self.x1, Self.x2]
                )
            ),
            .init(storage: .foundValidCertificateChain([Self.localhostLeaf, Self.intermediate1, Self.ca1])),
            .init(storage: .couldNotValidateLeafCertificate(Self.localhostLeaf)),
            .init(storage: .issuerIsAlreadyInTheChain([Self.insaneLeaf, Self.t3, Self.x2], issuer: Self.t3)),
        ]
        for diagnostic in diagnostics {
            let description = diagnostic.description
            XCTAssertFalse(
                description.contains { $0 == "\n" },
                "Diagnostic description contains new line: \(description)"
            )
        }
    }
}

private struct FailIfCalledPolicy: VerifierPolicy {
    let verifyingCriticalExtensions: [ASN1ObjectIdentifier] = []

    mutating func chainMeetsPolicyRequirements(
        chain: X509.UnverifiedCertificateChain
    ) async -> X509.PolicyEvaluationResult {
        XCTFail("Policy was called with chain \(chain)")
        return .failsToMeetPolicy(reason: "policy must not be called")
    }
}

private struct FailIfCertInChainPolicy: VerifierPolicy {
    let verifyingCriticalExtensions: [ASN1ObjectIdentifier] = []

    private let forbiddenCert: Certificate

    init(forbiddenCert: Certificate) {
        self.forbiddenCert = forbiddenCert
    }

    mutating func chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain) async -> PolicyEvaluationResult {
        guard chain.contains(self.forbiddenCert) else {
            return .meetsPolicy
        }
        return .failsToMeetPolicy(reason: "chain must not contain forbidden certificate")
    }
}

extension TimeInterval {
    private static let oneDay: TimeInterval = 60 * 60 * 24

    static func days(_ days: Int) -> TimeInterval {
        return Double(days) * oneDay
    }
}

final class DiagnosticsLog {
    var diagnostics: [VerificationDiagnostic.Storage] = []
    var count: Int {
        diagnostics.count
    }
    init(diagnostics: [VerificationDiagnostic.Storage]) {
        self.diagnostics = diagnostics
    }
    func append(_ diagnostic: VerificationDiagnostic) {
        diagnostics.append(diagnostic.storage)
    }
}

extension DiagnosticsLog: CustomDebugStringConvertible {
    var debugDescription: String {
        """
        \(self.diagnostics.enumerated().map {
            """
            \($0.0 + 1). ---------------------------------------------------------------------------------
            \($0.1.multilineDescription)
            """
        }.joined(separator: "\n"))
        """
    }
}

extension DiagnosticsLog: Equatable {
    static func == (lhs: DiagnosticsLog, rhs: DiagnosticsLog) -> Bool {
        lhs.diagnostics == rhs.diagnostics
    }
}

extension DiagnosticsLog: ExpressibleByArrayLiteral {
    convenience init(arrayLiteral elements: VerificationDiagnostic.Storage...) {
        self.init(diagnostics: elements)
    }
}
