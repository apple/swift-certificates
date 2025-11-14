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

import Benchmark
@_spi(FixedExpiryValidationTime) import X509
import Foundation
import Crypto
import SwiftASN1

public func verifier() async {
    var counts = 0

    counts += await testAllSuccessfulValidations()
    counts += await testAllUnsuccessfulValidations()

    blackHole(counts)
}

// MARK: - successful validation

func testAllSuccessfulValidations() async -> Int {
    var counts = 0
    counts += await testTrivialChainBuilding()
    counts += await testExtraRootsAreIgnored()
    counts += await testPuttingRootsInTheIntermediariesIsntAProblem()
    counts += await testSupportsCrossSignedRootWithoutTrouble()
    counts += await testBuildsTheShorterPathInTheCaseOfCrossSignedRoots()
    counts += await testPrefersToUseIntermediatesWithSKIThatMatches()
    counts += await testPrefersNoSKIToNonMatchingSKI()
    counts += await testRejectsRootsThatDidNotSignTheCertBeforeThem()
    counts += await testPolicyFailuresCanFindLongerPaths()
    counts += await testSelfSignedCertsAreTrustedWhenInTrustStore()
    counts += await testTrustRootsCanBeNonSelfSignedLeaves()
    counts += await testTrustRootsCanBeNonSelfSignedIntermediates()
    return counts
}

func testTrivialChainBuilding() async -> Int {
    let roots = CertificateStore([TestCertificate.ca1])

    var verifier = Verifier(rootCertificates: roots) {
        RFC5280Policy(fixedExpiryValidationTime: TestCertificate.referenceTime)
    }
    let result = await verifier.validate(
        leaf: TestCertificate.localhostLeaf,
        intermediates: CertificateStore([TestCertificate.intermediate1])
    )

    guard case .validCertificate(let chain) = result else {
        fatalError("Failed to validate: \(result)")
    }

    return chain.count
}

func testExtraRootsAreIgnored() async -> Int {
    let roots = CertificateStore([TestCertificate.ca1, TestCertificate.ca2])

    var verifier = Verifier(rootCertificates: roots) {
        RFC5280Policy(fixedExpiryValidationTime: TestCertificate.referenceTime)
    }
    let result = await verifier.validate(
        leaf: TestCertificate.localhostLeaf,
        intermediates: CertificateStore([TestCertificate.intermediate1])
    )

    guard case .validCertificate(let chain) = result else {
        fatalError("Failed to validate: \(result)")
    }

    return chain.count
}

func testPuttingRootsInTheIntermediariesIsntAProblem() async -> Int {
    let roots = CertificateStore([TestCertificate.ca1, TestCertificate.ca2])

    var verifier = Verifier(rootCertificates: roots) {
        RFC5280Policy(fixedExpiryValidationTime: TestCertificate.referenceTime)
    }
    let result = await verifier.validate(
        leaf: TestCertificate.localhostLeaf,
        intermediates: CertificateStore([TestCertificate.intermediate1, TestCertificate.ca1, TestCertificate.ca2])
    )

    guard case .validCertificate(let chain) = result else {
        fatalError("Failed to validate: \(result)")
    }

    return chain.count
}

func testSupportsCrossSignedRootWithoutTrouble() async -> Int {
    let roots = CertificateStore([TestCertificate.ca2])

    var verifier = Verifier(rootCertificates: roots) {
        RFC5280Policy(fixedExpiryValidationTime: TestCertificate.referenceTime)
    }
    let result = await verifier.validate(
        leaf: TestCertificate.localhostLeaf,
        intermediates: CertificateStore([TestCertificate.intermediate1, TestCertificate.ca1CrossSignedByCA2])
    )

    guard case .validCertificate(let chain) = result else {
        fatalError("Failed to validate: \(result)")
    }

    return chain.count
}

func testBuildsTheShorterPathInTheCaseOfCrossSignedRoots() async -> Int {
    let roots = CertificateStore([TestCertificate.ca1, TestCertificate.ca2])

    var verifier = Verifier(rootCertificates: roots) {
        RFC5280Policy(fixedExpiryValidationTime: TestCertificate.referenceTime)
    }
    let result = await verifier.validate(
        leaf: TestCertificate.localhostLeaf,
        intermediates: CertificateStore([
            TestCertificate.intermediate1, TestCertificate.ca2CrossSignedByCA1, TestCertificate.ca1CrossSignedByCA2,
        ])
    )

    guard case .validCertificate(let chain) = result else {
        fatalError("Failed to validate: \(result)")
    }

    return chain.count
}

func testPrefersToUseIntermediatesWithSKIThatMatches() async -> Int {
    let roots = CertificateStore([TestCertificate.ca1])

    var verifier = Verifier(rootCertificates: roots) {
        RFC5280Policy(fixedExpiryValidationTime: TestCertificate.referenceTime)
    }
    let result = await verifier.validate(
        leaf: TestCertificate.localhostLeaf,
        intermediates: CertificateStore([TestCertificate.intermediate1, TestCertificate.intermediate1WithoutSKIAKI])
    )

    guard case .validCertificate(let chain) = result else {
        fatalError("Failed to validate: \(result)")
    }

    return chain.count
}

func testPrefersNoSKIToNonMatchingSKI() async -> Int {
    let roots = CertificateStore([TestCertificate.ca1])

    var verifier = Verifier(rootCertificates: roots) {
        RFC5280Policy(fixedExpiryValidationTime: TestCertificate.referenceTime)
    }
    let result = await verifier.validate(
        leaf: TestCertificate.localhostLeaf,
        intermediates: CertificateStore([
            TestCertificate.intermediate1WithIncorrectSKIAKI, TestCertificate.intermediate1WithoutSKIAKI,
        ])
    )

    guard case .validCertificate(let chain) = result else {
        fatalError("Failed to validate: \(result)")
    }

    return chain.count
}

func testRejectsRootsThatDidNotSignTheCertBeforeThem() async -> Int {
    let roots = CertificateStore([TestCertificate.ca1WithAlternativePrivateKey, TestCertificate.ca2])

    var verifier = Verifier(rootCertificates: roots) {
        RFC5280Policy(fixedExpiryValidationTime: TestCertificate.referenceTime)
    }
    let result = await verifier.validate(
        leaf: TestCertificate.localhostLeaf,
        intermediates: CertificateStore([
            TestCertificate.ca1CrossSignedByCA2, TestCertificate.ca2CrossSignedByCA1, TestCertificate.intermediate1,
        ])
    )

    guard case .validCertificate(let chain) = result else {
        fatalError("Failed to validate: \(result)")
    }
    return chain.count
}

func testPolicyFailuresCanFindLongerPaths() async -> Int {
    let roots = CertificateStore([TestCertificate.ca1, TestCertificate.ca2])

    var verifier = Verifier(rootCertificates: roots) {
        FailIfCertInChainPolicy(forbiddenCert: TestCertificate.ca1)
        RFC5280Policy(fixedExpiryValidationTime: TestCertificate.referenceTime)
    }
    let result = await verifier.validate(
        leaf: TestCertificate.localhostLeaf,
        intermediates: CertificateStore([
            TestCertificate.intermediate1, TestCertificate.ca2CrossSignedByCA1, TestCertificate.ca1CrossSignedByCA2,
        ])
    )

    guard case .validCertificate(let chain) = result else {
        fatalError("Failed to validate: \(result)")
    }

    return chain.count
}

func testSelfSignedCertsAreTrustedWhenInTrustStore() async -> Int {
    let roots = CertificateStore([TestCertificate.ca1, TestCertificate.isolatedSelfSignedCert])

    var verifier = Verifier(rootCertificates: roots) {
        RFC5280Policy(fixedExpiryValidationTime: TestCertificate.referenceTime)
    }
    let result = await verifier.validate(
        leaf: TestCertificate.isolatedSelfSignedCert,
        intermediates: CertificateStore([TestCertificate.intermediate1])
    )

    guard case .validCertificate(let chain) = result else {
        fatalError("Failed to validate: \(result)")
    }

    return chain.count
}

func testTrustRootsCanBeNonSelfSignedLeaves() async -> Int {
    // we use a custom policy here to ignore the fact that the basic constraints extension is critical.
    struct IgnoreBasicConstraintsPolicy: VerifierPolicy {
        let verifyingCriticalExtensions: [ASN1ObjectIdentifier] = [.X509ExtensionID.basicConstraints]

        func chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain) async -> PolicyEvaluationResult {
            return .meetsPolicy
        }
    }

    let roots = CertificateStore([TestCertificate.localhostLeaf])

    var verifier = Verifier(rootCertificates: roots) { IgnoreBasicConstraintsPolicy() }
    let result = await verifier.validate(
        leaf: TestCertificate.localhostLeaf,
        intermediates: CertificateStore([TestCertificate.intermediate1])
    )

    guard case .validCertificate(let chain) = result else {
        fatalError("Failed to validate: \(result)")
    }

    return chain.count
}

func testTrustRootsCanBeNonSelfSignedIntermediates() async -> Int {
    let roots = CertificateStore([TestCertificate.intermediate1])

    var verifier = Verifier(rootCertificates: roots) {
        RFC5280Policy(fixedExpiryValidationTime: TestCertificate.referenceTime)
    }
    let result = await verifier.validate(
        leaf: TestCertificate.localhostLeaf,
        intermediates: CertificateStore([TestCertificate.intermediate1])
    )

    guard case .validCertificate(let chain) = result else {
        fatalError("Failed to validate: \(result)")
    }

    return chain.count
}

// MARK: - unsuccessful validation

func testAllUnsuccessfulValidations() async -> Int {
    var counts = 0
    counts += await testWePoliceCriticalExtensionsOnLeafCerts()
    counts += await testMissingIntermediateFailsToBuild()
    counts += await testSelfSignedCertsAreRejectedWhenNotInTheTrustStore()
    counts += await testMissingRootFailsToBuild()
    return counts
}

func testWePoliceCriticalExtensionsOnLeafCerts() async -> Int {
    let roots = CertificateStore([
        TestCertificate.ca1, TestCertificate.isolatedSelfSignedCertWithWeirdCriticalExtension,
    ])

    var verifier = Verifier(rootCertificates: roots) {
        RFC5280Policy(fixedExpiryValidationTime: TestCertificate.referenceTime)
    }
    let result = await verifier.validate(
        leaf: TestCertificate.isolatedSelfSignedCertWithWeirdCriticalExtension,
        intermediates: CertificateStore([TestCertificate.intermediate1])
    )

    guard case .couldNotValidate(let policyResults) = result else {
        fatalError("Incorrectly validated: \(result)")
    }

    return policyResults.count
}

func testMissingIntermediateFailsToBuild() async -> Int {
    let roots = CertificateStore([TestCertificate.ca1])

    var verifier = Verifier(rootCertificates: roots) {
        RFC5280Policy(fixedExpiryValidationTime: TestCertificate.referenceTime)
    }
    let result = await verifier.validate(
        leaf: TestCertificate.localhostLeaf,
        intermediates: CertificateStore([])
    )

    guard case .couldNotValidate(let policyResults) = result else {
        fatalError("Accidentally validated: \(result)")
    }

    return policyResults.count
}

func testSelfSignedCertsAreRejectedWhenNotInTheTrustStore() async -> Int {
    let roots = CertificateStore([TestCertificate.ca1])

    var verifier = Verifier(rootCertificates: roots) {
        RFC5280Policy(fixedExpiryValidationTime: TestCertificate.referenceTime)
    }
    let result = await verifier.validate(
        leaf: TestCertificate.isolatedSelfSignedCert,
        intermediates: CertificateStore([TestCertificate.intermediate1])
    )

    guard case .couldNotValidate(let policyResults) = result else {
        fatalError("Incorrectly validated: \(result)")
    }
    return policyResults.count
}

func testMissingRootFailsToBuild() async -> Int {
    let roots = CertificateStore([])

    var verifier = Verifier(rootCertificates: roots) {
        RFC5280Policy(fixedExpiryValidationTime: TestCertificate.referenceTime)
    }
    let result = await verifier.validate(
        leaf: TestCertificate.localhostLeaf,
        intermediates: CertificateStore([TestCertificate.intermediate1])
    )

    guard case .couldNotValidate(let policyResults) = result else {
        fatalError("Accidentally validated: \(result)")
    }

    return policyResults.count
}

private struct FailIfCertInChainPolicy: VerifierPolicy {
    let verifyingCriticalExtensions: [ASN1ObjectIdentifier] = []

    private let forbiddenCert: Certificate

    init(forbiddenCert: Certificate) {
        self.forbiddenCert = forbiddenCert
    }

    func chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain) async -> PolicyEvaluationResult {
        guard chain.contains(self.forbiddenCert) else {
            return .meetsPolicy
        }
        return .failsToMeetPolicy(reason: "chain must not contain \(self.forbiddenCert)")
    }
}

enum TestCertificate {
    static let referenceTime = Date()

    static let all = [
        ca1,
        ca1CrossSignedByCA2,
        ca1WithAlternativePrivateKey,
        ca2,
        ca2CrossSignedByCA1,
        intermediate1,
        intermediate1WithoutSKIAKI,
        intermediate1WithIncorrectSKIAKI,
        localhostLeaf,
        isolatedSelfSignedCert,
        isolatedSelfSignedCertWithWeirdCriticalExtension,
    ]

    private static let ca1PrivateKey = P384.Signing.PrivateKey()
    private static let ca1Name = try! DistinguishedName {
        CountryName("US")
        OrganizationName("Apple")
        CommonName("Swift Certificate Test CA 1")
    }
    static let ca1: Certificate = {
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
    static let ca1CrossSignedByCA2: Certificate = {
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
    static let ca1WithAlternativePrivateKey: Certificate = {
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
    static let ca2: Certificate = {
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
    static let ca2CrossSignedByCA1: Certificate = {
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

    static let intermediate1PrivateKey = P256.Signing.PrivateKey()
    static let intermediate1Name = try! DistinguishedName {
        CountryName("US")
        OrganizationName("Apple")
        CommonName("Swift Certificate Test Intermediate CA 1")
    }
    static let intermediate1: Certificate = {
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
    static let intermediate1WithoutSKIAKI: Certificate = {
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
    static let intermediate1WithIncorrectSKIAKI: Certificate = {
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
    static let localhostLeaf: Certificate = {
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
    static let isolatedSelfSignedCert: Certificate = {
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

    static let isolatedSelfSignedCertWithWeirdCriticalExtension: Certificate = {
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
}

extension TimeInterval {
    private static let oneDay: TimeInterval = 60 * 60 * 24

    static func days(_ days: Int) -> TimeInterval {
        return Double(days) * oneDay
    }
}
