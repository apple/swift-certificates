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
import X509
import Foundation
import Crypto
import SwiftASN1
import _CertificateInternals

let benchmarks = {
    Benchmark("Verifier", configuration: .init(warmupIterations: 1)) { benchmark in
        var counts = 0
        
        counts += await testAllSuccessfulValidations()
        counts += await testAllUnsuccessfulValidations()
        
        blackHole(counts)
    }
    
    let derEncodedCAs = WebPKI.all.map { try! PEMDocument(pemString: $0).derBytes }
    Benchmark("Parse WebPKI Roots") { benchmark in
        for _ in 0..<1000 {
            for derEncodedCA in derEncodedCAs {
                blackHole(try! Certificate(derEncoded: derEncodedCA).extensions.count)
            }
        }
    }
    
    Benchmark("TinyArray non-allocating functions") { benchmark in
        var counts = 0
        for _ in 0..<1000 {
            counts += _TinyArray(CollectionOfOne(1)).count
            
            do {
                var array = _TinyArray<Int>()
                array.append(contentsOf: CollectionOfOne(1))
                counts += array.count
            }
        }
        
        blackHole(counts)
    }
    
    Benchmark("TinyArray.append(_:)") { benchmark in
        var count = 0
        for _ in 0..<1000 {
            var tinyArray = _TinyArray<Int>()
            for i in 0..<1000 {
                tinyArray.append(i)
            }
            count += tinyArray.count
        }
        
        blackHole(count)
    }
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
        RFC5280Policy(validationTime: TestCertificate.referenceTime)
    }
    let result = await verifier.validate(leafCertificate: TestCertificate.localhostLeaf, intermediates: CertificateStore([TestCertificate.intermediate1]))

    guard case .validCertificate(let chain) = result else {
        fatalError("Failed to validate: \(result)")
    }

    return chain.count
}

func testExtraRootsAreIgnored() async -> Int {
    let roots = CertificateStore([TestCertificate.ca1, TestCertificate.ca2])

    var verifier = Verifier(rootCertificates: roots) { RFC5280Policy(validationTime: TestCertificate.referenceTime) }
    let result = await verifier.validate(leafCertificate: TestCertificate.localhostLeaf, intermediates: CertificateStore([TestCertificate.intermediate1]))

    guard case .validCertificate(let chain) = result else {
        fatalError("Failed to validate: \(result)")
    }

    return chain.count
}

func testPuttingRootsInTheIntermediariesIsntAProblem() async -> Int {
    let roots = CertificateStore([TestCertificate.ca1, TestCertificate.ca2])

    var verifier = Verifier(rootCertificates: roots) { RFC5280Policy(validationTime: TestCertificate.referenceTime) }
    let result = await verifier.validate(leafCertificate: TestCertificate.localhostLeaf, intermediates: CertificateStore([TestCertificate.intermediate1, TestCertificate.ca1, TestCertificate.ca2]))

    guard case .validCertificate(let chain) = result else {
        fatalError("Failed to validate: \(result)")
    }

    return chain.count
}

func testSupportsCrossSignedRootWithoutTrouble() async -> Int {
    let roots = CertificateStore([TestCertificate.ca2])

    var verifier = Verifier(rootCertificates: roots) { RFC5280Policy(validationTime: TestCertificate.referenceTime) }
    let result = await verifier.validate(leafCertificate: TestCertificate.localhostLeaf, intermediates: CertificateStore([TestCertificate.intermediate1, TestCertificate.ca1CrossSignedByCA2]))

    guard case .validCertificate(let chain) = result else {
        fatalError("Failed to validate: \(result)")
    }

    return chain.count
}

func testBuildsTheShorterPathInTheCaseOfCrossSignedRoots() async -> Int {
    let roots = CertificateStore([TestCertificate.ca1, TestCertificate.ca2])

    var verifier = Verifier(rootCertificates: roots) { RFC5280Policy(validationTime: TestCertificate.referenceTime) }
    let result = await verifier.validate(leafCertificate: TestCertificate.localhostLeaf, intermediates: CertificateStore([TestCertificate.intermediate1, TestCertificate.ca2CrossSignedByCA1, TestCertificate.ca1CrossSignedByCA2]))

    guard case .validCertificate(let chain) = result else {
        fatalError("Failed to validate: \(result)")
    }

    return chain.count
}

func testPrefersToUseIntermediatesWithSKIThatMatches() async -> Int {
    let roots = CertificateStore([TestCertificate.ca1])

    var verifier = Verifier(rootCertificates: roots) { RFC5280Policy(validationTime: TestCertificate.referenceTime) }
    let result = await verifier.validate(leafCertificate: TestCertificate.localhostLeaf, intermediates: CertificateStore([TestCertificate.intermediate1, TestCertificate.intermediate1WithoutSKIAKI]))

    guard case .validCertificate(let chain) = result else {
        fatalError("Failed to validate: \(result)")
    }

    return chain.count
}

func testPrefersNoSKIToNonMatchingSKI() async -> Int {
    let roots = CertificateStore([TestCertificate.ca1])

    var verifier = Verifier(rootCertificates: roots) { RFC5280Policy(validationTime: TestCertificate.referenceTime) }
    let result = await verifier.validate(leafCertificate: TestCertificate.localhostLeaf, intermediates: CertificateStore([TestCertificate.intermediate1WithIncorrectSKIAKI, TestCertificate.intermediate1WithoutSKIAKI]))

    guard case .validCertificate(let chain) = result else {
        fatalError("Failed to validate: \(result)")
    }

    return chain.count
}

func testRejectsRootsThatDidNotSignTheCertBeforeThem() async -> Int {
    let roots = CertificateStore([TestCertificate.ca1WithAlternativePrivateKey, TestCertificate.ca2])

    var verifier = Verifier(rootCertificates: roots) { RFC5280Policy(validationTime: TestCertificate.referenceTime) }
    let result = await verifier.validate(leafCertificate: TestCertificate.localhostLeaf, intermediates: CertificateStore([TestCertificate.ca1CrossSignedByCA2, TestCertificate.ca2CrossSignedByCA1, TestCertificate.intermediate1]))

    guard case .validCertificate(let chain) = result else {
        fatalError("Failed to validate: \(result)")
    }
    return chain.count
}

func testPolicyFailuresCanFindLongerPaths() async -> Int {
    let roots = CertificateStore([TestCertificate.ca1, TestCertificate.ca2])

    var verifier = Verifier(rootCertificates: roots) {
        FailIfCertInChainPolicy(forbiddenCert: TestCertificate.ca1)
        RFC5280Policy(validationTime: TestCertificate.referenceTime)
    }
    let result = await verifier.validate(leafCertificate: TestCertificate.localhostLeaf, intermediates: CertificateStore([TestCertificate.intermediate1, TestCertificate.ca2CrossSignedByCA1, TestCertificate.ca1CrossSignedByCA2]))

    guard case .validCertificate(let chain) = result else {
        fatalError("Failed to validate: \(result)")
    }

    return chain.count
}

func testSelfSignedCertsAreTrustedWhenInTrustStore() async -> Int {
    let roots = CertificateStore([TestCertificate.ca1, TestCertificate.isolatedSelfSignedCert])

    var verifier = Verifier(rootCertificates: roots) { RFC5280Policy(validationTime: TestCertificate.referenceTime) }
    let result = await verifier.validate(leafCertificate: TestCertificate.isolatedSelfSignedCert, intermediates: CertificateStore([TestCertificate.intermediate1]))

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
    let result = await verifier.validate(leafCertificate: TestCertificate.localhostLeaf, intermediates: CertificateStore([TestCertificate.intermediate1]))

    guard case .validCertificate(let chain) = result else {
        fatalError("Failed to validate: \(result)")
    }

    return chain.count
}

func testTrustRootsCanBeNonSelfSignedIntermediates() async -> Int {
    let roots = CertificateStore([TestCertificate.intermediate1])

    var verifier = Verifier(rootCertificates: roots) { RFC5280Policy(validationTime: TestCertificate.referenceTime) }
    let result = await verifier.validate(leafCertificate: TestCertificate.localhostLeaf, intermediates: CertificateStore([TestCertificate.intermediate1]))

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
    let roots = CertificateStore([TestCertificate.ca1, TestCertificate.isolatedSelfSignedCertWithWeirdCriticalExtension])

    var verifier = Verifier(rootCertificates: roots) { RFC5280Policy(validationTime: TestCertificate.referenceTime) }
    let result = await verifier.validate(leafCertificate: TestCertificate.isolatedSelfSignedCertWithWeirdCriticalExtension, intermediates: CertificateStore([TestCertificate.intermediate1]))

    guard case .couldNotValidate(let policyResults) = result else {
        fatalError("Incorrectly validated: \(result)")
    }
    
    return policyResults.count
}

func testMissingIntermediateFailsToBuild() async -> Int {
    let roots = CertificateStore([TestCertificate.ca1])

    var verifier = Verifier(rootCertificates: roots) { RFC5280Policy(validationTime: TestCertificate.referenceTime) }
    let result = await verifier.validate(leafCertificate: TestCertificate.localhostLeaf, intermediates: CertificateStore([]))

    guard case .couldNotValidate(let policyResults) = result else {
        fatalError("Accidentally validated: \(result)")
    }

    return policyResults.count
}

func testSelfSignedCertsAreRejectedWhenNotInTheTrustStore() async -> Int {
    let roots = CertificateStore([TestCertificate.ca1])

    var verifier = Verifier(rootCertificates: roots) { RFC5280Policy(validationTime: TestCertificate.referenceTime) }
    let result = await verifier.validate(leafCertificate: TestCertificate.isolatedSelfSignedCert, intermediates: CertificateStore([TestCertificate.intermediate1]))

    guard case .couldNotValidate(let policyResults) = result else {
        fatalError("Incorrectly validated: \(result)")
    }
    return policyResults.count
}

func testMissingRootFailsToBuild() async -> Int {
    let roots = CertificateStore([])

    var verifier = Verifier(rootCertificates: roots) { RFC5280Policy(validationTime: TestCertificate.referenceTime) }
    let result = await verifier.validate(leafCertificate: TestCertificate.localhostLeaf, intermediates: CertificateStore([TestCertificate.intermediate1]))

    guard case .couldNotValidate(let policyResults) = result else {
        fatalError("Accidentally validated: \(result)")
    }

    return policyResults.count
}

fileprivate struct FailIfCertInChainPolicy: VerifierPolicy {
    let verifyingCriticalExtensions: [ASN1ObjectIdentifier] = []

    private let forbiddenCert: Certificate

    init(forbiddenCert: Certificate) {
        self.forbiddenCert = forbiddenCert
    }

    mutating func chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain) async -> PolicyEvaluationResult {
        if chain.contains(self.forbiddenCert) {
            return .failsToMeetPolicy(reason: "chain must not contain \(self.forbiddenCert)")
        } else {
            return .meetsPolicy
        }
    }
}
