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

import Foundation
import XCTest
import SwiftASN1
@testable @_spi(DisableValidityCheck) import X509
import Crypto

class RFC5280PolicyBase: XCTestCase {
    enum PolicyFactory {
        case rfc5280
        case expiry
        case basicConstraints
        case nameConstraints
        
        @PolicyBuilder
        func create(_ validationTime: Date) -> some VerifierPolicy {
            switch self {
            case .rfc5280:
                RFC5280Policy(validationTime: validationTime)
                
            case .expiry:
                ExpiryPolicy(validationTime: validationTime)
                CatchAllPolicy()
                
            case .basicConstraints:
                BasicConstraintsPolicy()
                CatchAllPolicy()
                
            case .nameConstraints:
                NameConstraintsPolicy()
                CatchAllPolicy()
                
            }
        }
        
        // This do-nothing policy
        struct CatchAllPolicy: VerifierPolicy {
            let verifyingCriticalExtensions: [ASN1ObjectIdentifier] = [
                .X509ExtensionID.basicConstraints,
                .X509ExtensionID.nameConstraints,
                .X509ExtensionID.keyUsage
            ]
            
            func chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain) async -> PolicyEvaluationResult {
                return .meetsPolicy
            }
        }
    }
    
    func nameconstraintsExcludedSubtrees(excludedSubtrees: [GeneralName], subjectAlternativeNames: [GeneralName], match: Bool, policyFactory: PolicyFactory) async throws {
        let alternativeRoot = TestPKI.issueCA(
            extensions: try! Certificate.Extensions {
                Critical(
                    BasicConstraints.isCertificateAuthority(maxPathLength: nil)
                )
                Critical(
                    NameConstraints(excludedSubtrees: excludedSubtrees)
                )
            }
        )

        let alternativeIntermediate = TestPKI.issueIntermediate(
            name: TestPKI.unconstrainedIntermediateName,
            key: .init(TestPKI.unconstrainedIntermediateKey.publicKey),
            extensions: try! Certificate.Extensions {
                Critical(
                    BasicConstraints.isCertificateAuthority(maxPathLength: 0)
                )
                Critical(
                    NameConstraints(excludedSubtrees: excludedSubtrees)
                )
            },
            issuer: .unconstrainedRoot
        )

        let intermediateWithAConstrainedNameForSomeReason = TestPKI.issueIntermediate(
            name: TestPKI.unconstrainedIntermediateName,
            key: .init(TestPKI.unconstrainedIntermediateKey.publicKey),
            extensions: try! Certificate.Extensions {
                Critical(
                    BasicConstraints.isCertificateAuthority(maxPathLength: 0)
                )
                SubjectAlternativeNames(subjectAlternativeNames)
            },
            issuer: .unconstrainedRoot
        )

        let leaf = TestPKI.issueLeaf(
            issuer: .unconstrainedIntermediate,
            subjectAlternativeNames: subjectAlternativeNames
        )
        let leafWithoutNames = TestPKI.issueLeaf(
            issuer: .unconstrainedIntermediate
        )

        // Test a constraint on the root affecting the leaf
        var roots = CertificateStore([alternativeRoot])
        var verifier = Verifier(rootCertificates: roots) { policyFactory.create(TestPKI.startDate + 2.5) }
        var result = await verifier.validate(leafCertificate: leaf, intermediates: CertificateStore([TestPKI.unconstrainedIntermediate]))

        switch (match, result) {
        case (true, .couldNotValidate), (false, .validCertificate):
            // Expected outcomes
            ()
        default:
            XCTFail("Incorrect validation on excluded subtrees \(excludedSubtrees) for \(subjectAlternativeNames) from root, expected \(match) got \(result)")
        }

        // Test a constraint on the intermediate affecting the leaf.
        roots = CertificateStore([TestPKI.unconstrainedCA])
        verifier = Verifier(rootCertificates: roots) { policyFactory.create(TestPKI.startDate + 2.5) }
        result = await verifier.validate(leafCertificate: leaf, intermediates: CertificateStore([alternativeIntermediate]))

        switch (match, result) {
        case (true, .couldNotValidate), (false, .validCertificate):
            // Expected outcomes
            ()
        default:
            XCTFail("Incorrect validation on excluded subtrees \(excludedSubtrees) for \(subjectAlternativeNames) from intermediate, expected \(match) got \(result)")
        }

        // Test a constraint on the root affecting the intermediate
        roots = CertificateStore([alternativeRoot])
        verifier = Verifier(rootCertificates: root) {
            policyFactory.create(TestPKI.startDate + 2.5)
        }
        result = await verifier.validate(leafCertificate: leafWithoutNames, intermediates: CertificateStore([intermediateWithAConstrainedNameForSomeReason]))

        switch (match, result) {
        case (true, .couldNotValidate), (false, .validCertificate):
            // Expected outcomes
            ()
        default:
            XCTFail("Incorrect validation on excluded subtrees \(excludedSubtrees) for \(subjectAlternativeNames) from intermediate, expected \(match) got \(result)")
        }

        // Unconstrained everything.
        roots = CertificateStore([TestPKI.unconstrainedCA])
        verifier = Verifier(rootCertificates: roots) { policyFactory.create(TestPKI.startDate + 2.5) }
        result = await verifier.validate(leafCertificate: leaf, intermediates: CertificateStore([intermediateWithAConstrainedNameForSomeReason]))

        guard case .validCertificate(let chain) = result else {
            XCTFail("Unable to validate with unconstrained root: \(result)")
            return
        }

        XCTAssertEqual(chain, [leaf, intermediateWithAConstrainedNameForSomeReason, TestPKI.unconstrainedCA])
    }

    func nameconstraintsPermittedSubtrees(permittedSubtrees: [GeneralName], subjectAlternativeNames: [GeneralName], match: Bool, policyFactory: PolicyFactory) async throws {
        let alternativeRoot = TestPKI.issueCA(
            extensions: try! Certificate.Extensions {
                Critical(
                    BasicConstraints.isCertificateAuthority(maxPathLength: nil)
                )
                Critical(
                    NameConstraints(permittedSubtrees: permittedSubtrees)
                )
            }
        )

        let alternativeIntermediate = TestPKI.issueIntermediate(
            name: TestPKI.unconstrainedIntermediateName,
            key: .init(TestPKI.unconstrainedIntermediateKey.publicKey),
            extensions: try! Certificate.Extensions {
                Critical(
                    BasicConstraints.isCertificateAuthority(maxPathLength: 0)
                )
                Critical(
                    NameConstraints(permittedSubtrees: permittedSubtrees)
                )
            },
            issuer: .unconstrainedRoot
        )

        let intermediateWithAConstrainedNameForSomeReason = TestPKI.issueIntermediate(
            name: TestPKI.unconstrainedIntermediateName,
            key: .init(TestPKI.unconstrainedIntermediateKey.publicKey),
            extensions: try! Certificate.Extensions {
                Critical(
                    BasicConstraints.isCertificateAuthority(maxPathLength: 0)
                )
                SubjectAlternativeNames(subjectAlternativeNames)
            },
            issuer: .unconstrainedRoot
        )

        let leaf = TestPKI.issueLeaf(
            issuer: .unconstrainedIntermediate,
            subjectAlternativeNames: subjectAlternativeNames
        )
        let leafWithoutNames = TestPKI.issueLeaf(
            issuer: .unconstrainedIntermediate
        )

        // Test a constraint on the root affecting the leaf
        var roots = CertificateStore([alternativeRoot])
        var verifier = Verifier(rootCertificates: roots) { policyFactory.create(TestPKI.startDate + 2.5) }
        var result = await verifier.validate(leafCertificate: leaf, intermediates: CertificateStore([TestPKI.unconstrainedIntermediate]))

        switch (match, result) {
        case (true, .validCertificate), (false, .couldNotValidate):
            // Expected outcomes
            ()
        default:
            XCTFail("Incorrect validation on excluded subtrees \(permittedSubtrees) for \(subjectAlternativeNames) from root, expected \(match) got \(result)")
        }

        // Test a constraint on the intermediate affecting the leaf.
        roots = CertificateStore([TestPKI.unconstrainedCA])
        verifier = Verifier(rootCertificates: roots) { policyFactory.create(TestPKI.startDate + 2.5) }
        result = await verifier.validate(leafCertificate: leaf, intermediates: CertificateStore([alternativeIntermediate]))

        switch (match, result) {
        case (true, .validCertificate), (false, .couldNotValidate):
            // Expected outcomes
            ()
        default:
            XCTFail("Incorrect validation on excluded subtrees \(permittedSubtrees) for \(subjectAlternativeNames) from intermediate, expected \(match) got \(result)")
        }

        // Test a constraint on the root affecting the intermediate
        roots = CertificateStore([alternativeRoot])
        verifier = Verifier(rootCertificates: roots) { policyFactory.create(TestPKI.startDate + 2.5) }
        result = await verifier.validate(leafCertificate: leafWithoutNames, intermediates: CertificateStore([intermediateWithAConstrainedNameForSomeReason]))

        switch (match, result) {
        case (true, .validCertificate), (false, .couldNotValidate):
            // Expected outcomes
            ()
        default:
            XCTFail("Incorrect validation on excluded subtrees \(permittedSubtrees) for \(subjectAlternativeNames) from intermediate, expected \(match) got \(result)")
        }
    }
}

final class RFC5280PolicyTests1: RFC5280PolicyBase {
    func testValidCertsAreAccepted() async throws {
        let roots = CertificateStore([TestPKI.unconstrainedCA])
        let leaf = TestPKI.issueLeaf(issuer: .unconstrainedIntermediate)

        var verifier = Verifier(rootCertificates: roots, policy: PolicySet(policies: [RFC5280Policy(validationTime: Date())]))
        let result = await verifier.validate(leafCertificate: leaf, intermediates: CertificateStore([TestPKI.unconstrainedIntermediate]))

        guard case .validCertificate(let chain) = result else {
            XCTFail("Failed to validate: \(result)")
            return
        }

        XCTAssertEqual(chain, [leaf, TestPKI.unconstrainedIntermediate, TestPKI.unconstrainedCA])
    }

    private func _expiredLeafIsRejected(_ policyFactory: PolicyFactory) async throws {
        let roots = CertificateStore([TestPKI.unconstrainedCA])
        let leaf = TestPKI.issueLeaf(
            notValidBefore: TestPKI.startDate + 1.0,
            notValidAfter: TestPKI.startDate + 2.0,  // One second validity window
            issuer: .unconstrainedIntermediate
        )

        var verifier = Verifier(
            rootCertificates: roots, policy: PolicySet(policies: [policyFactory.create(TestPKI.startDate + 3.0)])
        )
        let result = await verifier.validate(leafCertificate: leaf, intermediates: CertificateStore([TestPKI.unconstrainedIntermediate]))

        guard case .couldNotValidate(let policyFailures) = result else {
            XCTFail("Failed to validate: \(result)")
            return
        }

        XCTAssertEqual(policyFailures.count, 1)
    }

    func testExpiredLeafIsRejected() async throws {
        try await self._expiredLeafIsRejected(.rfc5280)
    }

    func testExpiredLeafIsRejectedBasePolicy() async throws {
        try await self._expiredLeafIsRejected(.expiry)
    }

    func testExpiredLeafIsNotRejectedIfThePolicyDisablesExpiryChecking() async throws {
        let roots = CertificateStore([TestPKI.unconstrainedCA])
        let leaf = TestPKI.issueLeaf(
            notValidBefore: TestPKI.startDate + 1.0,
            notValidAfter: TestPKI.startDate + 2.0,  // One second validity window
            issuer: .unconstrainedIntermediate
        )

        var verifier = Verifier(
            rootCertificates: roots, policy: PolicySet(policies: [RFC5280Policy.withValidityCheckDisabled()])
        )
        let result = await verifier.validate(leafCertificate: leaf, intermediates: CertificateStore([TestPKI.unconstrainedIntermediate]))

        guard case .validCertificate = result else {
            XCTFail("Failed to validate: \(result)")
            return
        }
    }

    func _expiredIntermediateIsRejected(_ policyFactory: PolicyFactory) async throws {
        let roots = CertificateStore([TestPKI.unconstrainedCA])
        let leaf = TestPKI.issueLeaf(
            notValidBefore: TestPKI.startDate,
            notValidAfter: TestPKI.unconstrainedIntermediate.notValidAfter + 2.0,  // Later than the intermediate.
            issuer: .unconstrainedIntermediate
        )

        var verifier = Verifier(
            rootCertificates: roots,
            policy: PolicySet(policies: [policyFactory.create(TestPKI.unconstrainedIntermediate.notValidAfter + 1.0)])
        )
        let result = await verifier.validate(leafCertificate: leaf, intermediates: CertificateStore([TestPKI.unconstrainedIntermediate]))

        guard case .couldNotValidate(let policyFailures) = result else {
            XCTFail("Failed to validate: \(result)")
            return
        }

        XCTAssertEqual(policyFailures.count, 1)
    }

    func testExpiredIntermediateIsRejected() async throws {
        try await self._expiredIntermediateIsRejected(.rfc5280)
    }

    func testExpiredIntermediateIsRejectedBasePolicy() async throws {
        try await self._expiredIntermediateIsRejected(.expiry)
    }

    func testExpiredIntermediateIsNotRejectedIfThePolicyDisablesExpiryChecking() async throws {
        let roots = CertificateStore([TestPKI.unconstrainedCA])
        let leaf = TestPKI.issueLeaf(
            notValidBefore: TestPKI.startDate,
            notValidAfter: TestPKI.unconstrainedIntermediate.notValidAfter + 2.0,  // Later than the intermediate.
            issuer: .unconstrainedIntermediate
        )

        var verifier = Verifier(
            rootCertificates: roots,
            policy: PolicySet(policies: [RFC5280Policy.withValidityCheckDisabled()])
        )
        let result = await verifier.validate(leafCertificate: leaf, intermediates: CertificateStore([TestPKI.unconstrainedIntermediate]))

        guard case .validCertificate = result else {
            XCTFail("Failed to validate: \(result)")
            return
        }
    }

    func _expiredRootIsRejected(_ policyFactory: PolicyFactory) async throws {
        let roots = CertificateStore([TestPKI.unconstrainedCA])
        let leaf = TestPKI.issueLeaf(
            notValidBefore: TestPKI.startDate,
            notValidAfter: TestPKI.unconstrainedCA.notValidAfter + 2.0,  // Later than the root.
            issuer: .unconstrainedRoot  // Issue off the root directly to avoid the intermediate getting involved.
        )

        var verifier = Verifier(
            rootCertificates: roots,
            policy: PolicySet(policies: [policyFactory.create(TestPKI.unconstrainedCA.notValidAfter + 1.0)])
        )
        let result = await verifier.validate(leafCertificate: leaf, intermediates: CertificateStore([TestPKI.unconstrainedIntermediate]))

        guard case .couldNotValidate(let policyFailures) = result else {
            XCTFail("Failed to validate: \(result)")
            return
        }

        XCTAssertEqual(policyFailures.count, 1)
    }

    func testExpiredRootIsRejected() async throws {
        try await self._expiredRootIsRejected(.rfc5280)
    }

    func testExpiredRootIsRejectedBasePolicy() async throws {
        try await self._expiredRootIsRejected(.expiry)
    }

    func testExpiredRootIsNotRejectedIfThePolicyDisablesExpiryChecking() async throws {
        let roots = CertificateStore([TestPKI.unconstrainedCA])
        let leaf = TestPKI.issueLeaf(
            notValidBefore: TestPKI.startDate,
            notValidAfter: TestPKI.unconstrainedCA.notValidAfter + 2.0,  // Later than the root.
            issuer: .unconstrainedRoot  // Issue off the root directly to avoid the intermediate getting involved.
        )

        var verifier = Verifier(
            rootCertificates: roots,
            policy: PolicySet(policies: [RFC5280Policy.withValidityCheckDisabled()])
        )
        let result = await verifier.validate(leafCertificate: leaf, intermediates: CertificateStore([TestPKI.unconstrainedIntermediate]))

        guard case .validCertificate = result else {
            XCTFail("Failed to validate: \(result)")
            return
        }
    }

    func _notYetValidLeafIsRejected(_ policyFactory: PolicyFactory) async throws {
        let roots = CertificateStore([TestPKI.unconstrainedCA])
        let leaf = TestPKI.issueLeaf(
            notValidBefore: TestPKI.startDate + 2.0,
            notValidAfter: TestPKI.startDate + 3.0,  // One second validity window
            issuer: .unconstrainedIntermediate
        )

        var verifier = Verifier(
            rootCertificates: roots, policy: PolicySet(policies: [policyFactory.create(TestPKI.startDate + 1.0)])
        )
        let result = await verifier.validate(leafCertificate: leaf, intermediates: CertificateStore([TestPKI.unconstrainedIntermediate]))

        guard case .couldNotValidate(let policyFailures) = result else {
            XCTFail("Failed to validate: \(result)")
            return
        }

        XCTAssertEqual(policyFailures.count, 1)
    }

    func testNotYetValidLeafIsRejected() async throws {
        try await self._notYetValidLeafIsRejected(.rfc5280)
    }

    func testNotYetValidLeafIsRejectedBasePolicy() async throws {
        try await self._notYetValidLeafIsRejected(.expiry)
    }

    func testNotYetValidLeafIsNotRejectedIfValidityCheckingIsDisabled() async throws {
        let roots = CertificateStore([TestPKI.unconstrainedCA])
        let leaf = TestPKI.issueLeaf(
            notValidBefore: TestPKI.startDate + 2.0,
            notValidAfter: TestPKI.startDate + 3.0,  // One second validity window
            issuer: .unconstrainedIntermediate
        )

        var verifier = Verifier(
            rootCertificates: roots, policy: PolicySet(policies: [RFC5280Policy.withValidityCheckDisabled()])
        )
        let result = await verifier.validate(leafCertificate: leaf, intermediates: CertificateStore([TestPKI.unconstrainedIntermediate]))

        guard case .validCertificate = result else {
            XCTFail("Failed to validate: \(result)")
            return
        }
    }

    func _notYetValidIntermediateIsRejected(_ policyFactory: PolicyFactory) async throws {
        let roots = CertificateStore([TestPKI.unconstrainedCA])
        let leaf = TestPKI.issueLeaf(
            notValidBefore: TestPKI.unconstrainedIntermediate.notValidBefore - 2.0,  // Earlier than the intermediate
            notValidAfter: TestPKI.unconstrainedIntermediate.notValidAfter,
            issuer: .unconstrainedIntermediate
        )

        var verifier = Verifier(
            rootCertificates: roots,
            policy: PolicySet(policies: [policyFactory.create(TestPKI.unconstrainedIntermediate.notValidBefore - 1.0)])
        )
        let result = await verifier.validate(leafCertificate: leaf, intermediates: CertificateStore([TestPKI.unconstrainedIntermediate]))

        guard case .couldNotValidate(let policyFailures) = result else {
            XCTFail("Failed to validate: \(result)")
            return
        }

        XCTAssertEqual(policyFailures.count, 1)
    }

    func testNotYetValidIntermediateIsRejected() async throws {
        try await self._notYetValidIntermediateIsRejected(.rfc5280)
    }

    func testNotYetValidIntermediateIsRejectedBasePolicy() async throws {
        try await self._notYetValidIntermediateIsRejected(.expiry)
    }

    func testNotYetValidIntermediateIsNotRejectedIfValidityCheckingIsDisabled() async throws {
        let roots = CertificateStore([TestPKI.unconstrainedCA])
        let leaf = TestPKI.issueLeaf(
            notValidBefore: TestPKI.unconstrainedIntermediate.notValidBefore - 2.0,  // Earlier than the intermediate
            notValidAfter: TestPKI.unconstrainedIntermediate.notValidAfter,
            issuer: .unconstrainedIntermediate
        )

        var verifier = Verifier(
            rootCertificates: roots,
            policy: PolicySet(policies: [RFC5280Policy.withValidityCheckDisabled()])
        )
        let result = await verifier.validate(leafCertificate: leaf, intermediates: CertificateStore([TestPKI.unconstrainedIntermediate]))

        guard case .validCertificate = result else {
            XCTFail("Failed to validate: \(result)")
            return
        }
    }

    func _notYetValidRootIsRejected(_ policyFactory: PolicyFactory) async throws {
        let roots = CertificateStore([TestPKI.unconstrainedCA])
        let leaf = TestPKI.issueLeaf(
            notValidBefore: TestPKI.unconstrainedCA.notValidBefore - 2.0,  // Earlier than the root
            notValidAfter: TestPKI.startDate,
            issuer: .unconstrainedRoot  // Issue off the root directly to avoid the intermediate getting involved.
        )

        var verifier = Verifier(
            rootCertificates: roots,
            policy: PolicySet(policies: [policyFactory.create(TestPKI.unconstrainedCA.notValidBefore - 1.0)])
        )
        let result = await verifier.validate(leafCertificate: leaf, intermediates: CertificateStore([TestPKI.unconstrainedIntermediate]))

        guard case .couldNotValidate(let policyFailures) = result else {
            XCTFail("Failed to validate: \(result)")
            return
        }

        XCTAssertEqual(policyFailures.count, 1)
    }

    func testNotYetValidRootIsRejected() async throws {
        try await self._notYetValidRootIsRejected(.rfc5280)
    }

    func testNotYetValidRootIsRejectedBasePolicy() async throws {
        try await self._notYetValidRootIsRejected(.expiry)
    }

    func testNotYetValidRootIsNotRejectedIfValidityCheckingIsDisabled() async throws {
        let roots = CertificateStore([TestPKI.unconstrainedCA])
        let leaf = TestPKI.issueLeaf(
            notValidBefore: TestPKI.unconstrainedCA.notValidBefore - 2.0,  // Earlier than the root
            notValidAfter: TestPKI.startDate,
            issuer: .unconstrainedRoot  // Issue off the root directly to avoid the intermediate getting involved.
        )

        var verifier = Verifier(
            rootCertificates: roots,
            policy: PolicySet(policies: [RFC5280Policy.withValidityCheckDisabled()])
        )
        let result = await verifier.validate(leafCertificate: leaf, intermediates: CertificateStore([TestPKI.unconstrainedIntermediate]))

        guard case .validCertificate = result else {
            XCTFail("Failed to validate: \(result)")
            return
        }
    }

    func _malformedExpiryIsRejected(_ policyFactory: PolicyFactory) async throws {
        let roots = CertificateStore([TestPKI.unconstrainedCA])
        let leaf = TestPKI.issueLeaf(
            notValidBefore: TestPKI.startDate + 3.0,
            notValidAfter: TestPKI.startDate + 2.0,  // invalid order
            issuer: .unconstrainedIntermediate
        )

        var verifier = Verifier(
            rootCertificates: roots, policy: PolicySet(policies: [policyFactory.create(TestPKI.startDate + 2.5)])
        )
        let result = await verifier.validate(leafCertificate: leaf, intermediates: CertificateStore([TestPKI.unconstrainedIntermediate]))

        guard case .couldNotValidate(let policyFailures) = result else {
            XCTFail("Failed to validate: \(result)")
            return
        }

        XCTAssertEqual(policyFailures.count, 1)
    }

    func testMalformedExpiryIsRejected() async throws {
        try await self._malformedExpiryIsRejected(.rfc5280)
    }

    func testMalformedExpiryIsRejectedBasePolicy() async throws {
        try await self._malformedExpiryIsRejected(.expiry)
    }

    func testMalformedExpiryIsNotRejectedIfValidityCheckingIsDisabled() async throws {
        let roots = CertificateStore([TestPKI.unconstrainedCA])
        let leaf = TestPKI.issueLeaf(
            notValidBefore: TestPKI.startDate + 3.0,
            notValidAfter: TestPKI.startDate + 2.0,  // invalid order
            issuer: .unconstrainedIntermediate
        )

        var verifier = Verifier(
            rootCertificates: roots, policy: PolicySet(policies: [RFC5280Policy.withValidityCheckDisabled()])
        )
        let result = await verifier.validate(leafCertificate: leaf, intermediates: CertificateStore([TestPKI.unconstrainedIntermediate]))

        guard case .validCertificate = result else {
            XCTFail("Failed to validate: \(result)")
            return
        }
    }

    // This is a BasicConstraints extension that is invalid gibberish
    private static let brokenBasicConstraints = Certificate.Extension(
        oid: .X509ExtensionID.basicConstraints, critical: true, value: [1, 2, 3, 4, 5, 6, 7, 8, 9]
    )

    func _selfSignedCertsMustBeMarkedAsCA(_ policyFactory: PolicyFactory) async throws {
        let certsAndValidity = [
            (TestPKI.issueSelfSignedCert(basicConstraints: .isCertificateAuthority(maxPathLength: nil)), true),
            (TestPKI.issueSelfSignedCert(basicConstraints: .isCertificateAuthority(maxPathLength: 0)), true),
            (TestPKI.issueSelfSignedCert(basicConstraints: .notCertificateAuthority), false),
            (TestPKI.issueSelfSignedCert(customExtensions: Certificate.Extensions([Self.brokenBasicConstraints])), false),
            (TestPKI.issueSelfSignedCert(version: .v1), true),
        ]

        for (cert, isValid) in certsAndValidity {
            var verifier = Verifier(
                rootCertificates: CertificateStore([cert]),
                policy: PolicySet(policies: [policyFactory.create(TestPKI.startDate + 2.5)])
            )
            let result = await verifier.validate(leafCertificate: cert, intermediates: CertificateStore([]))

            switch (result, isValid) {
            case (.validCertificate, true),
                (.couldNotValidate, false):
                ()
            case (_, true):
                XCTFail("Failed to validate: \(result) \(cert)")
            case (_, false):
                XCTFail("Incorrectly validated: \(result) \(cert)")
            }
        }
    }

    func testSelfSignedCertsMustBeMarkedAsCA() async throws {
        try await self._selfSignedCertsMustBeMarkedAsCA(.rfc5280)
    }

    func testSelfSignedCertsMustBeMarkedAsCABasePolicy() async throws {
        try await self._selfSignedCertsMustBeMarkedAsCA(.basicConstraints)
    }

    func _intermediateCAMustBeMarkedCAInBasicConstraints(_ policyFactory: PolicyFactory) async throws {
        let invalidIntermediateCAs = [
            // Explicitly not being a CA is bad
            TestPKI.issueIntermediate(
                name: TestPKI.unconstrainedIntermediateName,
                key: .init(TestPKI.unconstrainedIntermediateKey.publicKey),
                extensions: try! Certificate.Extensions {
                    Critical(
                        BasicConstraints.notCertificateAuthority
                    )
                },
                issuer: .unconstrainedRoot
            ),

            // Not having BasicConstraints at all is also bad.
            TestPKI.issueIntermediate(
                name: TestPKI.unconstrainedIntermediateName,
                key: .init(TestPKI.unconstrainedIntermediateKey.publicKey),
                extensions: Certificate.Extensions([]),
                issuer: .unconstrainedRoot
            ),

            // As is having broken BasicConstraints
            TestPKI.issueIntermediate(
                name: TestPKI.unconstrainedIntermediateName,
                key: .init(TestPKI.unconstrainedIntermediateKey.publicKey),
                extensions: Certificate.Extensions([Self.brokenBasicConstraints]),
                issuer: .unconstrainedRoot
            )
        ]

        let leaf = TestPKI.issueLeaf(issuer: .unconstrainedIntermediate)

        for badIntermediate in invalidIntermediateCAs {
            var verifier = Verifier(
                rootCertificates: CertificateStore([TestPKI.unconstrainedCA]),
                policy: PolicySet(policies: [policyFactory.create(TestPKI.startDate + 2.5)])
            )
            var result = await verifier.validate(leafCertificate: leaf, intermediates: CertificateStore([badIntermediate]))

            guard case .couldNotValidate = result else {
                XCTFail("Incorrectly validated with \(badIntermediate) in chain")
                return
            }

            // Adding the better CA in works better, _and_ we don't use the bad intermediate!
            verifier = Verifier(
                rootCertificates: CertificateStore([TestPKI.unconstrainedCA]),
                policy: PolicySet(policies: [policyFactory.create(TestPKI.startDate + 2.5)])
            )
            result = await verifier.validate(leafCertificate: leaf, intermediates: CertificateStore([badIntermediate, TestPKI.unconstrainedIntermediate]))

            guard case .validCertificate(let chain) = result else {
                XCTFail("Unable to validate with both bad and good intermediate in chain")
                return
            }

            XCTAssertEqual(chain, [leaf, TestPKI.unconstrainedIntermediate, TestPKI.unconstrainedCA])

            // And having a v1 intermediate is fine too.
            let v1Intermediate = TestPKI.issueIntermediate(
                name: TestPKI.unconstrainedIntermediateName,
                version: .v1,
                key: .init(TestPKI.unconstrainedIntermediateKey.publicKey),
                extensions: Certificate.Extensions([]),
                issuer: .unconstrainedRoot
            )

            verifier = Verifier(
                rootCertificates: CertificateStore([TestPKI.unconstrainedCA]),
                policy: PolicySet(policies: [policyFactory.create(TestPKI.startDate + 2.5)])
            )
            result = await verifier.validate(leafCertificate: leaf, intermediates: CertificateStore([v1Intermediate]))

            guard case .validCertificate(let chain) = result else {
                XCTFail("Unable to validate with v1 intermediate in chain")
                return
            }

            XCTAssertEqual(chain, [leaf, v1Intermediate, TestPKI.unconstrainedCA])
        }
    }

    func testIntermediateCAMustBeMarkedAsCAInBasicConstraints() async throws {
        try await self._intermediateCAMustBeMarkedCAInBasicConstraints(.rfc5280)
    }

    func testIntermediateCAMustBeMarkedAsCAInBasicConstraintsBasePolicy() async throws {
        try await self._intermediateCAMustBeMarkedCAInBasicConstraints(.basicConstraints)
    }

    func _rootCAMustBeMarkedCAInBasicConstraints(_ policyFactory: PolicyFactory) async throws {
        let invalidRootCAs = [
            // Explicitly not being a CA is bad
            TestPKI.issueCA(extensions: try! Certificate.Extensions {
                Critical(
                    BasicConstraints.notCertificateAuthority
                )
            }),

            // Not having BasicConstraints at all is also bad.
            TestPKI.issueCA(extensions: Certificate.Extensions([])),

            // As is having broken BasicConstraints
            TestPKI.issueCA(extensions: Certificate.Extensions([Self.brokenBasicConstraints]))
        ]

        let leaf = TestPKI.issueLeaf(issuer: .unconstrainedIntermediate)

        for badRoot in invalidRootCAs {
            var verifier = Verifier(
                rootCertificates: CertificateStore([badRoot]),
                policy: PolicySet(policies: [policyFactory.create(TestPKI.startDate + 2.5)])
            )
            var result = await verifier.validate(leafCertificate: leaf, intermediates: CertificateStore([TestPKI.unconstrainedIntermediate]))

            guard case .couldNotValidate = result else {
                XCTFail("Incorrectly validated with \(badRoot) in chain")
                return
            }

            // Adding the better CA in works better, _and_ we don't use the bad root!
            verifier = Verifier(
                rootCertificates: CertificateStore([badRoot, TestPKI.unconstrainedCA]),
                policy: PolicySet(policies: [policyFactory.create(TestPKI.startDate + 2.5)])
            )
            result = await verifier.validate(leafCertificate: leaf, intermediates: CertificateStore([TestPKI.unconstrainedIntermediate]))

            guard case .validCertificate(let chain) = result else {
                XCTFail("Unable to validate with both bad and good root in chain")
                return
            }

            XCTAssertEqual(chain, [leaf, TestPKI.unconstrainedIntermediate, TestPKI.unconstrainedCA])

            // And a v1 root works too.
            let v1Root = TestPKI.issueCA(version: .v1, extensions: .init())

            verifier = Verifier(
                rootCertificates: CertificateStore([v1Root]),
                policy: PolicySet(policies: [policyFactory.create(TestPKI.startDate + 2.5)])
            )
            result = await verifier.validate(leafCertificate: leaf, intermediates: CertificateStore([TestPKI.unconstrainedIntermediate]))

            guard case .validCertificate(let chain) = result else {
                XCTFail("Unable to validate with v1 root in chain")
                return
            }

            XCTAssertEqual(chain, [leaf, TestPKI.unconstrainedIntermediate, v1Root])
        }
    }

    func testRootCAMustBeMarkedAsCAInBasicConstraints() async throws {
        try await self._rootCAMustBeMarkedCAInBasicConstraints(.rfc5280)
    }

    func testRootCAMustBeMarkedAsCAInBasicConstraintsBasePolicy() async throws {
        try await self._rootCAMustBeMarkedCAInBasicConstraints(.basicConstraints)
    }

    func _pathLengthConstraintsFromIntermediatesAreApplied(_ policyFactory: PolicyFactory) async throws {
        // This test requires that we use a second-level intermediate, to police the first-level
        // intermediate's path length constraint. This second level intermediate has a valid path length
        // constraint.
        let secondLevelIntermediate = TestPKI.issueIntermediate(
            name: TestPKI.secondLevelIntermediateName,
            key: .init(TestPKI.secondLevelIntermediateKey.publicKey),
            extensions: try! Certificate.Extensions {
                Critical(
                    BasicConstraints.isCertificateAuthority(maxPathLength: 0)
                )
            },
            issuer: .unconstrainedIntermediate
        )

        let leaf = TestPKI.issueLeaf(issuer: .secondLevelIntermediate)

        var verifier = Verifier(
            rootCertificates: CertificateStore([TestPKI.unconstrainedCA]),
            policy: PolicySet(policies: [policyFactory.create(TestPKI.startDate + 2.5)])
        )
        var result = await verifier.validate(leafCertificate: leaf, intermediates: CertificateStore([secondLevelIntermediate, TestPKI.unconstrainedIntermediate]))

        guard case .couldNotValidate = result else {
            XCTFail("Incorrectly validated with \(secondLevelIntermediate) in chain")
            return
        }

        // Creating a new first-level intermediate with a better path length constraint works!
        let newFirstLevelIntermediate = TestPKI.issueIntermediate(
            name: TestPKI.unconstrainedIntermediateName,
            key: .init(TestPKI.unconstrainedIntermediateKey.publicKey),
            extensions: try! Certificate.Extensions {
                Critical(
                    BasicConstraints.isCertificateAuthority(maxPathLength: 1)
                )
            },
            issuer: .unconstrainedRoot
        )

        verifier = Verifier(
            rootCertificates: CertificateStore([TestPKI.unconstrainedCA]),
            policy: PolicySet(policies: [policyFactory.create(TestPKI.startDate + 2.5)])
        )
        result = await verifier.validate(leafCertificate: leaf, intermediates: CertificateStore([secondLevelIntermediate, newFirstLevelIntermediate, TestPKI.unconstrainedIntermediate]))

        guard case .validCertificate(let chain) = result else {
            XCTFail("Unable to validate with both bad and good intermediate in chain")
            return
        }

        XCTAssertEqual(chain, [leaf, secondLevelIntermediate, newFirstLevelIntermediate, TestPKI.unconstrainedCA])
    }

    func testPathLengthConstraintsFromIntermediatesAreApplied() async throws {
        try await self._pathLengthConstraintsFromIntermediatesAreApplied(.rfc5280)
    }

    func testPathLengthConstraintsFromIntermediatesAreAppliedBasePolicy() async throws {
        try await self._pathLengthConstraintsFromIntermediatesAreApplied(.basicConstraints)
    }

    func _pathLengthConstraintsOnRootsAreApplied(_ policyFactory: PolicyFactory) async throws {
        // This test requires that we use a second-level intermediate, to police the first-level
        // intermediate's path length constraint. This second level intermediate has a valid path length
        // constraint.
        let alternativeRoot = TestPKI.issueCA(
            extensions: try! Certificate.Extensions {
                Critical(
                    BasicConstraints.isCertificateAuthority(maxPathLength: 0)
                )
            }
        )

        let leaf = TestPKI.issueLeaf(issuer: .unconstrainedIntermediate)

        var verifier = Verifier(
            rootCertificates: CertificateStore([alternativeRoot]),
            policy: PolicySet(policies: [policyFactory.create(TestPKI.startDate + 2.5)])
        )
        var result = await verifier.validate(leafCertificate: leaf, intermediates: CertificateStore([TestPKI.unconstrainedIntermediate]))

        guard case .couldNotValidate = result else {
            XCTFail("Incorrectly validated with \(alternativeRoot) in chain")
            return
        }

        // Adding back the good root works!
        verifier = Verifier(
            rootCertificates: CertificateStore([alternativeRoot, TestPKI.unconstrainedCA]),
            policy: PolicySet(policies: [policyFactory.create(TestPKI.startDate + 2.5)])
        )
        result = await verifier.validate(leafCertificate: leaf, intermediates: CertificateStore([TestPKI.unconstrainedIntermediate]))

        guard case .validCertificate(let chain) = result else {
            XCTFail("Unable to validate with both bad and good intermediate in chain")
            return
        }

        XCTAssertEqual(chain, [leaf, TestPKI.unconstrainedIntermediate, TestPKI.unconstrainedCA])
    }

    func testPathLengthConstraintsOnRootsAreApplied() async throws {
        try await self._pathLengthConstraintsFromIntermediatesAreApplied(.rfc5280)
    }

    func testPathLengthConstraintsOnRootsAreAppliedBasePolicy() async throws {
        try await self._pathLengthConstraintsFromIntermediatesAreApplied(.basicConstraints)
    }

    func testDNSNameConstraintsExcludedSubtrees() async throws {
        for (dnsName, constraint, match) in DNSNamesTests.fixtures {
            try await self.nameconstraintsExcludedSubtrees(
                excludedSubtrees: [.dnsName(constraint)], subjectAlternativeNames: [.dnsName(dnsName)], match: match, policyFactory: .rfc5280
            )
        }
    }

    func testDNSNameConstraintsExcludedSubtreesBasePolicy() async throws {
        for (dnsName, constraint, match) in DNSNamesTests.fixtures {
            try await self.nameconstraintsExcludedSubtrees(
                excludedSubtrees: [.dnsName(constraint)], subjectAlternativeNames: [.dnsName(dnsName)], match: match, policyFactory: .nameConstraints
            )
        }
    }

    func testIPAddressNameConstraintsExcludedSubtrees() async throws {
        for (ipAddress, constraint, match) in IPAddressNameTests.fixtures {
            try await self.nameconstraintsExcludedSubtrees(
                excludedSubtrees: [.ipAddress(constraint)], subjectAlternativeNames: [.ipAddress(ipAddress)], match: match, policyFactory: .rfc5280
            )
        }
    }

    func testIPAddressNameConstraintsExcludedSubtreesBasePolicy() async throws {
        for (ipAddress, constraint, match) in IPAddressNameTests.fixtures {
            try await self.nameconstraintsExcludedSubtrees(
                excludedSubtrees: [.ipAddress(constraint)], subjectAlternativeNames: [.ipAddress(ipAddress)], match: match, policyFactory: .nameConstraints
            )
        }
    }

    func testDirectoryNameConstraintsExcludedSubtrees() async throws {
        for firstName in NameConstraintsTests.names {
            for secondName in NameConstraintsTests.names {
                try await self.nameconstraintsExcludedSubtrees(
                    excludedSubtrees: [.directoryName(firstName)], subjectAlternativeNames: [.directoryName(secondName)], match: firstName == secondName, policyFactory: .rfc5280
                )
            }
        }
    }

    func testDirectoryNameConstraintsExcludedSubtreesBasePolicy() async throws {
        for firstName in NameConstraintsTests.names {
            for secondName in NameConstraintsTests.names {
                try await self.nameconstraintsExcludedSubtrees(
                    excludedSubtrees: [.directoryName(firstName)], subjectAlternativeNames: [.directoryName(secondName)], match: firstName == secondName, policyFactory: .nameConstraints
                )
            }
        }
    }

    func testDNSNameConstraintsPermittedSubtrees() async throws {
        for (dnsName, constraint, match) in DNSNamesTests.fixtures {
            try await self.nameconstraintsPermittedSubtrees(
                permittedSubtrees: [.dnsName(constraint)], subjectAlternativeNames: [.dnsName(dnsName)], match: match, policyFactory: .rfc5280
            )
        }
    }

    func testDNSNameConstraintsPermittedSubtreesBasePolicy() async throws {
        for (dnsName, constraint, match) in DNSNamesTests.fixtures {
            try await self.nameconstraintsPermittedSubtrees(
                permittedSubtrees: [.dnsName(constraint)], subjectAlternativeNames: [.dnsName(dnsName)], match: match, policyFactory: .nameConstraints
            )
        }
    }

    func testIPAddressNameConstraintsPermittedSubtrees() async throws {
        for (ipAddress, constraint, match) in IPAddressNameTests.fixtures {
            try await self.nameconstraintsPermittedSubtrees(
                permittedSubtrees: [.ipAddress(constraint)], subjectAlternativeNames: [.ipAddress(ipAddress)], match: match, policyFactory: .rfc5280
            )
        }
    }

    func testIPAddressNameConstraintsPermittedSubtreesBasePolicy() async throws {
        for (ipAddress, constraint, match) in IPAddressNameTests.fixtures {
            try await self.nameconstraintsPermittedSubtrees(
                permittedSubtrees: [.ipAddress(constraint)], subjectAlternativeNames: [.ipAddress(ipAddress)], match: match, policyFactory: .nameConstraints
            )
        }
    }

    func testDirectoryNameConstraintsPermittedSubtrees() async throws {
        // Fun fact! These tests require additional permitted subtrees, because they _also_ have to match the subject names
        // of the certificates. So let's add those too to omit them from the testing.
        let leafName = try! DistinguishedName {
            CountryName("US")
            OrganizationName("Apple")
            CommonName("Leaf")
        }

        for firstName in NameConstraintsTests.names {
            for secondName in NameConstraintsTests.names {
                try await self.nameconstraintsPermittedSubtrees(
                    permittedSubtrees: [.directoryName(firstName), .directoryName(TestPKI.unconstrainedIntermediateName), .directoryName(leafName)],
                    subjectAlternativeNames: [.directoryName(secondName)],
                    match: firstName == secondName,
                    policyFactory: .rfc5280
                )
            }
        }
    }

    func testDirectoryNameConstraintsPermittedSubtreesBasePolicy() async throws {
        // Fun fact! These tests require additional permitted subtrees, because they _also_ have to match the subject names
        // of the certificates. So let's add those too to omit them from the testing.
        let leafName = try! DistinguishedName {
            CountryName("US")
            OrganizationName("Apple")
            CommonName("Leaf")
        }

        for firstName in NameConstraintsTests.names {
            for secondName in NameConstraintsTests.names {
                try await self.nameconstraintsPermittedSubtrees(
                    permittedSubtrees: [.directoryName(firstName), .directoryName(TestPKI.unconstrainedIntermediateName), .directoryName(leafName)],
                    subjectAlternativeNames: [.directoryName(secondName)],
                    match: firstName == secondName,
                    policyFactory: .nameConstraints
                )
            }
        }
    }

    func allExcludedSubtreesAreEvaluated(_ policyFactory: PolicyFactory) async throws {
        // This confirms that so long as there exists _a_ constraint, it matches, even if there are others.
        let names: [GeneralName] = [
            .directoryName(try! DistinguishedName {
                CommonName("Excluded")
            }),
            .uniformResourceIdentifier("http://example.com"),
            .dnsName("example.org"),
            .ipAddress(ASN1OctetString(contentBytes: [127, 0, 0, 1])),
        ]
        let excludedSubtrees = [
            names[0],
            .uniformResourceIdentifier("example.com"),
            names[2],
            .ipAddress(ASN1OctetString(contentBytes: [127, 0, 0, 1, 255, 0, 0, 0])),
        ]
        let alternativeRoot = TestPKI.issueCA(
            extensions: try! Certificate.Extensions {
                Critical(
                    BasicConstraints.isCertificateAuthority(maxPathLength: nil)
                )
                Critical(
                    NameConstraints(excludedSubtrees: excludedSubtrees)
                )
            }
        )
        let roots = CertificateStore([alternativeRoot])

        for name in names {
            let leaf = TestPKI.issueLeaf(
                issuer: .unconstrainedIntermediate,
                subjectAlternativeNames: [name]
            )

            var verifier = Verifier(rootCertificates: roots) { policyFactory.create(TestPKI.startDate + 2.5) }
            let result = await verifier.validate(leafCertificate: leaf, intermediates: CertificateStore([TestPKI.unconstrainedIntermediate]))

            guard case .couldNotValidate = result else {
                XCTFail("Unexpectedly validated")
                return
            }
        }
    }

    func testAllExcludedSubtreesAreEvaluated() async throws {
        try await self.allExcludedSubtreesAreEvaluated(.rfc5280)
    }

    func testAllExcludedSubtreesAreEvaluatedBasePolicy() async throws {
        try await self.allExcludedSubtreesAreEvaluated(.nameConstraints)
    }

    func subtreesOfUnknownTypeAlwaysFail(_ policyFactory: PolicyFactory) async throws {
        let subtrees: [GeneralName] = try [
            .otherName(.init(typeID: [1, 2, 1, 1], value: ASN1Any(erasing: ASN1Null()))),
            .rfc822Name("bar.com"),
            .x400Address(ASN1Any(erasing: ASN1Null(), withIdentifier: GeneralName.x400AddressTag)),
            .ediPartyName(ASN1Any(erasing: ASN1Null(), withIdentifier: GeneralName.ediPartyNameTag)),
            .registeredID([1, 2, 1, 1]),
        ]
        let leaf = TestPKI.issueLeaf(
            issuer: .unconstrainedIntermediate
        )

        for name in subtrees {
            // First try excluded.
            var alternativeRoot = TestPKI.issueCA(
                extensions: try! Certificate.Extensions {
                    Critical(
                        BasicConstraints.isCertificateAuthority(maxPathLength: nil)
                    )
                    Critical(
                        NameConstraints(excludedSubtrees: [name])
                    )
                }
            )

            var roots = CertificateStore([alternativeRoot])
            var verifier = Verifier(rootCertificates: roots) { policyFactory.create(TestPKI.startDate + 2.5) }
            var result = await verifier.validate(leafCertificate: leaf, intermediates: CertificateStore([TestPKI.unconstrainedIntermediate]))

            guard case .couldNotValidate = result else {
                XCTFail("Unexpectedly validated")
                return
            }

            // Then included
            alternativeRoot = TestPKI.issueCA(
                extensions: try! Certificate.Extensions {
                    Critical(
                        BasicConstraints.isCertificateAuthority(maxPathLength: nil)
                    )
                    Critical(
                        NameConstraints(permittedSubtrees: [name])
                    )
                }
            )
            let constrainedLeaf = TestPKI.issueLeaf(
                issuer: .unconstrainedIntermediate,
                subjectAlternativeNames: [name]
            )

            roots = CertificateStore([alternativeRoot])
            verifier = Verifier(rootCertificates: roots) { policyFactory.create(TestPKI.startDate + 2.5) }
            result = await verifier.validate(leafCertificate: constrainedLeaf, intermediates: CertificateStore([TestPKI.unconstrainedIntermediate]))

            guard case .couldNotValidate = result else {
                XCTFail("Unexpectedly validated")
                return
            }
        }
    }

    func testSubtreesOfUnknownTypeAlwaysFail() async throws {
        try await self.subtreesOfUnknownTypeAlwaysFail(.rfc5280)
    }

    func testSubtreesOfUnknownTypeAlwaysFailBasePolicy() async throws {
        try await self.subtreesOfUnknownTypeAlwaysFail(.nameConstraints)
    }

    // This is a NameConstraints extension that is invalid gibberish
    private static let brokenNameConstraints = Certificate.Extension(
        oid: .X509ExtensionID.nameConstraints, critical: true, value: [1, 2, 3, 4, 5, 6, 7, 8, 9]
    )

    // This is a SAN extension that is invalid gibberish
    private static let brokenSubjectAlternativeName = Certificate.Extension(
        oid: .X509ExtensionID.subjectAlternativeName, critical: true, value: [1, 2, 3, 4, 5, 6, 7, 8, 9]
    )

    func brokenExtensionsPreventValidation(_ policyFactory: PolicyFactory) async throws {
        let alternativeRoot = TestPKI.issueCA(
            extensions: try! Certificate.Extensions {
                Critical(
                    BasicConstraints.isCertificateAuthority(maxPathLength: nil)
                )
                Critical(
                    Self.brokenNameConstraints
                )
            }
        )
        let goodRootWithConstraint = TestPKI.issueCA(
            extensions: try! Certificate.Extensions {
                Critical(
                    BasicConstraints.isCertificateAuthority(maxPathLength: nil)
                )
                Critical(
                    NameConstraints(excludedSubtrees: [
                        .dnsName("example.com")
                    ])
                )
            }
        )
        let bustedSAN = TestPKI.issueLeaf(
            issuer: .unconstrainedIntermediate,
            customExtensions: try! Certificate.Extensions {
                Critical(
                    BasicConstraints.notCertificateAuthority
                )
                Critical(
                    Self.brokenSubjectAlternativeName
                )
            }
        )
        let goodLeaf = TestPKI.issueLeaf(issuer: .unconstrainedIntermediate)

        // First test the bad root.
        var roots = CertificateStore([alternativeRoot])
        var verifier = Verifier(rootCertificates: roots) { policyFactory.create(TestPKI.startDate + 2.5) }
        var result = await verifier.validate(leafCertificate: goodLeaf, intermediates: CertificateStore([TestPKI.unconstrainedIntermediate]))

        guard case .couldNotValidate = result else {
            XCTFail("Unexpectedly validated")
            return
        }

        // Then the bad leaf.
        roots = CertificateStore([goodRootWithConstraint])
        verifier = Verifier(rootCertificates: roots) { policyFactory.create(TestPKI.startDate + 2.5) }
        result = await verifier.validate(leafCertificate: bustedSAN, intermediates: CertificateStore([TestPKI.unconstrainedIntermediate]))

        guard case .couldNotValidate = result else {
            XCTFail("Unexpectedly validated")
            return
        }
    }

    func testBrokenExtensionsPreventValidation() async throws {
        try await self.brokenExtensionsPreventValidation(.rfc5280)
    }

    func testBrokenExtensionsPreventValidationBasePolicy() async throws {
        try await self.brokenExtensionsPreventValidation(.nameConstraints)
    }

    func excludedSubtreesBeatPermittedSubtrees(_ policyFactory: PolicyFactory) async throws {
        let name = try! DistinguishedName {
            CommonName("Example")
        }

        // Having a name present in the excluded subtrees overrules the permitted ones.
        let names: [GeneralName] = [
            .dnsName("example.com"),
            .ipAddress(ASN1OctetString(contentBytes: [127, 0, 0, 1, 255, 0, 0, 0])),
            .uniformResourceIdentifier("example.com"),
            .directoryName(name)
        ]

        let alternativeIntermediate = TestPKI.issueIntermediate(
            name: TestPKI.unconstrainedIntermediateName,
            key: .init(TestPKI.unconstrainedIntermediateKey.publicKey),
            extensions: try! Certificate.Extensions {
                Critical(
                    BasicConstraints.isCertificateAuthority(maxPathLength: 0)
                )

                NameConstraints(permittedSubtrees: names, excludedSubtrees: names)
            },
            issuer: .unconstrainedRoot
        )

        let roots = CertificateStore([TestPKI.unconstrainedCA])

        for name in names {
            let leaf = TestPKI.issueLeaf(
                issuer: .unconstrainedIntermediate,
                subjectAlternativeNames: [name]
            )

            var verifier = Verifier(rootCertificates: roots) { policyFactory.create(TestPKI.startDate + 2.5) }
            let result = await verifier.validate(leafCertificate: leaf, intermediates: CertificateStore([alternativeIntermediate]))

            guard case .couldNotValidate = result else {
                XCTFail("Unexpectedly validated")
                return
            }
        }
    }

    func testExcludedSubtreesBeatPermittedSubtrees() async throws {
        try await self.excludedSubtreesBeatPermittedSubtrees(.rfc5280)
    }

    func testExcludedSubtreesBeatPermittedSubtreesBasePolicy() async throws {
        try await self.excludedSubtreesBeatPermittedSubtrees(.nameConstraints)
    }

    func testIgnoresKeyUsage() async throws {
        // This test doesn't have a base policy version, only the combined policy does this.
        let alternativeIntermediate = TestPKI.issueIntermediate(
            name: TestPKI.unconstrainedIntermediateName,
            key: .init(TestPKI.unconstrainedIntermediateKey.publicKey),
            extensions: try! Certificate.Extensions {
                Critical(
                    BasicConstraints.isCertificateAuthority(maxPathLength: 0)
                )

                // This key usage is forbidden by RFC 5280 in the context of an intermediate:
                //
                //   If the keyUsage extension is present, then the subject public key
                //   MUST NOT be used to verify signatures on certificates or CRLs unless
                //   the corresponding keyCertSign or cRLSign bit is set.
                //
                // We don't care here.
                Critical(
                    KeyUsage(digitalSignature: true)
                )
            },
            issuer: .unconstrainedRoot
        )

        let roots = CertificateStore([TestPKI.unconstrainedCA])
        let leaf = TestPKI.issueLeaf(issuer: .unconstrainedIntermediate)

        var verifier = Verifier(rootCertificates: roots, policy: PolicySet(policies: [RFC5280Policy(validationTime: Date())]))
        let result = await verifier.validate(leafCertificate: leaf, intermediates: CertificateStore([alternativeIntermediate]))

        guard case .validCertificate(let chain) = result else {
            XCTFail("Failed to validate: \(result)")
            return
        }

        XCTAssertEqual(chain, [leaf, alternativeIntermediate, TestPKI.unconstrainedCA])
    }

    func testFailsOnWeirdCriticalExtensionInLeaf() async throws {
        // This test doesn't have a base policy version, only the combined policy does this.
        let leaf = TestPKI.issueLeaf(
            issuer: .unconstrainedIntermediate,
            customExtensions: try! Certificate.Extensions {
                Critical(
                    BasicConstraints.notCertificateAuthority
                )
                Certificate.Extension(oid: [1, 2, 3, 4, 5], critical: true, value: [1, 2, 3, 4, 5])
            }
        )

        let roots = CertificateStore([TestPKI.unconstrainedCA])

        var verifier = Verifier(rootCertificates: roots, policy: PolicySet(policies: [RFC5280Policy(validationTime: Date())]))
        let result = await verifier.validate(leafCertificate: leaf, intermediates: CertificateStore([TestPKI.unconstrainedIntermediate]))

        guard case .couldNotValidate = result else {
            XCTFail("Incorrectly validated: \(result)")
            return
        }
    }
}

final class RFC5280PolicyURINameTests1: RFC5280PolicyBase {
    func testURINameConstraintsExcludedSubtrees() async throws {
        // This adapts the basic checks from the DNS name case, as they apply to the host part of the constraint. However,
        // to each case we add a little URI special sauce to confirm that they all still work (or don't!).
        for (dnsName, constraint, match) in DNSNamesTests.fixtures {
            for uri in DNSNamesTests.urisThatMatch(dnsName) {
                try await self.nameconstraintsExcludedSubtrees(
                    excludedSubtrees: [.uniformResourceIdentifier(constraint)], subjectAlternativeNames: [.uniformResourceIdentifier(uri)], match: match, policyFactory: .rfc5280
                )

                // Never works inverted
                try await self.nameconstraintsExcludedSubtrees(
                    excludedSubtrees: [.uniformResourceIdentifier(uri)], subjectAlternativeNames: [.uniformResourceIdentifier(constraint)], match: false, policyFactory: .rfc5280
                )
            }

            if constraint == "" {
                // We don't test the "don't match" case on the empty constraint, because everything matches the empty constraint
                continue
            }

            for uri in DNSNamesTests.urisThatDontMatch(dnsName) {
                try await self.nameconstraintsExcludedSubtrees(
                    excludedSubtrees: [.uniformResourceIdentifier(constraint)], subjectAlternativeNames: [.uniformResourceIdentifier(uri)], match: false, policyFactory: .rfc5280
                )
            }
        }
    }
}
final class RFC5280PolicyURINameTests2: RFC5280PolicyBase {
    func testURINameConstraintsExcludedSubtreesBasePolicy() async throws {
        // This adapts the basic checks from the DNS name case, as they apply to the host part of the constraint. However,
        // to each case we add a little URI special sauce to confirm that they all still work (or don't!).
        for (dnsName, constraint, match) in DNSNamesTests.fixtures {
            for uri in DNSNamesTests.urisThatMatch(dnsName) {
                try await self.nameconstraintsExcludedSubtrees(
                    excludedSubtrees: [.uniformResourceIdentifier(constraint)], subjectAlternativeNames: [.uniformResourceIdentifier(uri)], match: match, policyFactory: .nameConstraints
                )

                // Never works inverted
                try await self.nameconstraintsExcludedSubtrees(
                    excludedSubtrees: [.uniformResourceIdentifier(uri)], subjectAlternativeNames: [.uniformResourceIdentifier(constraint)], match: false, policyFactory: .nameConstraints
                )
            }

            if constraint == "" {
                // We don't test the "don't match" case on the empty constraint, because everything matches the empty constraint
                continue
            }

            for uri in DNSNamesTests.urisThatDontMatch(dnsName) {
                try await self.nameconstraintsExcludedSubtrees(
                    excludedSubtrees: [.uniformResourceIdentifier(constraint)], subjectAlternativeNames: [.uniformResourceIdentifier(uri)], match: false, policyFactory: .nameConstraints
                )
            }
        }
    }
}
final class RFC5280PolicyURINameTests3: RFC5280PolicyBase {
    func testURINameConstraintsPermittedSubtrees() async throws {
        // This adapts the basic checks from the DNS name case, as they apply to the host part of the constraint. However,
        // to each case we add a little URI special sauce to confirm that they all still work (or don't!).
        for (dnsName, constraint, match) in DNSNamesTests.fixtures {
            for uri in DNSNamesTests.urisThatMatch(dnsName) {
                try await self.nameconstraintsPermittedSubtrees(
                    permittedSubtrees: [.uniformResourceIdentifier(constraint)], subjectAlternativeNames: [.uniformResourceIdentifier(uri)], match: match, policyFactory: .rfc5280
                )

                // Never works inverted
                try await self.nameconstraintsPermittedSubtrees(
                    permittedSubtrees: [.uniformResourceIdentifier(uri)], subjectAlternativeNames: [.uniformResourceIdentifier(constraint)], match: false, policyFactory: .rfc5280
                )
            }

            if constraint == "" {
                // We don't test the "don't match" case on the empty constraint, because everything matches the empty constraint
                continue
            }

            for uri in DNSNamesTests.urisThatDontMatch(dnsName) {
                try await self.nameconstraintsPermittedSubtrees(
                    permittedSubtrees: [.uniformResourceIdentifier(constraint)], subjectAlternativeNames: [.uniformResourceIdentifier(uri)], match: false, policyFactory: .rfc5280
                )
            }
        }
    }
}
final class RFC5280PolicyURINameTests4: RFC5280PolicyBase {
    func testURINameConstraintsPermittedSubtreesBasePolicy() async throws {
        // This adapts the basic checks from the DNS name case, as they apply to the host part of the constraint. However,
        // to each case we add a little URI special sauce to confirm that they all still work (or don't!).
        for (dnsName, constraint, match) in DNSNamesTests.fixtures {
            for uri in DNSNamesTests.urisThatMatch(dnsName) {
                try await self.nameconstraintsPermittedSubtrees(
                    permittedSubtrees: [.uniformResourceIdentifier(constraint)], subjectAlternativeNames: [.uniformResourceIdentifier(uri)], match: match, policyFactory: .nameConstraints
                )

                // Never works inverted
                try await self.nameconstraintsPermittedSubtrees(
                    permittedSubtrees: [.uniformResourceIdentifier(uri)], subjectAlternativeNames: [.uniformResourceIdentifier(constraint)], match: false, policyFactory: .nameConstraints
                )
            }

            if constraint == "" {
                // We don't test the "don't match" case on the empty constraint, because everything matches the empty constraint
                continue
            }

            for uri in DNSNamesTests.urisThatDontMatch(dnsName) {
                try await self.nameconstraintsPermittedSubtrees(
                    permittedSubtrees: [.uniformResourceIdentifier(constraint)], subjectAlternativeNames: [.uniformResourceIdentifier(uri)], match: false, policyFactory: .nameConstraints
                )
            }
        }
    }
}

fileprivate enum TestPKI {
    static let startDate = Date()

    static let unconstrainedCAPrivateKey = P384.Signing.PrivateKey()
    static let unconstrainedCAName = try! DistinguishedName {
        CountryName("US")
        OrganizationName("Apple")
        CommonName("Swift Certificate Test CA 1")
    }
    static let unconstrainedCA: Certificate = {
        return try! Certificate(
            version: .v3,
            serialNumber: .init(),
            publicKey: .init(unconstrainedCAPrivateKey.publicKey),
            notValidBefore: startDate - .days(3650),
            notValidAfter: startDate + .days(3650),
            issuer: unconstrainedCAName,
            subject: unconstrainedCAName,
            signatureAlgorithm: .ecdsaWithSHA384,
            extensions: Certificate.Extensions {
                Critical(
                    BasicConstraints.isCertificateAuthority(maxPathLength: nil)
                )
            },
            issuerPrivateKey: .init(unconstrainedCAPrivateKey)
        )
    }()
    static func issueCA(version: Certificate.Version = .v3, extensions: Certificate.Extensions) -> Certificate {
        return try! Certificate(
            version: version,
            serialNumber: .init(),
            publicKey: .init(unconstrainedCAPrivateKey.publicKey),
            notValidBefore: startDate - .days(3650),
            notValidAfter: startDate + .days(3650),
            issuer: unconstrainedCAName,
            subject: unconstrainedCAName,
            signatureAlgorithm: .ecdsaWithSHA384,
            extensions: extensions,
            issuerPrivateKey: .init(unconstrainedCAPrivateKey)
        )
    }

    static let unconstrainedIntermediateKey = P256.Signing.PrivateKey()
    static let unconstrainedIntermediateName = try! DistinguishedName {
        CountryName("US")
        OrganizationName("Apple")
        CommonName("Swift Certificate Test Intermediate 1")
    }
    static let unconstrainedIntermediate: Certificate = {
        return issueIntermediate(
            name: unconstrainedIntermediateName,
            key: .init(unconstrainedIntermediateKey.publicKey),
            extensions: try! Certificate.Extensions {
                Critical(
                    BasicConstraints.isCertificateAuthority(maxPathLength: 0)
                )
            },
            issuer: .unconstrainedRoot
        )
    }()
    static func issueIntermediate(name: DistinguishedName, version: Certificate.Version = .v3, key: Certificate.PublicKey, extensions: Certificate.Extensions, issuer: Issuer) -> Certificate {
        return try! Certificate(
            version: version,
            serialNumber: .init(),
            publicKey: key,
            notValidBefore: startDate - .days(365),
            notValidAfter: startDate + .days(365),
            issuer: issuer.name,
            subject: name,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: extensions,
            issuerPrivateKey: issuer.key
        )
    }

    static let secondLevelIntermediateKey = P256.Signing.PrivateKey()
    static let secondLevelIntermediateName = try! DistinguishedName {
        CountryName("US")
        OrganizationName("Apple")
        CommonName("Swift Certificate Test Intermediate 2")
    }

    enum Issuer {
        case unconstrainedRoot
        case unconstrainedIntermediate
        case secondLevelIntermediate

        var name: DistinguishedName {
            switch self {
            case .unconstrainedRoot:
                return unconstrainedCAName
            case .unconstrainedIntermediate:
                return unconstrainedIntermediateName
            case .secondLevelIntermediate:
                return secondLevelIntermediateName
            }
        }

        var key: Certificate.PrivateKey {
            switch self {
            case .unconstrainedRoot:
                return .init(unconstrainedCAPrivateKey)
            case .unconstrainedIntermediate:
                return .init(unconstrainedIntermediateKey)
            case .secondLevelIntermediate:
                return .init(secondLevelIntermediateKey)
            }
        }
    }

    static func issueLeaf(
        commonName: String = "Leaf",
        notValidBefore: Date = Self.startDate,
        notValidAfter: Date = Self.startDate + .days(365),
        issuer: Issuer,
        subjectAlternativeNames: [GeneralName]? = nil,
        customExtensions: Certificate.Extensions? = nil
    ) -> Certificate {
        let leafKey = P256.Signing.PrivateKey()
        let name = try! DistinguishedName {
            CountryName("US")
            OrganizationName("Apple")
            CommonName(commonName)
        }

        let extensions: Certificate.Extensions
        if let customExtensions {
            extensions = customExtensions
        } else {
            extensions = try! Certificate.Extensions {
                Critical(
                    BasicConstraints.notCertificateAuthority
                )
                if let subjectAlternativeNames {
                    SubjectAlternativeNames(subjectAlternativeNames)
                }
            }
        }

        return try! Certificate(
            version: .v3,
            serialNumber: .init(),
            publicKey: .init(leafKey.publicKey),
            notValidBefore: notValidBefore,
            notValidAfter: notValidAfter,
            issuer: issuer.name,
            subject: name,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: extensions,
            issuerPrivateKey: issuer.key
        )
    }

    static func issueSelfSignedCert(
        commonName: String = "Leaf",
        version: Certificate.Version = .v3,
        basicConstraints: BasicConstraints = .notCertificateAuthority,
        customExtensions: Certificate.Extensions? = nil
    ) -> Certificate {
        let selfSignedKey = P256.Signing.PrivateKey()
        let name = try! DistinguishedName {
            CountryName("US")
            OrganizationName("Apple")
            CommonName(commonName)
        }

        let extensions: Certificate.Extensions

        if let customExtensions {
            extensions = customExtensions
        } else if version == .v3 {
            extensions = try! Certificate.Extensions {
                Critical(
                    basicConstraints
                )
            }
        } else {
            extensions = .init()
        }

        return try! Certificate(
            version: version,
            serialNumber: .init(),
            publicKey: .init(selfSignedKey.publicKey),
            notValidBefore: Self.startDate,
            notValidAfter: Self.startDate + .days(365),
            issuer: name,
            subject: name,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: extensions,
            issuerPrivateKey: Certificate.PrivateKey(selfSignedKey)
        )
    }
}
