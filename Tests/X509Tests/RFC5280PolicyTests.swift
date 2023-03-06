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
import X509
import Crypto

final class RFC5280PolicyTests: XCTestCase {
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

    func testExpiredLeafIsRejected() async throws {
        let roots = CertificateStore([TestPKI.unconstrainedCA])
        let leaf = TestPKI.issueLeaf(
            notValidBefore: TestPKI.startDate + 1.0,
            notValidAfter: TestPKI.startDate + 2.0,  // One second validity window
            issuer: .unconstrainedIntermediate
        )

        var verifier = Verifier(
            rootCertificates: roots, policy: PolicySet(policies: [RFC5280Policy(validationTime: TestPKI.startDate + 3.0)])
        )
        let result = await verifier.validate(leafCertificate: leaf, intermediates: CertificateStore([TestPKI.unconstrainedIntermediate]))

        guard case .couldNotValidate(let policyFailures) = result else {
            XCTFail("Failed to validate: \(result)")
            return
        }

        XCTAssertEqual(policyFailures.count, 1)
    }

    func testExpiredIntermediateIsRejected() async throws {
        let roots = CertificateStore([TestPKI.unconstrainedCA])
        let leaf = TestPKI.issueLeaf(
            notValidBefore: TestPKI.startDate,
            notValidAfter: TestPKI.unconstrainedIntermediate.notValidAfter + 2.0,  // Later than the intermediate.
            issuer: .unconstrainedIntermediate
        )

        var verifier = Verifier(
            rootCertificates: roots,
            policy: PolicySet(policies: [RFC5280Policy(validationTime: TestPKI.unconstrainedIntermediate.notValidAfter + 1.0)])
        )
        let result = await verifier.validate(leafCertificate: leaf, intermediates: CertificateStore([TestPKI.unconstrainedIntermediate]))

        guard case .couldNotValidate(let policyFailures) = result else {
            XCTFail("Failed to validate: \(result)")
            return
        }

        XCTAssertEqual(policyFailures.count, 1)
    }

    func testExpiredRootIsRejected() async throws {
        let roots = CertificateStore([TestPKI.unconstrainedCA])
        let leaf = TestPKI.issueLeaf(
            notValidBefore: TestPKI.startDate,
            notValidAfter: TestPKI.unconstrainedCA.notValidAfter + 2.0,  // Later than the root.
            issuer: .unconstrainedRoot  // Issue off the root directly to avoid the intermediate getting involved.
        )

        var verifier = Verifier(
            rootCertificates: roots,
            policy: PolicySet(policies: [RFC5280Policy(validationTime: TestPKI.unconstrainedCA.notValidAfter + 1.0)])
        )
        let result = await verifier.validate(leafCertificate: leaf, intermediates: CertificateStore([TestPKI.unconstrainedIntermediate]))

        guard case .couldNotValidate(let policyFailures) = result else {
            XCTFail("Failed to validate: \(result)")
            return
        }

        XCTAssertEqual(policyFailures.count, 1)
    }

    func testNotYetValidLeafIsRejected() async throws {
        let roots = CertificateStore([TestPKI.unconstrainedCA])
        let leaf = TestPKI.issueLeaf(
            notValidBefore: TestPKI.startDate + 2.0,
            notValidAfter: TestPKI.startDate + 3.0,  // One second validity window
            issuer: .unconstrainedIntermediate
        )

        var verifier = Verifier(
            rootCertificates: roots, policy: PolicySet(policies: [RFC5280Policy(validationTime: TestPKI.startDate + 1.0)])
        )
        let result = await verifier.validate(leafCertificate: leaf, intermediates: CertificateStore([TestPKI.unconstrainedIntermediate]))

        guard case .couldNotValidate(let policyFailures) = result else {
            XCTFail("Failed to validate: \(result)")
            return
        }

        XCTAssertEqual(policyFailures.count, 1)
    }

    func testNotYetValidIntermediateIsRejected() async throws {
        let roots = CertificateStore([TestPKI.unconstrainedCA])
        let leaf = TestPKI.issueLeaf(
            notValidBefore: TestPKI.unconstrainedIntermediate.notValidBefore - 2.0,  // Earlier than the intermediate
            notValidAfter: TestPKI.unconstrainedIntermediate.notValidAfter,
            issuer: .unconstrainedIntermediate
        )

        var verifier = Verifier(
            rootCertificates: roots,
            policy: PolicySet(policies: [RFC5280Policy(validationTime: TestPKI.unconstrainedIntermediate.notValidBefore - 1.0)])
        )
        let result = await verifier.validate(leafCertificate: leaf, intermediates: CertificateStore([TestPKI.unconstrainedIntermediate]))

        guard case .couldNotValidate(let policyFailures) = result else {
            XCTFail("Failed to validate: \(result)")
            return
        }

        XCTAssertEqual(policyFailures.count, 1)
    }

    func testNotYetValidRootIsRejected() async throws {
        let roots = CertificateStore([TestPKI.unconstrainedCA])
        let leaf = TestPKI.issueLeaf(
            notValidBefore: TestPKI.unconstrainedCA.notValidBefore - 2.0,  // Earlier than the root
            notValidAfter: TestPKI.startDate,
            issuer: .unconstrainedRoot  // Issue off the root directly to avoid the intermediate getting involved.
        )

        var verifier = Verifier(
            rootCertificates: roots,
            policy: PolicySet(policies: [RFC5280Policy(validationTime: TestPKI.unconstrainedCA.notValidBefore - 1.0)])
        )
        let result = await verifier.validate(leafCertificate: leaf, intermediates: CertificateStore([TestPKI.unconstrainedIntermediate]))

        guard case .couldNotValidate(let policyFailures) = result else {
            XCTFail("Failed to validate: \(result)")
            return
        }

        XCTAssertEqual(policyFailures.count, 1)
    }

    func testMalformedExpiryIsRejected() async throws {
        let roots = CertificateStore([TestPKI.unconstrainedCA])
        let leaf = TestPKI.issueLeaf(
            notValidBefore: TestPKI.startDate + 3.0,
            notValidAfter: TestPKI.startDate + 2.0,  // invalid order
            issuer: .unconstrainedIntermediate
        )

        var verifier = Verifier(
            rootCertificates: roots, policy: PolicySet(policies: [RFC5280Policy(validationTime: TestPKI.startDate + 2.5)])
        )
        let result = await verifier.validate(leafCertificate: leaf, intermediates: CertificateStore([TestPKI.unconstrainedIntermediate]))

        guard case .couldNotValidate(let policyFailures) = result else {
            XCTFail("Failed to validate: \(result)")
            return
        }

        XCTAssertEqual(policyFailures.count, 1)
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

    static let unconstrainedIntermediateKey = P256.Signing.PrivateKey()
    static let unconstrainedIntermediateName = try! DistinguishedName {
        CountryName("US")
        OrganizationName("Apple")
        CommonName("Swift Certificate Test Intermediate 1")
    }
    static let unconstrainedIntermediate: Certificate = {
        return try! Certificate(
            version: .v3,
            serialNumber: .init(),
            publicKey: .init(unconstrainedIntermediateKey.publicKey),
            notValidBefore: startDate - .days(365),
            notValidAfter: startDate + .days(365),
            issuer: unconstrainedCAName,
            subject: unconstrainedIntermediateName,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: Certificate.Extensions {
                Critical(
                    BasicConstraints.isCertificateAuthority(maxPathLength: 0)
                )
            },
            issuerPrivateKey: .init(unconstrainedCAPrivateKey)
        )
    }()

    enum Issuer {
        case unconstrainedRoot
        case unconstrainedIntermediate

        var name: DistinguishedName {
            switch self {
            case .unconstrainedRoot:
                return unconstrainedCAName
            case .unconstrainedIntermediate:
                return unconstrainedIntermediateName
            }
        }

        var key: Certificate.PrivateKey {
            switch self {
            case .unconstrainedRoot:
                return .init(unconstrainedCAPrivateKey)
            case .unconstrainedIntermediate:
                return .init(unconstrainedIntermediateKey)
            }
        }
    }

    static func issueLeaf(
        commonName: String = "Leaf",
        notValidBefore: Date = Self.startDate,
        notValidAfter: Date = Self.startDate + .days(365),
        issuer: Issuer
    ) -> Certificate {
        let leafKey = P256.Signing.PrivateKey()
        let name = try! DistinguishedName {
            CountryName("US")
            OrganizationName("Apple")
            CommonName(commonName)
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
            extensions: Certificate.Extensions {
                Critical(
                    BasicConstraints.notCertificateAuthority
                )
            },
            issuerPrivateKey: issuer.key
        )
    }
}
