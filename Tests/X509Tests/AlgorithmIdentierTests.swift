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

import XCTest
import SwiftASN1
@testable import X509

final class AlgorithmIdentifierTests: XCTestCase {

    // MARK: - Tests for hasNullOrAbsentParameters

    func testHasNullOrAbsentParametersWithAbsentParameters() throws {
        let algorithmIdentifier = AlgorithmIdentifier(
            algorithm: .AlgorithmIdentifier.sha256,
            parameters: nil
        )

        XCTAssertTrue(algorithmIdentifier.hasNullOrAbsentParameters)
    }

    func testHasNullOrAbsentParametersWithExplicitNull() throws {
        let algorithmIdentifier = AlgorithmIdentifier(
            algorithm: .AlgorithmIdentifier.sha256,
            parameters: try ASN1Any(erasing: ASN1Null())
        )

        XCTAssertTrue(algorithmIdentifier.hasNullOrAbsentParameters)
    }

    func testHasNullOrAbsentParametersWithNonNullParameters() throws {
        let algorithmIdentifier = AlgorithmIdentifier(
            algorithm: .AlgorithmIdentifier.idEcPublicKey,
            parameters: try ASN1Any(erasing: ASN1ObjectIdentifier.NamedCurves.secp256r1)
        )

        XCTAssertFalse(algorithmIdentifier.hasNullOrAbsentParameters)
    }

    func testHasNullOrAbsentParametersWithDifferentDataType() throws {
        let algorithmIdentifier = AlgorithmIdentifier(
            algorithm: .AlgorithmIdentifier.sha256,
            parameters: try ASN1Any(erasing: 7)
        )

        XCTAssertFalse(algorithmIdentifier.hasNullOrAbsentParameters)
    }

    // MARK: - Tests for isEqualWithNullAndAbsentParametersMatching

    func testIsEqualWithDifferentAlgorithms() throws {
        let algorithm1 = AlgorithmIdentifier(
            algorithm: .AlgorithmIdentifier.sha256,
            parameters: nil
        )

        let algorithm2 = AlgorithmIdentifier(
            algorithm: .AlgorithmIdentifier.sha384,
            parameters: nil
        )

        XCTAssertFalse(algorithm1.isEqualWithNullAndAbsentParametersMatching(to: algorithm2))
    }

    func testIsEqualWithSameAlgorithmAndBothAbsentParameters() throws {
        let algorithm1 = AlgorithmIdentifier(
            algorithm: .AlgorithmIdentifier.sha256,
            parameters: nil
        )

        let algorithm2 = AlgorithmIdentifier(
            algorithm: .AlgorithmIdentifier.sha256,
            parameters: nil
        )

        XCTAssertTrue(algorithm1.isEqualWithNullAndAbsentParametersMatching(to: algorithm2))
    }

    func testIsEqualWithSameAlgorithmAndBothNullParameters() throws {
        let algorithm1 = AlgorithmIdentifier(
            algorithm: .AlgorithmIdentifier.sha256,
            parameters: try ASN1Any(erasing: ASN1Null())
        )

        let algorithm2 = AlgorithmIdentifier(
            algorithm: .AlgorithmIdentifier.sha256,
            parameters: try ASN1Any(erasing: ASN1Null())
        )

        XCTAssertTrue(algorithm1.isEqualWithNullAndAbsentParametersMatching(to: algorithm2))
    }

    func testIsEqualWithSameAlgorithmMixedNullAndAbsentParameters() throws {
        let algorithmWithNil = AlgorithmIdentifier(
            algorithm: .AlgorithmIdentifier.sha256,
            parameters: nil
        )

        let algorithmWithNull = AlgorithmIdentifier(
            algorithm: .AlgorithmIdentifier.sha256,
            parameters: try ASN1Any(erasing: ASN1Null())
        )

        XCTAssertTrue(algorithmWithNil.isEqualWithNullAndAbsentParametersMatching(to: algorithmWithNull))
        XCTAssertTrue(algorithmWithNull.isEqualWithNullAndAbsentParametersMatching(to: algorithmWithNil))
    }

    func testIsEqualWithSameAlgorithmAndSameNonNullParameters() throws {
        let algorithm1 = AlgorithmIdentifier(
            algorithm: .AlgorithmIdentifier.idEcPublicKey,
            parameters: try ASN1Any(erasing: 7)
        )

        let algorithm2 = AlgorithmIdentifier(
            algorithm: .AlgorithmIdentifier.idEcPublicKey,
            parameters: try ASN1Any(erasing: 7)
        )

        XCTAssertTrue(algorithm1.isEqualWithNullAndAbsentParametersMatching(to: algorithm2))
    }

    func testIsEqualWithSameAlgorithmAndDifferentNonNullParameters() throws {
        let algorithm1 = AlgorithmIdentifier(
            algorithm: .AlgorithmIdentifier.idEcPublicKey,
            parameters: try ASN1Any(erasing: 3)
        )

        let algorithm2 = AlgorithmIdentifier(
            algorithm: .AlgorithmIdentifier.idEcPublicKey,
            parameters: try ASN1Any(erasing: 5)
        )

        XCTAssertFalse(algorithm1.isEqualWithNullAndAbsentParametersMatching(to: algorithm2))
    }

    func testIsEqualWithOneNullAndOneNonNullParameters() throws {
        let algorithmWithNull = AlgorithmIdentifier(
            algorithm: .AlgorithmIdentifier.idEcPublicKey,
            parameters: nil
        )

        let algorithmWithParams = AlgorithmIdentifier(
            algorithm: .AlgorithmIdentifier.idEcPublicKey,
            parameters: try ASN1Any(erasing: 7)
        )

        XCTAssertFalse(algorithmWithNull.isEqualWithNullAndAbsentParametersMatching(to: algorithmWithParams))
        XCTAssertFalse(algorithmWithParams.isEqualWithNullAndAbsentParametersMatching(to: algorithmWithNull))
    }

    // MARK: - Test pre-defined static algorithm identifiers for consistency

    func testRSAAlgorithmConsistency() throws {
        XCTAssertTrue(
            AlgorithmIdentifier.sha256WithRSAEncryption.isEqualWithNullAndAbsentParametersMatching(
                to: .sha256WithRSAEncryptionUsingNil
            )
        )
        XCTAssertTrue(
            AlgorithmIdentifier.sha384WithRSAEncryption.isEqualWithNullAndAbsentParametersMatching(
                to: .sha384WithRSAEncryptionUsingNil
            )
        )
        XCTAssertTrue(
            AlgorithmIdentifier.sha512WithRSAEncryption.isEqualWithNullAndAbsentParametersMatching(
                to: .sha512WithRSAEncryptionUsingNil
            )
        )
        XCTAssertTrue(
            AlgorithmIdentifier.sha1WithRSAEncryption.isEqualWithNullAndAbsentParametersMatching(
                to: .sha1WithRSAEncryptionUsingNil
            )
        )
    }

    func testHashAlgorithmConsistency() throws {
        XCTAssertTrue(AlgorithmIdentifier.sha1.isEqualWithNullAndAbsentParametersMatching(to: .sha1UsingNil))
        XCTAssertTrue(AlgorithmIdentifier.sha256.isEqualWithNullAndAbsentParametersMatching(to: .sha256UsingNil))
        XCTAssertTrue(AlgorithmIdentifier.sha384.isEqualWithNullAndAbsentParametersMatching(to: .sha384UsingNil))
        XCTAssertTrue(AlgorithmIdentifier.sha512.isEqualWithNullAndAbsentParametersMatching(to: .sha512UsingNil))
    }
}
