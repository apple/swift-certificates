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
import Crypto
import SwiftASN1
@testable import X509

final class DigestsTests: XCTestCase {
    private static let message: [UInt8] = Array("The quick brown fox jumps over the lazy dog".utf8)

    func testComputeDigestSHA256MatchesCrypto() throws {
        let algorithm = try AlgorithmIdentifier(digestAlgorithmFor: .ecdsaWithSHA256)
        let digest = try Digest.computeDigest(for: Self.message, using: algorithm)
        XCTAssertEqual(Array(digest), Array(SHA256.hash(data: Self.message)))
    }

    func testComputeDigestSHA384MatchesCrypto() throws {
        let algorithm = try AlgorithmIdentifier(digestAlgorithmFor: .ecdsaWithSHA384)
        let digest = try Digest.computeDigest(for: Self.message, using: algorithm)
        XCTAssertEqual(Array(digest), Array(SHA384.hash(data: Self.message)))
    }

    func testComputeDigestSHA512MatchesCrypto() throws {
        let algorithm = try AlgorithmIdentifier(digestAlgorithmFor: .ecdsaWithSHA512)
        let digest = try Digest.computeDigest(for: Self.message, using: algorithm)
        XCTAssertEqual(Array(digest), Array(SHA512.hash(data: Self.message)))
    }

    func testComputeDigestSHA1MatchesCrypto() throws {
        let algorithm = try AlgorithmIdentifier(digestAlgorithmFor: .sha1WithRSAEncryption)
        let digest = try Digest.computeDigest(for: Self.message, using: algorithm)
        XCTAssertEqual(Array(digest), Array(Insecure.SHA1.hash(data: Self.message)))
    }

    func testComputeDigestRejectsNonDigestAlgorithm() throws {
        // `rsaKey` is a key algorithm, not a digest algorithm, so it must be rejected.
        XCTAssertThrowsError(try Digest.computeDigest(for: Self.message, using: .rsaKey)) { error in
            guard let error = error as? CertificateError else {
                XCTFail("Unexpected error: \(error)")
                return
            }
            XCTAssertEqual(error.code, .unsupportedDigestAlgorithm)
        }
    }

    func testDigestSequenceIsStable() throws {
        // Iterating the digest twice must yield the same bytes each time.
        let algorithm = try AlgorithmIdentifier(digestAlgorithmFor: .ecdsaWithSHA256)
        let digest = try Digest.computeDigest(for: Self.message, using: algorithm)
        XCTAssertEqual(Array(digest), Array(digest))
    }
}
