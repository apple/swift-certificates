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

private struct Policy: VerifierPolicy {
    var result: PolicyEvaluationResult = .meetsPolicy
    var verifyingCriticalExtensions: [ASN1ObjectIdentifier] = []

    mutating func chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain) async -> PolicyEvaluationResult {
        result
    }
}

final class PolicyBuilderTests: XCTestCase {
    func testVerifyingCriticalExtensions_empty() {
        XCTAssertEqual(
            Set(
                AnyPolicy {

                }.verifyingCriticalExtensions
            ),
            []
        )
    }

    func testVerifyingCriticalExtensions_concatenation() {
        XCTAssertEqual(
            Set(
                AnyPolicy {
                    Policy(verifyingCriticalExtensions: [[1, 1]])
                }.verifyingCriticalExtensions
            ),
            [
                [1, 1]
            ]
        )

        XCTAssertEqual(
            Set(
                AnyPolicy {
                    Policy(verifyingCriticalExtensions: [[1, 1]])
                    Policy(verifyingCriticalExtensions: [[1, 2]])
                }.verifyingCriticalExtensions
            ),
            [
                [1, 1],
                [1, 2],
            ]
        )

        XCTAssertEqual(
            Set(
                AnyPolicy {
                    Policy(verifyingCriticalExtensions: [[1, 1]])
                    Policy(verifyingCriticalExtensions: [[1, 2]])
                    Policy(verifyingCriticalExtensions: [[1, 3]])
                }.verifyingCriticalExtensions
            ),
            [
                [1, 1],
                [1, 2],
                [1, 3],
            ]
        )
    }

    func testVerifyingCriticalExtensions_if() {
        let `true` = true
        let `false` = false
        XCTAssertEqual(
            Set(
                AnyPolicy {
                    if `true` {
                        Policy(verifyingCriticalExtensions: [[1, 1]])
                    }
                }.verifyingCriticalExtensions
            ),
            [
                [1, 1]
            ]
        )

        XCTAssertEqual(
            Set(
                AnyPolicy {
                    if `false` {
                        Policy(verifyingCriticalExtensions: [[1, 1]])
                    }
                }.verifyingCriticalExtensions
            ),
            []
        )
    }

    func testVerifyingCriticalExtensions_ifElse() {
        let `true` = true
        let `false` = false
        XCTAssertEqual(
            Set(
                AnyPolicy {
                    if `true` {
                        Policy(verifyingCriticalExtensions: [[1, 1]])
                    } else {
                        Policy(verifyingCriticalExtensions: [[1, 2]])
                    }
                }.verifyingCriticalExtensions
            ),
            [
                [1, 1]
            ]
        )

        XCTAssertEqual(
            Set(
                AnyPolicy {
                    if `false` {
                        Policy(verifyingCriticalExtensions: [[1, 1]])
                    } else {
                        Policy(verifyingCriticalExtensions: [[1, 2]])
                    }
                }.verifyingCriticalExtensions
            ),
            [
                [1, 2]
            ]
        )
    }

    func testVerifyingCriticalExtensions_oneOf() {
        // When both policies specify the same exts, then the overall policy also has those exts
        XCTAssertEqual(
            Set(
                OneOfPolicies {
                    Policy(verifyingCriticalExtensions: [[1, 1]])
                    Policy(verifyingCriticalExtensions: [[1, 1]])
                }.verifyingCriticalExtensions
            ),
            [
                [1, 1]
            ]
        )
        // When both policies specify the different exts, the overall has the intersection
        XCTAssertEqual(
            Set(
                OneOfPolicies {
                    Policy(verifyingCriticalExtensions: [[1, 1], [1, 2]])
                    Policy(verifyingCriticalExtensions: [[1, 2], [1, 3]])
                }.verifyingCriticalExtensions
            ),
            [
                [1, 2]
            ]
        )
        // Here the sets are disjoint so the overall is empty
        XCTAssertEqual(
            Set(
                OneOfPolicies {
                    Policy(verifyingCriticalExtensions: [[1, 1], [1, 2]])
                    Policy(verifyingCriticalExtensions: [[1, 3], [1, 4]])
                }.verifyingCriticalExtensions
            ),
            []
        )
    }

    func testVerifyingCriticalExtensions_oneOf_allOf() {
        // All of means we get all the exts
        XCTAssertEqual(
            Set(
                OneOfPolicies {
                    AllOfPolicies {
                        Policy(verifyingCriticalExtensions: [[1, 1]])
                        Policy(verifyingCriticalExtensions: [[1, 2]])
                    }
                }.verifyingCriticalExtensions
            ),
            [
                [1, 1], [1, 2],
            ]
        )
        XCTAssertEqual(
            Set(
                OneOfPolicies {
                    Policy(verifyingCriticalExtensions: [[1, 1]])
                    AllOfPolicies {
                        Policy(verifyingCriticalExtensions: [[1, 1]])
                        Policy(verifyingCriticalExtensions: [[1, 2]])
                    }
                }.verifyingCriticalExtensions
            ),
            [
                [1, 1]
            ]
        )
        XCTAssertEqual(
            Set(
                OneOfPolicies {
                    Policy(verifyingCriticalExtensions: [[1, 1]])
                    AllOfPolicies {
                        Policy(verifyingCriticalExtensions: [[1, 2]])
                        Policy(verifyingCriticalExtensions: [[1, 3]])
                    }
                }.verifyingCriticalExtensions
            ),
            []
        )
    }

    private static let privateKey = P384.Signing.PrivateKey()

    private static let certificate = try! Certificate(
        version: .v3,
        serialNumber: .init(),
        publicKey: .init(privateKey.publicKey),
        notValidBefore: Date() - .days(356),
        notValidAfter: Date() + .days(356),
        issuer: try! DistinguishedName {
            CountryName("US")
            OrganizationName("Apple")
            CommonName("Swift Certificate Test CA 1")
        },
        subject: try! DistinguishedName {
            CountryName("US")
            OrganizationName("Apple")
            CommonName("Swift Certificate Test CA 1")
        },
        signatureAlgorithm: .ecdsaWithSHA384,
        extensions: .init(),
        issuerPrivateKey: .init(privateKey)
    )

    private let chain = UnverifiedCertificateChain([
        certificate
    ])

    private func assertMeetsPolicy(
        @PolicyBuilder makePolicy: () throws -> some VerifierPolicy,
        chain: UnverifiedCertificateChain? = nil,
        file: StaticString = #filePath,
        line: UInt = #line
    ) async rethrows {
        var policy = try makePolicy()
        let result = await policy.chainMeetsPolicyRequirements(chain: chain ?? self.chain)
        guard case .meetsPolicy = result else {
            XCTFail("\(result)", file: file, line: line)
            return
        }
    }

    private func assertFailsToMeetPolicy(
        @PolicyBuilder makePolicy: () throws -> some VerifierPolicy,
        chain: UnverifiedCertificateChain? = nil,
        file: StaticString = #filePath,
        line: UInt = #line
    ) async rethrows {
        var policy = try makePolicy()
        let result = await policy.chainMeetsPolicyRequirements(chain: chain ?? self.chain)
        guard case .failsToMeetPolicy = result else {
            XCTFail("\(result)", file: file, line: line)
            return
        }
    }

    func testChainMeetsPolicyRequirements_empty() async {
        await assertMeetsPolicy {

        }
    }

    func testChainMeetsPolicyRequirements_concatenation() async {
        await assertMeetsPolicy {
            Policy(result: .meetsPolicy)
        }

        await assertMeetsPolicy {
            Policy(result: .meetsPolicy)
            Policy(result: .meetsPolicy)
        }

        await assertMeetsPolicy {
            Policy(result: .meetsPolicy)
            Policy(result: .meetsPolicy)
            Policy(result: .meetsPolicy)
        }

        await assertFailsToMeetPolicy {
            Policy(result: .failsToMeetPolicy(reason: ""))
        }

        await assertFailsToMeetPolicy {
            Policy(result: .meetsPolicy)
            Policy(result: .failsToMeetPolicy(reason: ""))
        }

        await assertFailsToMeetPolicy {
            Policy(result: .failsToMeetPolicy(reason: ""))
            Policy(result: .meetsPolicy)
        }

        await assertFailsToMeetPolicy {
            Policy(result: .meetsPolicy)
            Policy(result: .meetsPolicy)
            Policy(result: .failsToMeetPolicy(reason: ""))
        }
    }

    func testChainMeetsPolicyRequirements_if() async {
        let `true` = true
        let `false` = false
        await assertMeetsPolicy {
            if `true` {
                Policy(result: .meetsPolicy)
            }
        }

        await assertMeetsPolicy {
            if `false` {
                Policy(result: .meetsPolicy)
            }
        }

        await assertFailsToMeetPolicy {
            if `true` {
                Policy(result: .failsToMeetPolicy(reason: ""))
            }
        }

        await assertMeetsPolicy {
            if `false` {
                Policy(result: .failsToMeetPolicy(reason: ""))
            }
        }
    }

    func testChainMeetsPolicyRequirements_ifElse() async {
        let `true` = true
        let `false` = false
        await assertMeetsPolicy {
            if `true` {
                Policy(result: .meetsPolicy)
            } else {
                Policy(result: .meetsPolicy)
            }
        }

        await assertMeetsPolicy {
            if `false` {
                Policy(result: .meetsPolicy)
            } else {
                Policy(result: .meetsPolicy)
            }
        }

        await assertFailsToMeetPolicy {
            if `true` {
                Policy(result: .failsToMeetPolicy(reason: ""))
            } else {
                Policy(result: .meetsPolicy)
            }
        }

        await assertMeetsPolicy {
            if `false` {
                Policy(result: .failsToMeetPolicy(reason: ""))
            } else {
                Policy(result: .meetsPolicy)
            }
        }

        await assertMeetsPolicy {
            if `true` {
                Policy(result: .meetsPolicy)
            } else {
                Policy(result: .failsToMeetPolicy(reason: ""))
            }
        }

        await assertFailsToMeetPolicy {
            if `false` {
                Policy(result: .meetsPolicy)
            } else {
                Policy(result: .failsToMeetPolicy(reason: ""))
            }
        }
    }

    func testAnyPolicyTypeIsPreserved() {
        // tested at compile time
        let _: Verifier<AnyPolicy> = Verifier(rootCertificates: CertificateStore()) {
            AnyPolicy {
                RFC5280Policy()
            }
        }
    }

    func testChainFailsPolicy_OneOf_empty() async {
        await assertFailsToMeetPolicy {
            OneOfPolicies {}
        }
        let `false` = false
        // This is effectively empty because the branch is never true
        await assertFailsToMeetPolicy {
            OneOfPolicies {
                if `false` {
                    Policy(result: .meetsPolicy)
                }
            }
        }

        let policy: Policy? = nil
        // This is effectively empty because the optional is always nil
        await assertFailsToMeetPolicy {
            OneOfPolicies {
                if let policy {
                    policy
                }
            }
        }
    }

    func testChainMeetsPolicy_OneOf_concatenation_both_valid() async {
        await assertMeetsPolicy {
            OneOfPolicies {
                Policy(result: .meetsPolicy)
                Policy(result: .meetsPolicy)
            }
        }
    }

    func testChainMeetsPolicy_OneOf_concatenation_first_valid() async {
        await assertMeetsPolicy {
            OneOfPolicies {
                Policy(result: .meetsPolicy)
                Policy(result: .failsToMeetPolicy(reason: ""))
            }
        }
    }

    func testChainMeetsPolicy_OneOf_concatenation_second_valid() async {
        await assertMeetsPolicy {
            OneOfPolicies {
                Policy(result: .failsToMeetPolicy(reason: ""))
                Policy(result: .meetsPolicy)
            }
        }
    }

    func testChainFailsToMeetPolicy_OneOf_concatenation_both_invalid() async {
        await assertFailsToMeetPolicy {
            OneOfPolicies {
                Policy(result: .failsToMeetPolicy(reason: ""))
                Policy(result: .failsToMeetPolicy(reason: ""))
            }
        }
    }

    func testChainMeetsPolicyRequirements_oneOf_ifElse() async {
        let `true` = true
        let `false` = false
        await assertMeetsPolicy {
            OneOfPolicies {
                Policy(result: .failsToMeetPolicy(reason: ""))
                if `true` {
                    Policy(result: .meetsPolicy)
                } else {
                    Policy(result: .failsToMeetPolicy(reason: ""))
                }
            }
        }

        await assertMeetsPolicy {
            OneOfPolicies {
                Policy(result: .failsToMeetPolicy(reason: ""))
                if `false` {
                    Policy(result: .failsToMeetPolicy(reason: ""))
                } else {
                    Policy(result: .meetsPolicy)
                }
            }
        }

        await assertFailsToMeetPolicy {
            OneOfPolicies {
                Policy(result: .failsToMeetPolicy(reason: ""))
                if `true` {
                    Policy(result: .failsToMeetPolicy(reason: ""))
                } else {
                    Policy(result: .meetsPolicy)
                }
            }
        }
    }

    func testChainMeetsPolicyRequirements_oneOf_optional() async {
        let meeting: Policy? = Policy(result: .meetsPolicy)
        let failing: Policy? = Policy(result: .failsToMeetPolicy(reason: ""))
        await assertMeetsPolicy {
            OneOfPolicies {
                if let meeting {
                    meeting
                }
            }
        }
        await assertFailsToMeetPolicy {
            OneOfPolicies {
                if let failing {
                    failing
                }
            }
        }
    }

    func testChainMeetsPolicy_allOf() async {
        await assertMeetsPolicy {
            AllOfPolicies {
                Policy(result: .meetsPolicy)
                Policy(result: .meetsPolicy)
            }
        }
        await assertFailsToMeetPolicy {
            AllOfPolicies {
                Policy(result: .meetsPolicy)
                Policy(result: .failsToMeetPolicy(reason: ""))
            }
        }
    }

    func testChainMeetsPolicy_allOf_oneOf() async {
        await assertMeetsPolicy {
            OneOfPolicies {
                AllOfPolicies {
                    Policy(result: .meetsPolicy)
                }
            }
        }
        await assertFailsToMeetPolicy {
            OneOfPolicies {
                AllOfPolicies {
                    Policy(result: .failsToMeetPolicy(reason: ""))
                }
            }
        }
        await assertMeetsPolicy {
            OneOfPolicies {
                Policy(result: .meetsPolicy)
                Policy(result: .failsToMeetPolicy(reason: ""))
                AllOfPolicies {
                    Policy(result: .meetsPolicy)
                    Policy(result: .meetsPolicy)
                }
            }
        }
        await assertFailsToMeetPolicy {
            OneOfPolicies {
                Policy(result: .failsToMeetPolicy(reason: ""))
                AllOfPolicies {
                    Policy(result: .meetsPolicy)
                    Policy(result: .failsToMeetPolicy(reason: ""))
                }
            }
        }
    }

    func testAllOfPoliciesThrowing() {
        // Creating a AllOfPolicies which throws an error inside will itself throw
        struct TestError: Error {}
        func throwingPolicyBuilder() throws -> Policy {
            throw TestError()
        }

        XCTAssertThrowsError(
            try AllOfPolicies {
                try throwingPolicyBuilder()
            }
        ) { error in
            XCTAssertTrue(error is TestError)
        }
    }

    func testAllOfPoliciesNonThrowing() {
        // creating a AllOfPolicies with a non-throwing closure can't throw
        // This is tested at compile time (lack of `try` keyword)
        _ = AllOfPolicies {
            Policy(result: .meetsPolicy)
        }
    }

    func testOneOfPoliciesThrowing() {
        // Creating a OneOfPolicies which throws an error inside will itself throw
        struct TestError: Error {}
        func throwingPolicyBuilder() throws -> Policy {
            throw TestError()
        }

        XCTAssertThrowsError(
            try OneOfPolicies {
                try throwingPolicyBuilder()
            }
        ) { error in
            XCTAssertTrue(error is TestError)
        }
    }

    func testOneOfPoliciesNonThrowing() {
        // creating a OneOfPolicies with a non-throwing closure can't throw
        // This is tested at compile time (lack of `try` keyword)
        _ = OneOfPolicies {
            Policy(result: .meetsPolicy)
        }
    }
}
