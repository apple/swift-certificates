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
@preconcurrency import Crypto
import SwiftASN1
@testable @_spi(FixedExpiryValidationTime) import X509
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

actor TestRequester: OCSPRequester {
    enum QueryResult {
        case success(OCSPResponse)
        case nonTerminalError(Error)
        case terminalError(Error)
    }
    private let queryClosure: @Sendable (OCSPRequest, String) async -> QueryResult
    private let file: StaticString
    private let line: UInt
    var queryCount: Int = 0

    init(
        query: @escaping @Sendable (OCSPRequest, String) async -> QueryResult,
        file: StaticString = #filePath,
        line: UInt = #line
    ) {
        self.queryClosure = query
        self.file = file
        self.line = line
    }

    func query(request requestDerEncoded: [UInt8], uri: String) async -> OCSPRequesterQueryResult {
        queryCount += 1
        let request: OCSPRequest
        do {
            request = try OCSPRequest(derEncoded: requestDerEncoded[...])
        } catch {
            XCTFail("failed to deserialise request \(error)", file: file, line: line)
            return .terminalError(error)
        }
        switch await queryClosure(request, uri) {
        case .success(let response):
            do {
                var serializer = DER.Serializer()
                try serializer.serialize(response)
                return .response(serializer.serializedBytes)
            } catch {
                XCTFail("failed to serialise response \(error)", file: file, line: line)
                return .terminalError(error)
            }
        case .nonTerminalError(let error):
            return .nonTerminalError(error)
        case .terminalError(let error):
            return .terminalError(error)
        }
    }
}

extension OCSPRequester {
    func assertNoThrow(
        file: StaticString = #filePath,
        line: UInt = #line
    ) -> some OCSPRequester {
        AssertNoThrowRequester(wrapped: self, file: file, line: line)
    }
}

extension OCSPRequester where Self == TestRequester {
    /// makes sure that the given ``query`` closure does **not** throw by failing the test if it does throw.
    static func noThrow(
        query: @escaping @Sendable (OCSPRequest, String) async throws -> OCSPResponse,
        file: StaticString = #filePath,
        line: UInt = #line
    ) -> some OCSPRequester {
        TestRequester(query: { request, url in
            do {
                return .success(try await query(request, url))
            } catch {
                return .terminalError(error)
            }
        }).assertNoThrow(file: file, line: line)
    }
}

struct AssertNoThrowRequester<Wrapped: OCSPRequester>: OCSPRequester {
    var wrapped: Wrapped
    var file: StaticString
    var line: UInt
    func query(request: [UInt8], uri: String) async -> OCSPRequesterQueryResult {
        switch await wrapped.query(request: request, uri: uri).storage {
        case .success(let bytes):
            return .response(bytes)
        case .nonTerminal(let error):
            XCTFail("test query closure throw soft failure \(error)", file: file, line: line)
            return .nonTerminalError(error)
        case .terminal(let error):
            XCTFail("test query closure throw hard failure \(error)", file: file, line: line)
            return .terminalError(error)
        }

    }
}

final class OCSPVerifierPolicyTests: XCTestCase {
    private static let ca1Name = try! DistinguishedName {
        CountryName("US")
        OrganizationName("Apple")
        CommonName("Swift Certificate Test CA 1")
    }
    private static let ca1PrivateKey = P384.Signing.PrivateKey()

    @available(macOS 11.0, iOS 14, tvOS 14, watchOS 7, macCatalyst 14, visionOS 1.0, *)
    private static func ca(ocspServer: String? = nil) -> Certificate {
        try! Certificate(
            version: .v3,
            serialNumber: .init(),
            publicKey: .init(ca1PrivateKey.publicKey),
            notValidBefore: Date() - .days(365),
            notValidAfter: Date() + .days(3650),
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
                if let ocspServer {
                    AuthorityInformationAccess([
                        AuthorityInformationAccess.AccessDescription(
                            method: .ocspServer,
                            location: GeneralName.uniformResourceIdentifier(ocspServer)
                        )
                    ])
                }
            },
            issuerPrivateKey: .init(ca1PrivateKey)
        )
    }
    @available(macOS 11.0, iOS 14, tvOS 14, watchOS 7, macCatalyst 14, visionOS 1.0, *)
    private static let ca1: Certificate = ca()

    fileprivate static let intermediatePrivateKey = P384.Signing.PrivateKey()
    private static let leafPrivateKey = P384.Signing.PrivateKey()
    private static func certificate(
        subject: DistinguishedName,
        publicKey: P384.Signing.PublicKey,
        issuer: DistinguishedName,
        issuerPrivateKey: P384.Signing.PrivateKey,
        isIntermediate: Bool,
        ocspServer: String? = nil
    ) -> Certificate {
        try! Certificate(
            version: .v3,
            serialNumber: .init(),
            publicKey: .init(publicKey),
            notValidBefore: Date() - .days(365),
            notValidAfter: Date() + .days(3650),
            issuer: issuer,
            subject: subject,
            signatureAlgorithm: .ecdsaWithSHA384,
            extensions: .init {
                if isIntermediate {
                    Critical(
                        BasicConstraints.isCertificateAuthority(maxPathLength: 0)
                    )
                }
                if let ocspServer {
                    AuthorityInformationAccess([
                        AuthorityInformationAccess.AccessDescription(
                            method: .ocspServer,
                            location: GeneralName.uniformResourceIdentifier(ocspServer)
                        )
                    ])
                }
            },
            issuerPrivateKey: .init(issuerPrivateKey)
        )
    }

    fileprivate static let intermediate1Name = try! DistinguishedName {
        CountryName("US")
        OrganizationName("Apple")
        CommonName("Swift Certificate Test Intermediate CA 1")
    }
    private static let localhostLeafName = try! DistinguishedName {
        CountryName("US")
        OrganizationName("Apple")
        CommonName("localhost")
    }

    private static func intermediate(ocspServer: String? = nil) -> Certificate {
        certificate(
            subject: intermediate1Name,
            publicKey: intermediatePrivateKey.publicKey,
            issuer: ca1Name,
            issuerPrivateKey: ca1PrivateKey,
            isIntermediate: true,
            ocspServer: ocspServer
        )
    }

    private static func leaf(ocspServer: String? = nil) -> Certificate {
        certificate(
            subject: localhostLeafName,
            publicKey: leafPrivateKey.publicKey,
            issuer: intermediate1Name,
            issuerPrivateKey: intermediatePrivateKey,
            isIntermediate: false,
            ocspServer: ocspServer
        )
    }

    private static let chainWithSingleCertWithOCSP = [
        leaf(ocspServer: responderURI),
        intermediate(),
    ]

    private static let responderURI = "http://ocsp.apple.com/path"
    fileprivate static let responderId = ResponderID.byName(
        try! DistinguishedName {
            CommonName("Swift OCSP Test Responder")
        }
    )

    private static let responderIntermediate1Name = try! DistinguishedName {
        CountryName("US")
        OrganizationName("Apple")
        CommonName("Swift Certificate Test Responder Intermediate 1")
    }
    private static let responderIntermediate1PrivateKey = P384.Signing.PrivateKey()
    @available(macOS 11.0, iOS 14, tvOS 14, watchOS 7, macCatalyst 14, visionOS 1.0, *)
    private static let invalidResponderIntermediate1 = try! Certificate(
        version: .v3,
        serialNumber: .init(),
        publicKey: .init(responderIntermediate1PrivateKey.publicKey),
        notValidBefore: Date() - .days(365),
        notValidAfter: Date() + .days(3650),
        issuer: ca1.subject,
        subject: responderIntermediate1Name,
        signatureAlgorithm: .ecdsaWithSHA384,
        extensions: Certificate.Extensions {},
        issuerPrivateKey: .init(ca1PrivateKey)
    )

    private let validationTime = Date()

    private enum ExpectedVerificationResult {
        case failsToMeetPolicy
        case meetsPolicy
    }

    private func assertChain(
        soft: ExpectedVerificationResult,
        hard: ExpectedVerificationResult,
        chain: [Certificate],
        requester: @autoclosure () -> some OCSPRequester,
        fixedValidationTime: Date? = nil,
        expectedQueryCount: Int = 1,
        file: StaticString = #filePath,
        line: UInt = #line
    ) async {
        switch soft {
        case .failsToMeetPolicy:
            await self.assertChainFailsToMeetPolicy(
                mode: .soft,
                chain: chain,
                requester: requester(),
                expectedQueryCount: expectedQueryCount,
                fixedValidationTime: fixedValidationTime,
                file: file,
                line: line
            )
        case .meetsPolicy:
            await self.assertChainMeetsPolicy(
                mode: .soft,
                chain: chain,
                requester: requester(),
                expectedQueryCount: expectedQueryCount,
                fixedValidationTime: fixedValidationTime,
                file: file,
                line: line
            )
        }

        switch hard {
        case .failsToMeetPolicy:
            await self.assertChainFailsToMeetPolicy(
                mode: .hard,
                chain: chain,
                requester: requester(),
                expectedQueryCount: expectedQueryCount,
                fixedValidationTime: fixedValidationTime,
                file: file,
                line: line
            )
        case .meetsPolicy:
            await self.assertChainMeetsPolicy(
                mode: .hard,
                chain: chain,
                requester: requester(),
                expectedQueryCount: expectedQueryCount,
                fixedValidationTime: fixedValidationTime,
                file: file,
                line: line
            )
        }
    }

    private func assertChainMeetsPolicy(
        mode: OCSPFailureMode = .hard,
        chain: [Certificate],
        requester: some OCSPRequester,
        expectedQueryCount: Int = 1,
        fixedValidationTime: Date? = nil,
        file: StaticString = #filePath,
        line: UInt = #line
    ) async {
        let result: PolicyEvaluationResult

        if let fixedValidationTime {
            var policy = OCSPVerifierPolicy(
                failureMode: mode,
                requester: requester,
                fixedExpiryValidationTime: fixedValidationTime
            )
            result = await policy.chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain(chain))
        } else {
            var policy = OCSPVerifierPolicy(failureMode: mode, requester: requester)
            result = await policy.chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain(chain))
        }

        guard case .meetsPolicy = result else {
            XCTFail("fails to validate \(result)", file: file, line: line)
            printChainForDebugging(chain)
            return
        }
        if let testRequest = requester as? TestRequester {
            let queryCount = await testRequest.queryCount
            XCTAssertEqual(queryCount, expectedQueryCount, "unexpected requester query count", file: file, line: line)
        }
    }

    private func printChainForDebugging(_ chain: [Certificate]) {
        print("chain:")
        for certificate in chain {
            print(certificate)
        }
        do {
            var serializer = DER.Serializer()
            try serializer.serializeSequenceOf(chain)
            print("base64 DER representation of chain:")
            print(Data(serializer.serializedBytes).base64EncodedString())
        } catch {
            print("failed to serialise chain \(error)")
        }
    }

    private func assertChainFailsToMeetPolicy(
        mode: OCSPFailureMode = .hard,
        chain: [Certificate],
        requester: some OCSPRequester,
        expectedQueryCount: Int = 1,
        fixedValidationTime: Date? = nil,

        file: StaticString = #filePath,
        line: UInt = #line
    ) async {
        let result: PolicyEvaluationResult

        if let fixedValidationTime {
            var policy = OCSPVerifierPolicy(
                failureMode: mode,
                requester: requester,
                fixedExpiryValidationTime: fixedValidationTime
            )
            result = await policy.chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain(chain))
        } else {
            var policy = OCSPVerifierPolicy(failureMode: mode, requester: requester)
            result = await policy.chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain(chain))
        }

        guard case .failsToMeetPolicy = result else {
            XCTFail("chain did not fail validation", file: file, line: line)
            printChainForDebugging(chain)
            return
        }
        if let testRequest = requester as? TestRequester {
            let actualQueryCount = await testRequest.queryCount
            XCTAssertEqual(
                actualQueryCount,
                expectedQueryCount,
                "unexpected requester query count",
                file: file,
                line: line
            )
        }
    }

    func testSingleCertWithOCSP() async {
        let now = self.validationTime
        await self.assertChain(
            soft: .meetsPolicy,
            hard: .meetsPolicy,
            chain: Self.chainWithSingleCertWithOCSP,
            requester: TestRequester.noThrow { [validationTime] request, uri -> OCSPResponse in
                XCTAssertEqual(uri, Self.responderURI)
                XCTAssertNil(request.signature)
                let nonce = try XCTUnwrap(request.tbsRequest.requestExtensions?.ocspNonce)
                XCTAssertEqual(request.tbsRequest.requestList.count, 1)
                let singleRequest = try XCTUnwrap(request.tbsRequest.requestList.first)
                return .successful(
                    try .signed(
                        producedAt: .init(validationTime),
                        responses: [
                            OCSPSingleResponse(
                                certID: singleRequest.certID,
                                certStatus: .good,
                                thisUpdate: .init(now - .days(1)),
                                nextUpdate: .init(now + .days(1))
                            )
                        ]
                    ) {
                        nonce
                    }
                )
            }
        )
    }

    func testWrongNonce() async {
        let now = self.validationTime
        await self.assertChain(
            soft: .meetsPolicy,
            hard: .failsToMeetPolicy,
            chain: Self.chainWithSingleCertWithOCSP,
            requester: TestRequester.noThrow { [validationTime] request, uri -> OCSPResponse in
                XCTAssertEqual(uri, Self.responderURI)
                XCTAssertNil(request.signature)
                XCTAssertNotNil(try request.tbsRequest.requestExtensions?.ocspNonce)
                XCTAssertEqual(request.tbsRequest.requestList.count, 1)
                let singleRequest = try XCTUnwrap(request.tbsRequest.requestList.first)
                return .successful(
                    try .signed(
                        producedAt: .init(validationTime),
                        responses: [
                            OCSPSingleResponse(
                                certID: singleRequest.certID,
                                certStatus: .good,
                                thisUpdate: .init(now - .days(1)),
                                nextUpdate: .init(now + .days(1))
                            )
                        ]
                    ) {
                        OCSPNonce()
                    }
                )
            }
        )
    }

    func testRevokedCert() async {
        let now = self.validationTime
        await self.assertChain(
            soft: .failsToMeetPolicy,
            hard: .failsToMeetPolicy,
            chain: Self.chainWithSingleCertWithOCSP,
            requester: TestRequester.noThrow { [validationTime] request, uri -> OCSPResponse in
                XCTAssertEqual(uri, Self.responderURI)
                XCTAssertNil(request.signature)
                let nonce = try XCTUnwrap(request.tbsRequest.requestExtensions?.ocspNonce)
                XCTAssertEqual(request.tbsRequest.requestList.count, 1)
                let singleRequest = try XCTUnwrap(request.tbsRequest.requestList.first)
                return .successful(
                    try .signed(
                        producedAt: .init(validationTime),
                        responses: [
                            OCSPSingleResponse(
                                certID: singleRequest.certID,
                                certStatus: .revoked(
                                    .init(
                                        revocationTime: .init(now),
                                        revocationReason: .unspecified
                                    )
                                ),
                                thisUpdate: .init(now - .days(1)),
                                nextUpdate: .init(now + .days(1))
                            )
                        ]
                    ) {
                        nonce
                    }
                )
            }
        )
    }

    @available(macOS 11.0, iOS 14, tvOS 14, watchOS 7, macCatalyst 14, visionOS 1.0, *)
    func testInvalidResponderCertChain() async {
        let now = self.validationTime
        await self.assertChain(
            soft: .meetsPolicy,
            hard: .failsToMeetPolicy,
            chain: Self.chainWithSingleCertWithOCSP,
            requester: TestRequester.noThrow { [validationTime] request, uri -> OCSPResponse in
                XCTAssertEqual(uri, Self.responderURI)
                XCTAssertNil(request.signature)
                let nonce = try XCTUnwrap(request.tbsRequest.requestExtensions?.ocspNonce)
                XCTAssertEqual(request.tbsRequest.requestList.count, 1)
                let singleRequest = try XCTUnwrap(request.tbsRequest.requestList.first)
                return .successful(
                    try .signed(
                        responderID: .byName(Self.invalidResponderIntermediate1.subject),
                        producedAt: .init(validationTime),
                        responses: [
                            OCSPSingleResponse(
                                certID: singleRequest.certID,
                                certStatus: .good,
                                thisUpdate: .init(now - .days(1)),
                                nextUpdate: .init(now + .days(1))
                            )
                        ],
                        privateKey: Self.responderIntermediate1PrivateKey,
                        certs: [Self.invalidResponderIntermediate1]
                    ) {
                        nonce
                    }
                )
            }
        )
    }

    func testResponderSignatureAlgorithmIdentifierMismatch() async {
        let now = self.validationTime
        await self.assertChain(
            soft: .meetsPolicy,
            hard: .failsToMeetPolicy,
            chain: Self.chainWithSingleCertWithOCSP,
            requester: TestRequester.noThrow { request, uri -> OCSPResponse in
                XCTAssertEqual(uri, Self.responderURI)
                XCTAssertNil(request.signature)
                let nonce = try XCTUnwrap(request.tbsRequest.requestExtensions?.ocspNonce)
                XCTAssertEqual(request.tbsRequest.requestList.count, 1)
                let singleRequest = try XCTUnwrap(request.tbsRequest.requestList.first)

                let responseData = OCSPResponseData(
                    version: .v1,
                    responderID: Self.responderId,
                    producedAt: .init(Date()),
                    responses: [
                        OCSPSingleResponse(
                            certID: singleRequest.certID,
                            certStatus: .good,
                            thisUpdate: .init(now - .days(1)),
                            nextUpdate: .init(now + .days(1))
                        )
                    ],
                    responseExtensions: try .init {
                        nonce
                    }
                )

                var serializer = DER.Serializer()
                try serializer.serialize(responseData)
                let tbsCertificateBytes = serializer.serializedBytes[...]

                let digest = SHA384.hash(data: tbsCertificateBytes)
                let signature = try Self.intermediatePrivateKey.signature(for: digest)

                let response = try BasicOCSPResponse(
                    responseData: responseData,
                    // signature digest was creating using SHA384 but we specify the wrong identifier SHA256
                    signatureAlgorithm: .ecdsaWithSHA256,
                    signature: .init(bytes: Array(signature.derRepresentation)[...]),
                    certs: []
                )
                return .successful(response)
            }
        )
    }

    func testResponseDoesNotIncludeResponseForRequestedCert() async {
        let now = self.validationTime
        await self.assertChain(
            soft: .meetsPolicy,
            hard: .failsToMeetPolicy,
            chain: Self.chainWithSingleCertWithOCSP,
            requester: TestRequester.noThrow { [validationTime] request, uri -> OCSPResponse in
                XCTAssertEqual(uri, Self.responderURI)
                XCTAssertNil(request.signature)
                let nonce = try XCTUnwrap(request.tbsRequest.requestExtensions?.ocspNonce)
                XCTAssertEqual(request.tbsRequest.requestList.count, 1)
                return .successful(
                    try .signed(
                        producedAt: .init(validationTime),
                        responses: [
                            OCSPSingleResponse(
                                certID: .init(
                                    hashAlgorithm: .init(algorithm: .sha1NoSign, parameters: nil),
                                    issuerNameHash: .init(contentBytes: [0, 1, 2, 3, 4][...]),
                                    issuerKeyHash: .init(contentBytes: [6, 7, 8, 9, 10][...]),
                                    serialNumber: .init()
                                ),
                                certStatus: .good,
                                thisUpdate: .init(now - .days(1)),
                                nextUpdate: .init(now + .days(1))
                            )
                        ]
                    ) {
                        nonce
                    }
                )
            }
        )
    }

    @available(macOS 11.0, iOS 14, tvOS 14, watchOS 7, macCatalyst 14, visionOS 1.0, *)
    func testShouldNotQueryResponderIfNoOCSPServerIsDefined() async {
        await self.assertChain(
            soft: .meetsPolicy,
            hard: .meetsPolicy,
            chain: [
                Self.leaf(),
                Self.intermediate(),
                Self.ca1,
            ],
            requester: TestRequester.noThrow { request, uri -> OCSPResponse in
                struct ShouldNotQueryResponderError: Error {}
                throw ShouldNotQueryResponderError()
            },
            expectedQueryCount: 0
        )
    }

    @available(macOS 11.0, iOS 14, tvOS 14, watchOS 7, macCatalyst 14, visionOS 1.0, *)
    func testLastCertificateIsNotAllowedToHaveOCSP() async {
        await self.assertChain(
            soft: .failsToMeetPolicy,
            hard: .failsToMeetPolicy,
            chain: [
                Self.leaf(),
                Self.intermediate(),
                Self.ca(ocspServer: Self.responderURI),
            ],
            requester: TestRequester.noThrow { request, uri -> OCSPResponse in
                struct ShouldNotQueryResponderError: Error {}
                throw ShouldNotQueryResponderError()
            },
            expectedQueryCount: 0
        )
    }

    func testDoesNotFailOnSoftFailure() async {
        await self.assertChain(
            soft: .meetsPolicy,
            hard: .meetsPolicy,
            chain: Self.chainWithSingleCertWithOCSP,
            requester: TestRequester { request, uri -> TestRequester.QueryResult in
                struct QueryErrorsAreAcceptable: Error {}
                return .nonTerminalError(QueryErrorsAreAcceptable())
            }
        )
    }

    func testFailsOnTerminalError() async {
        await self.assertChain(
            soft: .failsToMeetPolicy,
            hard: .failsToMeetPolicy,
            chain: Self.chainWithSingleCertWithOCSP,
            requester: TestRequester { request, uri -> TestRequester.QueryResult in
                struct QueryErrorsAreNotAcceptable: Error {}
                return .terminalError(QueryErrorsAreNotAcceptable())
            }
        )
    }

    func testTimeValidation() async {
        func responseWithCertStatusGood(
            producedAt: Date = self.validationTime,
            thisUpdate: Date,
            nextUpdate: Date?
        ) -> some OCSPRequester {
            TestRequester.noThrow { request, uri -> OCSPResponse in
                XCTAssertEqual(uri, Self.responderURI)
                XCTAssertNil(request.signature)
                let nonce = try XCTUnwrap(request.tbsRequest.requestExtensions?.ocspNonce)
                XCTAssertEqual(request.tbsRequest.requestList.count, 1)
                let singleRequest = try XCTUnwrap(request.tbsRequest.requestList.first)
                return .successful(
                    try .signed(
                        producedAt: .init(producedAt),
                        responses: [
                            OCSPSingleResponse(
                                certID: singleRequest.certID,
                                certStatus: .good,
                                thisUpdate: .init(thisUpdate),
                                nextUpdate: nextUpdate.map { .init($0) }
                            )
                        ]
                    ) {
                        nonce
                    }
                )
            }
        }

        /// produced at is in the future
        await self.assertChain(
            soft: .meetsPolicy,
            hard: .failsToMeetPolicy,
            chain: Self.chainWithSingleCertWithOCSP,
            requester: responseWithCertStatusGood(
                producedAt: self.validationTime + OCSPResponseData.defaultTrustTimeLeeway + 2,
                thisUpdate: self.validationTime,
                nextUpdate: self.validationTime + 1
            ),
            fixedValidationTime: self.validationTime
        )

        /// is almost exactly in the current time window
        await self.assertChain(
            soft: .meetsPolicy,
            hard: .meetsPolicy,
            chain: Self.chainWithSingleCertWithOCSP,
            requester: responseWithCertStatusGood(
                thisUpdate: self.validationTime,
                nextUpdate: self.validationTime + 1
            ),
            fixedValidationTime: self.validationTime
        )

        /// is almost exactly in the current time window with leeway
        await self.assertChain(
            soft: .meetsPolicy,
            hard: .meetsPolicy,
            chain: Self.chainWithSingleCertWithOCSP,
            requester: responseWithCertStatusGood(
                producedAt: self.validationTime - OCSPResponseData.defaultTrustTimeLeeway + 1,
                thisUpdate: self.validationTime - OCSPResponseData.defaultTrustTimeLeeway + 1,
                nextUpdate: self.validationTime - OCSPResponseData.defaultTrustTimeLeeway + 2
            ),
            fixedValidationTime: self.validationTime
        )

        /// no next update
        await self.assertChain(
            soft: .meetsPolicy,
            hard: .failsToMeetPolicy,
            chain: Self.chainWithSingleCertWithOCSP,
            requester: responseWithCertStatusGood(
                thisUpdate: self.validationTime,
                nextUpdate: nil
            )
        )
        /// time window is in the future
        await self.assertChain(
            soft: .meetsPolicy,
            hard: .failsToMeetPolicy,
            chain: Self.chainWithSingleCertWithOCSP,
            requester: responseWithCertStatusGood(
                producedAt: self.validationTime + OCSPResponseData.defaultTrustTimeLeeway + 1,
                thisUpdate: self.validationTime + OCSPResponseData.defaultTrustTimeLeeway + 1,
                nextUpdate: self.validationTime + OCSPResponseData.defaultTrustTimeLeeway + 2
            ),
            fixedValidationTime: self.validationTime
        )

        /// next update is in the past
        await self.assertChain(
            soft: .meetsPolicy,
            hard: .failsToMeetPolicy,
            chain: Self.chainWithSingleCertWithOCSP,
            requester: responseWithCertStatusGood(
                thisUpdate: self.validationTime - OCSPResponseData.defaultTrustTimeLeeway + 1,
                nextUpdate: self.validationTime - OCSPResponseData.defaultTrustTimeLeeway - 1
            )
        )
        /// this update and next update is in the past
        await self.assertChain(
            soft: .meetsPolicy,
            hard: .failsToMeetPolicy,
            chain: Self.chainWithSingleCertWithOCSP,
            requester: responseWithCertStatusGood(
                thisUpdate: self.validationTime - OCSPResponseData.defaultTrustTimeLeeway - 2,
                nextUpdate: self.validationTime - OCSPResponseData.defaultTrustTimeLeeway - 1
            )
        )
        /// this update, next update, and validation time is a fixed date in the future
        await self.assertChain(
            soft: .meetsPolicy,
            hard: .meetsPolicy,
            chain: Self.chainWithSingleCertWithOCSP,
            requester: responseWithCertStatusGood(
                thisUpdate: Date() + .days(10),
                nextUpdate: Date() + .days(20)
            ),
            fixedValidationTime: Date() + .days(15)
        )
    }

    func testWWWDotAppleDotComResponder() async throws {
        actor StaticOCSPRequester: OCSPRequester {
            var responses: [OCSPResponse]
            init(responses: [OCSPResponse]) {
                self.responses = responses
            }
            var nextIndex: Int = 0
            func query(request: [UInt8], uri: String) async -> OCSPRequesterQueryResult {
                let responseIndex = nextIndex
                nextIndex += 1
                guard responses.indices.contains(responseIndex) else {
                    struct StaticOCSPRequesterRunOutOfResponses: Error {}
                    return .terminalError(StaticOCSPRequesterRunOutOfResponses())
                }
                let response = responses[responseIndex]
                do {
                    return .response(try DER.Serializer.serialized(element: response))
                } catch {
                    return .terminalError(error)
                }
            }
        }

        func load(_ filePath: String, extension: String) throws -> [UInt8] {
            guard let url = Bundle.module.url(forResource: filePath, withExtension: `extension`) else {
                struct CouldNotGetURLFromBundle: Error {
                    var filePath: String
                    var `extension`: String
                }
                throw CouldNotGetURLFromBundle(filePath: filePath, extension: `extension`)
            }

            return Array(try Data(contentsOf: url))
        }
        func loadCertificate(_ filePath: String, extension: String) throws -> Certificate {
            try Certificate(derEncoded: load(filePath, extension: `extension`))
        }
        func loadOCSPResponse(_ filePath: String, extension: String) throws -> OCSPResponse {
            try OCSPResponse(derEncoded: load(filePath, extension: `extension`))
        }

        let root = try loadCertificate("www.apple.com.root", extension: "der")
        let intermediate = try loadCertificate("www.apple.com.intermediate", extension: "der")
        let leaf = try loadCertificate("www.apple.com", extension: "der")
        let ocspResponseLeaf = try loadOCSPResponse("www.apple.com.ocsp-response", extension: "der")
        let ocspResponseIntermediate = try loadOCSPResponse(
            "www.apple.com.intermediate.ocsp-response",
            extension: "der"
        )
        let timeOfOCSPRequest = try Date(
            GeneralizedTime(year: 2023, month: 3, day: 15, hours: 15, minutes: 36, seconds: 0, fractionalSeconds: 0.0)
        )

        await self.assertChain(
            soft: .meetsPolicy,
            hard: .meetsPolicy,
            chain: [leaf, intermediate, root],
            requester: StaticOCSPRequester(responses: [
                ocspResponseLeaf,
                ocspResponseIntermediate,
            ]).assertNoThrow(),
            fixedValidationTime: timeOfOCSPRequest
        )
    }
}

extension BasicOCSPResponse {
    static func signed(
        responseData: OCSPResponseData,
        privateKey: P384.Signing.PrivateKey,
        certs: [Certificate]?
    ) throws -> Self {
        var serializer = DER.Serializer()
        try serializer.serialize(responseData)
        let tbsCertificateBytes = serializer.serializedBytes[...]

        let digest = SHA384.hash(data: tbsCertificateBytes)
        let signature = try privateKey.signature(for: digest)

        return try .init(
            responseData: responseData,
            signatureAlgorithm: .ecdsaWithSHA384,
            signature: .init(bytes: Array(signature.derRepresentation)[...]),
            certs: certs
        )
    }
    static func signed(
        version: OCSPVersion = .v1,
        responderID: ResponderID = .byName(OCSPVerifierPolicyTests.intermediate1Name),
        producedAt: GeneralizedTime,
        responses: [OCSPSingleResponse],
        privateKey: P384.Signing.PrivateKey = OCSPVerifierPolicyTests.intermediatePrivateKey,
        certs: [Certificate]? = [],
        @ExtensionsBuilder responseExtensions: () throws -> Result<Certificate.Extensions, any Error> = {
            .success(Certificate.Extensions())
        }
    ) throws -> Self {
        try .signed(
            responseData: .init(
                version: version,
                responderID: responderID,
                producedAt: producedAt,
                responses: responses,
                responseExtensions: try responseExtensions().get()
            ),
            privateKey: privateKey,
            certs: certs
        )
    }

    init(
        responseData: OCSPResponseData,
        signatureAlgorithm: AlgorithmIdentifier,
        signature: ASN1BitString,
        certs: [Certificate]?
    ) throws {
        self.init(
            responseData: responseData,
            responseDataBytes: try DER.Serializer.serialized(element: responseData)[...],
            signatureAlgorithm: signatureAlgorithm,
            signature: signature,
            certs: certs
        )
    }
}
