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

import XCTest
import Crypto
import SwiftASN1
@testable import X509
import Foundation

actor TestRequester: OCSPRequester {
    private let queryClosure: @Sendable (OCSPRequest, String) async throws -> OCSPResponse
    private let file: StaticString
    private let line: UInt
    var queryCount: Int = 0
    
    init(
        query: @escaping @Sendable (OCSPRequest, String) async throws -> OCSPResponse,
        file: StaticString = #file,
        line: UInt = #line
    ) {
        self.queryClosure = query
        self.file = file
        self.line = line
    }
    
    func query(request requestDerEncoded: [UInt8], uri: String) async throws -> [UInt8] {
        queryCount += 1
        let request: OCSPRequest
        do {
            request = try OCSPRequest(derEncoded: requestDerEncoded[...])
        } catch {
            XCTFail("failed to deserialise request \(error)", file: file, line: line)
            throw error
        }
        let response = try await queryClosure(request, uri)
        do {
            var serializer = DER.Serializer()
            try serializer.serialize(response)
            return serializer.serializedBytes
        } catch {
            XCTFail("failed to serialise response \(error)", file: file, line: line)
            throw error
        }
    }
}

extension TestRequester {
    /// makes sure that the given ``query`` closure does **not** throw by failing the test if it does throw.
    static func noThrow(
        query: @escaping @Sendable (OCSPRequest, String) async throws -> OCSPResponse,
        file: StaticString = #file,
        line: UInt = #line
    ) -> Self {
        .init(query: { request, uri in
            do {
                return try await query(request, uri)
            } catch {
                XCTFail("test query closure throw error \(error)", file: file, line: line)
                throw error
            }
        }, file: file, line: line)
    }
}

final class OCSPVerifierPolicyTests: XCTestCase {
    private static let privateKey = P384.Signing.PrivateKey()
    private static func certificate(
        subject: DistinguishedName,
        issuer: DistinguishedName,
        ocspServer: String? = nil
    ) -> Certificate {
        try! Certificate(
            version: .v3,
            serialNumber: .init(),
            publicKey: .init(privateKey.publicKey),
            notValidBefore: Date() - .days(365),
            notValidAfter: Date() + .days(3650),
            issuer: ca1Name,
            subject: ca1Name,
            signatureAlgorithm: .ecdsaWithSHA384,
            extensions: .init {
                if let ocspServer {
                    AuthorityInformationAccess([
                        AuthorityInformationAccess.AccessDescription(
                            method: .ocspServer,
                            location: GeneralName.uniformResourceIdentifier(ocspServer))
                    ])
                }
            },
            issuerPrivateKey: .init(privateKey)
        )
    }
    private static let ca1Name = try! DistinguishedName {
        CountryName("US")
        OrganizationName("Apple")
        CommonName("Swift Certificate Test CA 1")
    }
    private static let intermediate1Name = try! DistinguishedName {
        CountryName("US")
        OrganizationName("Apple")
        CommonName("Swift Certificate Test Intermediate CA 1")
    }
    private static let localhostLeafName = try! DistinguishedName {
        CountryName("US")
        OrganizationName("Apple")
        CommonName("localhost")
    }
    
    private static let responderURI = "http://ocsp.apple.com/path"
    fileprivate static let responderId = ResponderID.byName(try! DistinguishedName {
        CommonName("Swift OCSP Test Responder")
    })
    private static let chainWithSingleCertWithOCSP = [
        certificate(subject: localhostLeafName, issuer: intermediate1Name, ocspServer: responderURI),
        certificate(subject: intermediate1Name, issuer: intermediate1Name),
    ]
    
    private let now = Date()
    
    func assertChainMeetsPolicy(
        chain: [Certificate],
        requester: TestRequester,
        expectedQueryCount: Int = 1,
        file: StaticString = #file,
        line: UInt = #line
    ) async {
        let policy = OCSPVerifierPolicy(
            requester: requester,
            now: self.now
        )
        let result = await policy.chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain(chain))
        guard case .meetsPolicy = result else {
            XCTFail("fails to validate \(result)", file: file, line: line)
            printChainForDebugging(chain)
            return
        }
        let queryCount = await requester.queryCount
        XCTAssertEqual(queryCount, expectedQueryCount, "unexpected requester query count", file: file, line: line)
    }
    
    func printChainForDebugging(_ chain: [Certificate]) {
        dump(chain) // TODO: replace with Certificate.description once implemented
        do {
            var serializer = DER.Serializer()
            try serializer.serializeSequenceOf(chain)
            print("base64 DER representation of chain:")
            print(Data(serializer.serializedBytes).base64EncodedString())
        } catch {
            print("failed to serialise chain \(error)")
        }
    }
    
    func assertChainFailsToMeetPolicy(
        chain: [Certificate],
        requester: TestRequester,
        expectedQueryCount: Int = 1,
        expectedReason: String? = nil,
        file: StaticString = #file,
        line: UInt = #line
    ) async {
        let policy = OCSPVerifierPolicy(
            requester: requester,
            now: self.now
        )
        let result = await policy.chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain(chain))
        guard case .failsToMeetPolicy(let actualReason) = result else {
            XCTFail("chain did not fail validation", file: file, line: line)
            printChainForDebugging(chain)
            return
        }
        if let expectedReason {
            XCTAssertEqual(actualReason, expectedReason, "unexpected policy failure reason", file: file, line: line)
        }
        let actualQueryCount = await requester.queryCount
        XCTAssertEqual(actualQueryCount, expectedQueryCount, "unexpected requester query count", file: file, line: line)
    }
    
    func testSingleCertWithOCSP() async {
        await self.assertChainMeetsPolicy(
            chain: Self.chainWithSingleCertWithOCSP,
            requester: .noThrow { request, uri -> OCSPResponse in
                XCTAssertEqual(uri, Self.responderURI)
                XCTAssertNil(request.signature)
                let nonce = try XCTUnwrap(request.tbsRequest.requestExtensions?.ocspNonce)
                XCTAssertEqual(request.tbsRequest.requestList.count, 1)
                let singleRequest = try XCTUnwrap(request.tbsRequest.requestList.first)
                return .successful(.signed(responses: [OCSPSingleResponse(
                    certID: singleRequest.certID,
                    certStatus: .good,
                    thisUpdate: try .init(self.now - .days(1)),
                    nextUpdate: try .init(self.now + .days(1))
                )], responseExtensions: { nonce }))
            }
        )
    }
    
    func testWrongNonce() async {
        await self.assertChainFailsToMeetPolicy(
            chain: Self.chainWithSingleCertWithOCSP,
            requester: .noThrow { request, uri -> OCSPResponse in
                XCTAssertEqual(uri, Self.responderURI)
                XCTAssertNil(request.signature)
                XCTAssertNotNil(try request.tbsRequest.requestExtensions?.ocspNonce)
                XCTAssertEqual(request.tbsRequest.requestList.count, 1)
                let singleRequest = try XCTUnwrap(request.tbsRequest.requestList.first)
                return .successful(.signed(responses: [OCSPSingleResponse(
                    certID: singleRequest.certID,
                    certStatus: .good,
                    thisUpdate: try .init(self.now - .days(1)),
                    nextUpdate: try .init(self.now + .days(1))
                )], responseExtensions: { OCSPNonce() }))
            }
        )
    }
    
    func testRevokedCert() async {
        await self.assertChainFailsToMeetPolicy(
            chain: Self.chainWithSingleCertWithOCSP,
            requester: .noThrow { request, uri -> OCSPResponse in
                XCTAssertEqual(uri, Self.responderURI)
                XCTAssertNil(request.signature)
                let nonce = try XCTUnwrap(request.tbsRequest.requestExtensions?.ocspNonce)
                XCTAssertEqual(request.tbsRequest.requestList.count, 1)
                let singleRequest = try XCTUnwrap(request.tbsRequest.requestList.first)
                return .successful(.signed(responses: [OCSPSingleResponse(
                    certID: singleRequest.certID,
                    certStatus: .revoked(.init(
                        revocationTime: try .init(self.now),
                        revocationReason: .unspecified
                    )),
                    thisUpdate: try .init(self.now - .days(1)),
                    nextUpdate: try .init(self.now + .days(1))
                )], responseExtensions: { nonce }))
            }
        )
    }
    
    func testResponseDoesNotIncludeResponseForRequestedCert() async {
        await self.assertChainFailsToMeetPolicy(
            chain: Self.chainWithSingleCertWithOCSP,
            requester: .noThrow { request, uri -> OCSPResponse in
                XCTAssertEqual(uri, Self.responderURI)
                XCTAssertNil(request.signature)
                let nonce = try XCTUnwrap(request.tbsRequest.requestExtensions?.ocspNonce)
                XCTAssertEqual(request.tbsRequest.requestList.count, 1)
                return .successful(.signed(responses: [OCSPSingleResponse(
                    certID: .init(
                        hashAlgorithm: .init(algorithm: .sha1NoSign, parameters: nil),
                        issuerNameHash: .init(contentBytes: [0, 1, 2, 3, 4][...]),
                        issuerKeyHash: .init(contentBytes: [6, 7, 8, 9, 10][...]),
                        serialNumber: .init()
                    ),
                    certStatus: .good,
                    thisUpdate: try .init(self.now - .days(1)),
                    nextUpdate: try .init(self.now + .days(1))
                )], responseExtensions: { nonce }))
            }
        )
    }
    
    func testShouldNotQueryResponderIfNoOCSPServerIsDefined() async {
        await self.assertChainMeetsPolicy(chain: [
            Self.certificate(subject: Self.localhostLeafName, issuer: Self.intermediate1Name),
            Self.certificate(subject: Self.intermediate1Name, issuer: Self.ca1Name),
            Self.certificate(subject: Self.ca1Name, issuer: Self.ca1Name),
        ], requester: .noThrow { request, uri -> OCSPResponse in
            struct ShouldNotQueryResponderError: Error {}
            throw ShouldNotQueryResponderError()
        }, expectedQueryCount: 0)
    }
    
    func testLastCertificateIsNotAllowedToHaveOCSP() async {
        await self.assertChainFailsToMeetPolicy(chain: [
            Self.certificate(subject: Self.localhostLeafName, issuer: Self.intermediate1Name),
            Self.certificate(subject: Self.intermediate1Name, issuer: Self.ca1Name),
            Self.certificate(subject: Self.ca1Name, issuer: Self.ca1Name, ocspServer: Self.responderURI),
        ], requester: .noThrow { request, uri -> OCSPResponse in
            struct ShouldNotQueryResponderError: Error {}
            throw ShouldNotQueryResponderError()
        }, expectedQueryCount: 0)
    }
    
    func testQueryIsAllowedToFail() async {
        await self.assertChainMeetsPolicy(
            chain: Self.chainWithSingleCertWithOCSP,
            requester: .init { request, uri -> OCSPResponse in
                struct QueryErrorsAreAcceptable: Error {}
                throw QueryErrorsAreAcceptable()
            }
        )
    }
    
    func testTimeValidation() async {
        func responseWithCertStatusGood(
            thisUpdate: Date,
            nextUpdate: Date?
        ) -> TestRequester {
            .noThrow { request, uri -> OCSPResponse in
                XCTAssertEqual(uri, Self.responderURI)
                XCTAssertNil(request.signature)
                let nonce = try XCTUnwrap(request.tbsRequest.requestExtensions?.ocspNonce)
                XCTAssertEqual(request.tbsRequest.requestList.count, 1)
                let singleRequest = try XCTUnwrap(request.tbsRequest.requestList.first)
                return .successful(.signed(responses: [OCSPSingleResponse(
                    certID: singleRequest.certID,
                    certStatus: .good,
                    thisUpdate: try .init(thisUpdate),
                    nextUpdate: try nextUpdate.map { try .init($0) }
                )], responseExtensions: { nonce }))
            }
        }
        
        /// is almost exactly in the current time window
        await self.assertChainMeetsPolicy(
            chain: Self.chainWithSingleCertWithOCSP,
            requester: responseWithCertStatusGood(
                thisUpdate: self.now,
                nextUpdate: self.now + 1
            )
        )
        
        /// no next update
        await self.assertChainFailsToMeetPolicy(
            chain: Self.chainWithSingleCertWithOCSP,
            requester: responseWithCertStatusGood(
                thisUpdate: self.now,
                nextUpdate: nil
            )
        )
        /// time window is in the future
        await self.assertChainFailsToMeetPolicy(
            chain: Self.chainWithSingleCertWithOCSP,
            requester: responseWithCertStatusGood(
                thisUpdate: self.now + 1,
                nextUpdate: self.now + 2
            )
        )
        
        /// next update is in the past
        await self.assertChainFailsToMeetPolicy(
            chain: Self.chainWithSingleCertWithOCSP,
            requester: responseWithCertStatusGood(
                thisUpdate: self.now + 1,
                nextUpdate: self.now - 1
            )
        )
        /// this update and next update is in the past
        await self.assertChainFailsToMeetPolicy(
            chain: Self.chainWithSingleCertWithOCSP,
            requester: responseWithCertStatusGood(
                thisUpdate: self.now - 2,
                nextUpdate: self.now - 1
            )
        )
    }
}

extension GeneralizedTime {
    init(_ date: Date) throws {
        let components = gregorianCalendar.dateComponents(in: utcTimeZone, from: date)
        try self.init(
            year: components.year!,
            month: components.month!,
            day: components.day!,
            hours: components.hour!,
            minutes: components.minute!,
            seconds: components.second!,
            fractionalSeconds: 0.0
        )
    }
}


extension BasicOCSPResponse {
    static func signed(responseData: OCSPResponseData) -> Self {
        // TODO: actually sign the response once we validate the signature
        .init(
            responseData: responseData,
            signatureAlgorithm: .ecdsaWithSHA256,
            signature: .init(bytes: [][...])
        )
    }
    static func signed(
        version: OCSPVersion = .v1,
        responderID: ResponderID = OCSPVerifierPolicyTests.responderId,
        producedAt: GeneralizedTime = try! .init(Date()),
        responses: [OCSPSingleResponse],
        @ExtensionsBuilder responseExtensions: () -> Certificate.Extensions = { .init() }
    ) -> Self {
        .signed(responseData: .init(
            version: version,
            responderID: responderID,
            producedAt: producedAt,
            responses: responses,
            responseExtensions: responseExtensions()
        ))
    }
}
