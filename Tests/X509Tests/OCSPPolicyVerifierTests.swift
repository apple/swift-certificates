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
#if canImport(Darwin)
import Foundation
#else
@preconcurrency import Foundation
#endif

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
    private static let ca1Name = try! DistinguishedName {
        CountryName("US")
        OrganizationName("Apple")
        CommonName("Swift Certificate Test CA 1")
    }
    private static let ca1PrivateKey = P384.Signing.PrivateKey()
    
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
                SubjectKeyIdentifier(keyIdentifier: ArraySlice(Insecure.SHA1.hash(data: ca1PrivateKey.publicKey.derRepresentation)))
                if let ocspServer {
                    AuthorityInformationAccess([
                        AuthorityInformationAccess.AccessDescription(
                            method: .ocspServer,
                            location: GeneralName.uniformResourceIdentifier(ocspServer))
                    ])
                }
            },
            issuerPrivateKey: .init(ca1PrivateKey)
        )
    }
    private static let ca1: Certificate = ca()
    
    private static let intermediatePrivateKey = P384.Signing.PrivateKey()
    private static let leafPrivateKey = P384.Signing.PrivateKey()
    private static func certificate(
        subject: DistinguishedName,
        publicKey: P384.Signing.PublicKey,
        issuer: DistinguishedName,
        issuerPrivateKey: P384.Signing.PrivateKey,
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
                if let ocspServer {
                    AuthorityInformationAccess([
                        AuthorityInformationAccess.AccessDescription(
                            method: .ocspServer,
                            location: GeneralName.uniformResourceIdentifier(ocspServer))
                    ])
                }
            },
            issuerPrivateKey: .init(issuerPrivateKey)
        )
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
    
    private static func intermediate(ocspServer: String? = nil) -> Certificate {
        certificate(
            subject: intermediate1Name,
            publicKey: intermediatePrivateKey.publicKey,
            issuer: ca1Name,
            issuerPrivateKey: ca1PrivateKey,
            ocspServer: ocspServer
        )
    }
    
    private static func leaf(ocspServer: String? = nil) -> Certificate {
        certificate(
            subject: localhostLeafName,
            publicKey: leafPrivateKey.publicKey,
            issuer: intermediate1Name,
            issuerPrivateKey: intermediatePrivateKey,
            ocspServer: ocspServer
        )
    }
    
    private static let chainWithSingleCertWithOCSP = [
        leaf(ocspServer: responderURI),
        intermediate(),
    ]
    
    private static let responderURI = "http://ocsp.apple.com/path"
    fileprivate static let responderId = ResponderID.byName(try! DistinguishedName {
        CommonName("Swift OCSP Test Responder")
    })
    
    private let now = Date()
    private static let verifier = Verifier(rootCertificates: CertificateStore([responderCa1]), policy: PolicySet(policies: []))
    
    func assertChainMeetsPolicy(
        chain: [Certificate],
        requester: TestRequester,
        expectedQueryCount: Int = 1,
        file: StaticString = #file,
        line: UInt = #line
    ) async {
        var policy = OCSPVerifierPolicy(
            requester: requester,
            validationTime: self.now,
            verifier: Self.verifier
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
        var policy = OCSPVerifierPolicy(
            requester: requester,
            validationTime: self.now,
            verifier: Self.verifier
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
        let now = self.now
        await self.assertChainMeetsPolicy(
            chain: Self.chainWithSingleCertWithOCSP,
            requester: .noThrow { request, uri -> OCSPResponse in
                XCTAssertEqual(uri, Self.responderURI)
                XCTAssertNil(request.signature)
                let nonce = try XCTUnwrap(request.tbsRequest.requestExtensions?.ocspNonce)
                XCTAssertEqual(request.tbsRequest.requestList.count, 1)
                let singleRequest = try XCTUnwrap(request.tbsRequest.requestList.first)
                return .successful(try .signed(
                    responses: [OCSPSingleResponse(
                        certID: singleRequest.certID,
                        certStatus: .good,
                        thisUpdate: try .init(now - .days(1)),
                        nextUpdate: try .init(now + .days(1))
                    )]) {
                        nonce
                    }
                )
            }
        )
    }
    
    func testWrongNonce() async {
        let now = self.now
        await self.assertChainFailsToMeetPolicy(
            chain: Self.chainWithSingleCertWithOCSP,
            requester: .noThrow { request, uri -> OCSPResponse in
                XCTAssertEqual(uri, Self.responderURI)
                XCTAssertNil(request.signature)
                XCTAssertNotNil(try request.tbsRequest.requestExtensions?.ocspNonce)
                XCTAssertEqual(request.tbsRequest.requestList.count, 1)
                let singleRequest = try XCTUnwrap(request.tbsRequest.requestList.first)
                return .successful(try .signed(
                    responses: [OCSPSingleResponse(
                    certID: singleRequest.certID,
                    certStatus: .good,
                    thisUpdate: try .init(now - .days(1)),
                    nextUpdate: try .init(now + .days(1))
                    )]) {
                        OCSPNonce()
                    }
                )
            }
        )
    }
    
    func testRevokedCert() async {
        let now = self.now
        await self.assertChainFailsToMeetPolicy(
            chain: Self.chainWithSingleCertWithOCSP,
            requester: .noThrow { request, uri -> OCSPResponse in
                XCTAssertEqual(uri, Self.responderURI)
                XCTAssertNil(request.signature)
                let nonce = try XCTUnwrap(request.tbsRequest.requestExtensions?.ocspNonce)
                XCTAssertEqual(request.tbsRequest.requestList.count, 1)
                let singleRequest = try XCTUnwrap(request.tbsRequest.requestList.first)
                return .successful(try .signed(
                    responses: [OCSPSingleResponse(
                        certID: singleRequest.certID,
                        certStatus: .revoked(.init(
                            revocationTime: try .init(now),
                            revocationReason: .unspecified
                        )),
                        thisUpdate: try .init(now - .days(1)),
                        nextUpdate: try .init(now + .days(1))
                    )]) {
                        nonce
                    }
                )
            }
        )
    }
    
    func testInvalidResponderCertChain() async {
        let now = self.now
        await self.assertChainFailsToMeetPolicy(
            chain: Self.chainWithSingleCertWithOCSP,
            requester: .noThrow { request, uri -> OCSPResponse in
                XCTAssertEqual(uri, Self.responderURI)
                XCTAssertNil(request.signature)
                let nonce = try XCTUnwrap(request.tbsRequest.requestExtensions?.ocspNonce)
                XCTAssertEqual(request.tbsRequest.requestList.count, 1)
                let singleRequest = try XCTUnwrap(request.tbsRequest.requestList.first)
                return .successful(try .signed(
                    responses: [OCSPSingleResponse(
                        certID: singleRequest.certID,
                        certStatus: .good,
                        thisUpdate: try .init(now - .days(1)),
                        nextUpdate: try .init(now + .days(1))
                    )],
                    privateKey: responderLeaf1PrivateKey,
                    certs: [responderLeaf1]) {
                        nonce
                    }
                )
            }
        )
    }
    
    func testResponderSignatureAlgorithmIdentifierMismatch() async {
        let now = self.now
        await self.assertChainFailsToMeetPolicy(
            chain: Self.chainWithSingleCertWithOCSP,
            requester: .noThrow { request, uri -> OCSPResponse in
                XCTAssertEqual(uri, Self.responderURI)
                XCTAssertNil(request.signature)
                let nonce = try XCTUnwrap(request.tbsRequest.requestExtensions?.ocspNonce)
                XCTAssertEqual(request.tbsRequest.requestList.count, 1)
                let singleRequest = try XCTUnwrap(request.tbsRequest.requestList.first)
                
                let responseData = OCSPResponseData(
                    version: .v1,
                    responderID: Self.responderId,
                    producedAt: try .init(Date()),
                    responses: [OCSPSingleResponse(
                        certID: singleRequest.certID,
                        certStatus: .good,
                        thisUpdate: try .init(now - .days(1)),
                        nextUpdate: try .init(now + .days(1))
                    )],
                    responseExtensions: try .init {
                        nonce
                    }
                )
                
                var serializer = DER.Serializer()
                try serializer.serialize(responseData)
                let tbsCertificateBytes = serializer.serializedBytes[...]
                
                let digest = SHA384.hash(data: tbsCertificateBytes)
                let signature = try responderLeaf1PrivateKey.signature(for: digest)
                
                let response = BasicOCSPResponse(
                    responseData: responseData,
                    // signature digest was creating using SHA384 but we specify the wrong identifier SHA256
                    signatureAlgorithm: .ecdsaWithSHA256,
                    signature: .init(bytes: Array(signature.derRepresentation)[...]),
                    certs: [
                        responderLeaf1,
                        responderIntermediate1,
                    ]
                )
                return .successful(response)
            }
        )
    }
    
    func testResponseDoesNotIncludeResponseForRequestedCert() async {
        let now = self.now
        await self.assertChainFailsToMeetPolicy(
            chain: Self.chainWithSingleCertWithOCSP,
            requester: .noThrow { request, uri -> OCSPResponse in
                XCTAssertEqual(uri, Self.responderURI)
                XCTAssertNil(request.signature)
                let nonce = try XCTUnwrap(request.tbsRequest.requestExtensions?.ocspNonce)
                XCTAssertEqual(request.tbsRequest.requestList.count, 1)
                return .successful(try .signed(
                    responses: [OCSPSingleResponse(
                        certID: .init(
                            hashAlgorithm: .init(algorithm: .sha1NoSign, parameters: nil),
                            issuerNameHash: .init(contentBytes: [0, 1, 2, 3, 4][...]),
                            issuerKeyHash: .init(contentBytes: [6, 7, 8, 9, 10][...]),
                            serialNumber: .init()
                        ),
                        certStatus: .good,
                        thisUpdate: try .init(now - .days(1)),
                        nextUpdate: try .init(now + .days(1))
                    )]) {
                        nonce
                    }
                )
            }
        )
    }
    
    func testShouldNotQueryResponderIfNoOCSPServerIsDefined() async {
        await self.assertChainMeetsPolicy(chain: [
            Self.leaf(),
            Self.intermediate(),
            Self.ca1,
        ], requester: .noThrow { request, uri -> OCSPResponse in
            struct ShouldNotQueryResponderError: Error {}
            throw ShouldNotQueryResponderError()
        }, expectedQueryCount: 0)
    }
    
    func testLastCertificateIsNotAllowedToHaveOCSP() async {
        await self.assertChainFailsToMeetPolicy(chain: [
            Self.leaf(),
            Self.intermediate(),
            Self.ca(ocspServer: Self.responderURI),
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
                return .successful(try .signed(
                    responses: [OCSPSingleResponse(
                        certID: singleRequest.certID,
                        certStatus: .good,
                        thisUpdate: try .init(thisUpdate),
                        nextUpdate: try nextUpdate.map { try .init($0) }
                    )]) {
                        nonce
                    }
                )
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

private let responderCa1Name = try! DistinguishedName {
    CountryName("US")
    OrganizationName("Apple")
    CommonName("Swift Certificate Test Responder CA 1")
}
private let responderCa1PrivateKey = P384.Signing.PrivateKey()
private let responderCa1 = try! Certificate(
    version: .v3,
    serialNumber: .init(),
    publicKey: .init(responderCa1PrivateKey.publicKey),
    notValidBefore: Date() - .days(365),
    notValidAfter: Date() + .days(3650),
    issuer: responderCa1Name,
    subject: responderCa1Name,
    signatureAlgorithm: .ecdsaWithSHA384,
    extensions: Certificate.Extensions {
        Critical(
            BasicConstraints.isCertificateAuthority(maxPathLength: nil)
        )
        KeyUsage(keyCertSign: true)
        SubjectKeyIdentifier(keyIdentifier: ArraySlice(Insecure.SHA1.hash(data: responderCa1PrivateKey.publicKey.derRepresentation)))
    },
    issuerPrivateKey: .init(responderCa1PrivateKey)
)

private let responderIntermediate1Name = try! DistinguishedName {
    CountryName("US")
    OrganizationName("Apple")
    CommonName("Swift Certificate Test Responder Intermediate 1")
}
private let responderIntermediate1PrivateKey = P384.Signing.PrivateKey()
private let responderIntermediate1 = try! Certificate(
    version: .v3,
    serialNumber: .init(),
    publicKey: .init(responderIntermediate1PrivateKey.publicKey),
    notValidBefore: Date() - .days(365),
    notValidAfter: Date() + .days(3650),
    issuer: responderCa1Name,
    subject: responderIntermediate1Name,
    signatureAlgorithm: .ecdsaWithSHA384,
    extensions: Certificate.Extensions {},
    issuerPrivateKey: .init(responderCa1PrivateKey)
)

private let responderLeaf1Name = try! DistinguishedName {
    CountryName("US")
    OrganizationName("Apple")
    CommonName("Swift Certificate Test Responder Leaf 1")
}
private let responderLeaf1PrivateKey = P384.Signing.PrivateKey()
private let responderLeaf1 = try! Certificate(
    version: .v3,
    serialNumber: .init(),
    publicKey: .init(responderLeaf1PrivateKey.publicKey),
    notValidBefore: Date() - .days(365),
    notValidAfter: Date() + .days(3650),
    issuer: responderIntermediate1Name,
    subject: responderLeaf1Name,
    signatureAlgorithm: .ecdsaWithSHA384,
    extensions: Certificate.Extensions {},
    issuerPrivateKey: .init(responderIntermediate1PrivateKey)
)


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
        
        return .init(
            responseData: responseData,
            signatureAlgorithm: .ecdsaWithSHA384,
            signature: .init(bytes: Array(signature.derRepresentation)[...]),
            certs: certs
        )
    }
    static func signed(
        version: OCSPVersion = .v1,
        responderID: ResponderID = OCSPVerifierPolicyTests.responderId,
        producedAt: GeneralizedTime = try! .init(Date()),
        responses: [OCSPSingleResponse],
        privateKey: P384.Signing.PrivateKey = responderLeaf1PrivateKey,
        certs: [Certificate]? = [
            responderLeaf1,
            responderIntermediate1,
        ],
        @ExtensionsBuilder responseExtensions: () -> Certificate.Extensions = { .init() }
    ) throws -> Self {
        try .signed(
            responseData: .init(
                version: version,
                responderID: responderID,
                producedAt: producedAt,
                responses: responses,
                responseExtensions: responseExtensions()
            ),
            privateKey: privateKey,
            certs: certs
        )
    }
}
