//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCertificates open source project
//
// Copyright (c) 2022 Apple Inc. and the SwiftCertificates project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCertificates project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCrypto open source project
//
// Copyright (c) 2021 Apple Inc. and the SwiftCrypto project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.md for the list of SwiftCrypto project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//
import XCTest

@testable import SwiftASN1
@testable import X509

final class OCSPTests: XCTestCase {
    private func assertRoundTrips<ASN1Object: DERParseable & DERSerializable & Equatable>(_ value: ASN1Object) throws {
        var serializer = DER.Serializer()
        try serializer.serialize(value)
        let parsed = try ASN1Object(derEncoded: serializer.serializedBytes)
        XCTAssertEqual(parsed, value)
    }

    func testRequestRoundtrip() throws {
        let ocspRequest = OCSPRequest(
            tbsRequest: OCSPTBSRequest(
                version: .v1,
                requestorName: GeneralName.dnsName("swift.org"),
                requestList: [
                    OCSPSingleRequest(
                        certID: OCSPCertID(
                            hashAlgorithm: .ecdsaWithSHA256,
                            issuerNameHash: .init(contentBytes: [0, 1, 2, 3, 4, 5, 6, 7, 8]),
                            issuerKeyHash: .init(contentBytes: [10, 11, 12, 13, 14, 15, 16, 17, 18]),
                            serialNumber: .init(bytes: [20, 21, 22, 23, 24, 25, 26, 27, 28])
                        ),
                        singleRequestExtensions: nil
                    )
                ],
                requestExtensions: nil
            ),
            signature: OCSPSignature(
                algorithmIIdentifier: .p256PublicKey,
                signature: .init(bytes: [31, 32, 33, 34, 35, 36, 37, 38]),
                certs: nil
            )
        )

        try assertRoundTrips(ocspRequest)
    }

    func testResponderIDByNameRoundTrips() throws {
        let id = ResponderID.byName(
            try DistinguishedName {
                CommonName("Responder")
            }
        )

        try self.assertRoundTrips(id)
    }

    func testResponderIDByKeyIDRoundTrips() throws {
        let id = ResponderID.byKey(
            ASN1OctetString(contentBytes: [1, 2, 3, 4])
        )

        try self.assertRoundTrips(id)
    }

    func testResponderIDByNameSerialization() throws {
        let id = ResponderID.byName(
            try DistinguishedName {
                CommonName("Responder")
            }
        )

        let expected: [UInt8] = [
            161, 22, 48, 20, 49, 18, 48, 16, 6, 3, 85, 4, 3, 12, 9, 82, 101, 115, 112, 111, 110, 100, 101, 114,
        ]

        var serializer = DER.Serializer()
        try serializer.serialize(id)
        XCTAssertEqual(serializer.serializedBytes, expected)
    }

    func testResponderIDByKeySerialization() throws {
        let id = ResponderID.byKey(
            ASN1OctetString(contentBytes: [1, 2, 3, 4])
        )

        let expected: [UInt8] = [162, 6, 4, 4, 1, 2, 3, 4]

        var serializer = DER.Serializer()
        try serializer.serialize(id)
        XCTAssertEqual(serializer.serializedBytes, expected)
    }

    func testCertIDRoundTrips() throws {
        let certID = OCSPCertID(
            hashAlgorithm: .p256PublicKey,
            issuerNameHash: ASN1OctetString(contentBytes: [1, 2, 3, 4]),
            issuerKeyHash: ASN1OctetString(contentBytes: [5, 6, 7, 8]),
            serialNumber: .init()
        )

        try self.assertRoundTrips(certID)
    }

    func testOCSPCertIDSerialization() throws {
        let certID = OCSPCertID(
            hashAlgorithm: .p256PublicKey,
            issuerNameHash: ASN1OctetString(contentBytes: [1, 2, 3, 4]),
            issuerKeyHash: ASN1OctetString(contentBytes: [5, 6, 7, 8]),
            serialNumber: .init(bytes: [9, 10, 11, 12])
        )

        let expected: [UInt8] = [
            48, 39, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134,
            72, 206, 61, 3, 1, 7, 4, 4, 1, 2, 3, 4, 4, 4, 5, 6, 7, 8, 2, 4,
            9, 10, 11, 12,
        ]

        var serializer = DER.Serializer()
        try serializer.serialize(certID)
        XCTAssertEqual(serializer.serializedBytes, expected)
    }

    func testCRLReasonRoundTrips() throws {
        let fixtures: [CRLReason] = [
            .unspecified,
            .keyCompromise,
            .caCompromise,
            .affiliationChanged,
            .superseded,
            .cessationOfOperation,
            .certificateHold,
            .removeFromCRL,
            .privilegeWithdrawn,
            .aaCompromise,
        ]

        for fixture in fixtures {
            try self.assertRoundTrips(fixture)
        }
    }

    func testCRLReasonSerialization() throws {
        let fixtures: [(CRLReason, Int)] = [
            (.unspecified, 0),
            (.keyCompromise, 1),
            (.caCompromise, 2),
            (.affiliationChanged, 3),
            (.superseded, 4),
            (.cessationOfOperation, 5),
            (.certificateHold, 6),
            (.removeFromCRL, 8),
            (.privilegeWithdrawn, 9),
            (.aaCompromise, 10),
        ]

        for (fixture, expectedPayload) in fixtures {
            var serializer = DER.Serializer()
            try serializer.serialize(fixture)

            var expected = [UInt8]()
            expected.writeIdentifier(ASN1Identifier.enumerated, constructed: false)
            expected.append(1)
            expected.append(UInt8(expectedPayload))
            XCTAssertEqual(serializer.serializedBytes, expected)
        }
    }

    func testOCSPRevokedInfoRoundTrips() throws {
        var revokedInfo = OCSPRevokedInfo(
            revocationTime: try .init(
                year: 2021,
                month: 01,
                day: 02,
                hours: 03,
                minutes: 04,
                seconds: 05,
                fractionalSeconds: 0.06
            ),
            revocationReason: nil
        )
        try self.assertRoundTrips(revokedInfo)

        revokedInfo.revocationReason = .caCompromise
        try self.assertRoundTrips(revokedInfo)
    }

    func testOCSPRevokedInfoSerializesWithoutReason() throws {
        let revokedInfo = OCSPRevokedInfo(
            revocationTime: try .init(
                year: 2021,
                month: 01,
                day: 02,
                hours: 03,
                minutes: 04,
                seconds: 05,
                fractionalSeconds: 0.06
            ),
            revocationReason: nil
        )
        let expected: [UInt8] = [
            48, 20, 24, 18, 50, 48, 50, 49, 48, 49, 48, 50, 48, 51, 48, 52, 48, 53, 46, 48, 54, 90,
        ]

        var serializer = DER.Serializer()
        try serializer.serialize(revokedInfo)
        XCTAssertEqual(serializer.serializedBytes, expected)
    }

    func testOCSPRevokedInfoSerializesWithReason() throws {
        let revokedInfo = OCSPRevokedInfo(
            revocationTime: try .init(
                year: 2021,
                month: 01,
                day: 02,
                hours: 03,
                minutes: 04,
                seconds: 05,
                fractionalSeconds: 0.06
            ),
            revocationReason: .cessationOfOperation
        )
        let expected: [UInt8] = [
            48, 25, 24, 18, 50, 48, 50, 49, 48, 49, 48, 50, 48, 51, 48, 52, 48, 53, 46, 48, 54, 90, 160, 3, 10, 1, 5,
        ]

        var serializer = DER.Serializer()
        try serializer.serialize(revokedInfo)
        XCTAssertEqual(serializer.serializedBytes, expected)
    }

    func testOCSPCertStatusRoundTrips() throws {
        let fixtures: [OCSPCertStatus] = [
            .good,
            .revoked(
                OCSPRevokedInfo(
                    revocationTime: try .init(
                        year: 2021,
                        month: 01,
                        day: 02,
                        hours: 03,
                        minutes: 04,
                        seconds: 05,
                        fractionalSeconds: 0.06
                    ),
                    revocationReason: .cessationOfOperation
                )
            ),
            .unknown,
        ]

        for fixture in fixtures {
            try self.assertRoundTrips(fixture)
        }
    }

    func testOCSPCertStatusGoodSerializes() throws {
        let value = OCSPCertStatus.good
        let expected: [UInt8] = [128, 0]

        var serializer = DER.Serializer()
        try serializer.serialize(value)
        XCTAssertEqual(serializer.serializedBytes, expected)
    }

    func testOCSPCertStatusRevokedSerializes() throws {
        let value = OCSPCertStatus.revoked(
            OCSPRevokedInfo(
                revocationTime: try .init(
                    year: 2021,
                    month: 01,
                    day: 02,
                    hours: 03,
                    minutes: 04,
                    seconds: 05,
                    fractionalSeconds: 0.06
                ),
                revocationReason: .cessationOfOperation
            )
        )
        let expected: [UInt8] = [
            161, 25, 24, 18, 50, 48, 50, 49, 48, 49, 48, 50, 48, 51, 48, 52, 48, 53, 46, 48, 54, 90, 160, 3, 10, 1, 5,
        ]

        var serializer = DER.Serializer()
        try serializer.serialize(value)
        XCTAssertEqual(serializer.serializedBytes, expected)
    }

    func testOCSPCertStatusUnknownSerializes() throws {
        let value = OCSPCertStatus.unknown
        let expected: [UInt8] = [130, 0]

        var serializer = DER.Serializer()
        try serializer.serialize(value)
        XCTAssertEqual(serializer.serializedBytes, expected)
    }

    func testOCSPSingleResponseRoundTrips() throws {
        let fixtures: [OCSPSingleResponse] = [
            .init(
                certID: OCSPCertID(
                    hashAlgorithm: .p256PublicKey,
                    issuerNameHash: ASN1OctetString(contentBytes: [1, 2, 3, 4]),
                    issuerKeyHash: ASN1OctetString(contentBytes: [5, 6, 7, 8]),
                    serialNumber: .init(bytes: [9, 10, 11, 12])
                ),
                certStatus: .good,
                thisUpdate: try .init(
                    year: 1,
                    month: 2,
                    day: 3,
                    hours: 4,
                    minutes: 5,
                    seconds: 6,
                    fractionalSeconds: 0.7
                ),
                nextUpdate: nil,
                extensions: nil
            ),
            .init(
                certID: OCSPCertID(
                    hashAlgorithm: .p256PublicKey,
                    issuerNameHash: ASN1OctetString(contentBytes: [1, 2, 3, 4]),
                    issuerKeyHash: ASN1OctetString(contentBytes: [5, 6, 7, 8]),
                    serialNumber: .init(bytes: [9, 10, 11, 12])
                ),
                certStatus: .good,
                thisUpdate: try .init(
                    year: 1,
                    month: 2,
                    day: 3,
                    hours: 4,
                    minutes: 5,
                    seconds: 6,
                    fractionalSeconds: 0.7
                ),
                nextUpdate: try .init(
                    year: 8,
                    month: 9,
                    day: 10,
                    hours: 11,
                    minutes: 12,
                    seconds: 13,
                    fractionalSeconds: 0.14
                ),
                extensions: nil
            ),
            .init(
                certID: OCSPCertID(
                    hashAlgorithm: .p256PublicKey,
                    issuerNameHash: ASN1OctetString(contentBytes: [1, 2, 3, 4]),
                    issuerKeyHash: ASN1OctetString(contentBytes: [5, 6, 7, 8]),
                    serialNumber: .init(bytes: [9, 10, 11, 12])
                ),
                certStatus: .good,
                thisUpdate: try .init(
                    year: 1,
                    month: 2,
                    day: 3,
                    hours: 4,
                    minutes: 5,
                    seconds: 6,
                    fractionalSeconds: 0.7
                ),
                nextUpdate: nil,
                extensions: try .init {
                    OCSPNonce()
                }
            ),
            .init(
                certID: OCSPCertID(
                    hashAlgorithm: .p256PublicKey,
                    issuerNameHash: ASN1OctetString(contentBytes: [1, 2, 3, 4]),
                    issuerKeyHash: ASN1OctetString(contentBytes: [5, 6, 7, 8]),
                    serialNumber: .init(bytes: [9, 10, 11, 12])
                ),
                certStatus: .good,
                thisUpdate: try .init(
                    year: 1,
                    month: 2,
                    day: 3,
                    hours: 4,
                    minutes: 5,
                    seconds: 6,
                    fractionalSeconds: 0.7
                ),
                nextUpdate: try .init(
                    year: 8,
                    month: 9,
                    day: 10,
                    hours: 11,
                    minutes: 12,
                    seconds: 13,
                    fractionalSeconds: 0.14
                ),
                extensions: try .init {
                    OCSPNonce()
                }
            ),
        ]

        for fixture in fixtures {
            try self.assertRoundTrips(fixture)
        }
    }

    func testOCSPResponseDataRoundTrips() throws {
        let responderID = ResponderID.byName(
            try DistinguishedName {
                CommonName("Responder")
            }
        )

        let response = OCSPSingleResponse(
            certID: OCSPCertID(
                hashAlgorithm: .p256PublicKey,
                issuerNameHash: ASN1OctetString(contentBytes: [1, 2, 3, 4]),
                issuerKeyHash: ASN1OctetString(contentBytes: [5, 6, 7, 8]),
                serialNumber: .init(bytes: [9, 10, 11, 12])
            ),
            certStatus: .good,
            thisUpdate: try .init(year: 1, month: 2, day: 3, hours: 4, minutes: 5, seconds: 6, fractionalSeconds: 0.7),
            nextUpdate: try .init(
                year: 8,
                month: 9,
                day: 10,
                hours: 11,
                minutes: 12,
                seconds: 13,
                fractionalSeconds: 0.14
            ),
            extensions: try .init {
                OCSPNonce()
            }
        )

        let extensions = try Certificate.Extensions {
            Certificate.Extension(oid: [1, 2, 3, 4], critical: true, value: [5, 6, 7, 8])
            Certificate.Extension(oid: [2, 10, 11, 12], critical: false, value: [13, 14, 15, 16])
        }

        let fixtures: [OCSPResponseData] = [
            .init(
                responderID: responderID,
                producedAt: try .init(
                    year: 1,
                    month: 2,
                    day: 3,
                    hours: 4,
                    minutes: 5,
                    seconds: 6,
                    fractionalSeconds: 0.7
                ),
                responses: [response, response, response],
                responseExtensions: nil
            ),
            .init(
                version: .v1,
                responderID: responderID,
                producedAt: try .init(
                    year: 1,
                    month: 2,
                    day: 3,
                    hours: 4,
                    minutes: 5,
                    seconds: 6,
                    fractionalSeconds: 0.7
                ),
                responses: [response, response, response],
                responseExtensions: nil
            ),
            .init(
                responderID: responderID,
                producedAt: try .init(
                    year: 1,
                    month: 2,
                    day: 3,
                    hours: 4,
                    minutes: 5,
                    seconds: 6,
                    fractionalSeconds: 0.7
                ),
                responses: [response, response, response],
                responseExtensions: extensions
            ),
            .init(
                version: .v1,
                responderID: responderID,
                producedAt: try .init(
                    year: 1,
                    month: 2,
                    day: 3,
                    hours: 4,
                    minutes: 5,
                    seconds: 6,
                    fractionalSeconds: 0.7
                ),
                responses: [response, response, response],
                responseExtensions: extensions
            ),
        ]

        for fixture in fixtures {
            try self.assertRoundTrips(fixture)
        }
    }

    func testBasicOCSPResponseRoundTrips() throws {
        let responderID = ResponderID.byName(
            try DistinguishedName {
                CommonName("Responder")
            }
        )

        let response = OCSPSingleResponse(
            certID: OCSPCertID(
                hashAlgorithm: .p256PublicKey,
                issuerNameHash: ASN1OctetString(contentBytes: [1, 2, 3, 4]),
                issuerKeyHash: ASN1OctetString(contentBytes: [5, 6, 7, 8]),
                serialNumber: .init(bytes: [9, 10, 11, 12])
            ),
            certStatus: .good,
            thisUpdate: try .init(year: 1, month: 2, day: 3, hours: 4, minutes: 5, seconds: 6, fractionalSeconds: 0.7),
            nextUpdate: try .init(
                year: 8,
                month: 9,
                day: 10,
                hours: 11,
                minutes: 12,
                seconds: 13,
                fractionalSeconds: 0.14
            ),
            extensions: try .init {
                Certificate.Extension(oid: [1, 2, 3, 4], critical: true, value: [5, 6, 7, 8])
            }
        )

        let extensions = try Certificate.Extensions {
            Certificate.Extension(oid: [1, 2, 3, 4], critical: true, value: [5, 6, 7, 8])
            Certificate.Extension(oid: [2, 10, 11, 12], critical: false, value: [13, 14, 15, 16])
        }

        let responseData = OCSPResponseData(
            responderID: responderID,
            producedAt: try .init(year: 1, month: 2, day: 3, hours: 4, minutes: 5, seconds: 6, fractionalSeconds: 0.7),
            responses: [response, response, response],
            responseExtensions: extensions
        )

        // This is massive, so we don't have more than one fixture. Takes a lot of space to even write it down!
        let basicResponse = try BasicOCSPResponse(
            responseData: responseData,
            signatureAlgorithm: .p256PublicKey,
            signature: ASN1BitString(bytes: [1, 2, 3, 4]),
            certs: nil
        )
        try self.assertRoundTrips(basicResponse)
    }

    func testOCSPResponseBytesRoundTrips() throws {
        let bytes = OCSPResponseBytes(
            responseType: .OCSP.basicResponse,
            response: ASN1OctetString(contentBytes: [1, 2, 3, 4])
        )
        try self.assertRoundTrips(bytes)
    }

    func testOCSPResponseBytesFromBasicResponse() throws {
        let responderID = ResponderID.byName(
            try DistinguishedName {
                CommonName("Responder")
            }
        )

        let response = OCSPSingleResponse(
            certID: OCSPCertID(
                hashAlgorithm: .p256PublicKey,
                issuerNameHash: ASN1OctetString(contentBytes: [1, 2, 3, 4]),
                issuerKeyHash: ASN1OctetString(contentBytes: [5, 6, 7, 8]),
                serialNumber: .init(bytes: [9, 10, 11, 12])
            ),
            certStatus: .good,
            thisUpdate: try .init(year: 1, month: 2, day: 3, hours: 4, minutes: 5, seconds: 6, fractionalSeconds: 0.7),
            nextUpdate: try .init(
                year: 8,
                month: 9,
                day: 10,
                hours: 11,
                minutes: 12,
                seconds: 13,
                fractionalSeconds: 0.14
            ),
            extensions: try .init {
                Certificate.Extension(oid: [1, 2, 3, 4], critical: true, value: [5, 6, 7, 8])
            }
        )

        let extensions = try Certificate.Extensions {
            Certificate.Extension(oid: [1, 2, 3, 4], critical: true, value: [5, 6, 7, 8])
            Certificate.Extension(oid: [2, 10, 11, 12], critical: false, value: [13, 14, 15, 16])
        }

        let responseData = OCSPResponseData(
            responderID: responderID,
            producedAt: try .init(year: 1, month: 2, day: 3, hours: 4, minutes: 5, seconds: 6, fractionalSeconds: 0.7),
            responses: [response, response, response],
            responseExtensions: extensions
        )

        // This is massive, so we don't have more than one fixture. Takes a lot of space to even write it down!
        let basicResponse = try BasicOCSPResponse(
            responseData: responseData,
            signatureAlgorithm: .p256PublicKey,
            signature: ASN1BitString(bytes: [1, 2, 3, 4]),
            certs: nil
        )
        let bytes = try OCSPResponseBytes(encoding: basicResponse)
        XCTAssertEqual(bytes.responseType, .OCSP.basicResponse)
        XCTAssertEqual(try BasicOCSPResponse(derEncoded: bytes.response.bytes), basicResponse)
        XCTAssertEqual(try BasicOCSPResponse(decoding: bytes), basicResponse)
        try assertRoundTrips(bytes)
    }

    func testCannotDecodeBasicOCSPResponseWithWrongOID() throws {
        let bytes = OCSPResponseBytes(
            responseType: .AlgorithmIdentifier.idEcPublicKey,
            response: ASN1OctetString(contentBytes: [1, 2, 3, 4])
        )
        XCTAssertThrowsError(try BasicOCSPResponse(decoding: bytes))
    }

    func testOCSPResponseStatusRoundTrips() throws {
        let fixtures: [OCSPResponseStatus] = [
            .successful,
            .malformedRequest,
            .internalError,
            .tryLater,
            .sigRequired,
            .unauthorized,
        ]

        for fixture in fixtures {
            try self.assertRoundTrips(fixture)
        }
    }

    func testOCSPResponseStatusRefusesToDeserializeOutOfBandValues() throws {
        var serializer = DER.Serializer()
        try serializer.serialize(Int(4))

        XCTAssertThrowsError(try OCSPResponseStatus(derEncoded: serializer.serializedBytes))
    }

    func testOCSPResponse() throws {
        let fixtures: [OCSPResponse] = [
            .malformedRequest,
            .sigRequired,
            .tryLater,
            .internalError,
            .unauthorized,
            .successful(
                try .init(
                    responseData: .init(
                        responderID: .byName(
                            try DistinguishedName {
                                CommonName("Responder")
                            }
                        ),
                        producedAt: .init(Date()),
                        responses: []
                    ),
                    signatureAlgorithm: .p384PublicKey,
                    signature: ASN1BitString(bytes: [1, 2, 3, 4]),
                    certs: nil
                )
            ),
        ]

        for fixture in fixtures {
            try self.assertRoundTrips(fixture)
        }
    }

}
