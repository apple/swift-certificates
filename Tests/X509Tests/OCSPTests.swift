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

final class OCSPTests: XCTestCase {
    // TODO: Make these work.
    #if false
    private func assertRoundTrips<ASN1Object: DERParseable & DERSerializable & Equatable>(_ value: ASN1Object) throws {
        var serializer = DER.Serializer()
        try serializer.serialize(value)
        let parsed = try ASN1Object(derEncoded: serializer.serializedBytes)
        XCTAssertEqual(parsed, value)
    }

    func testResponderIDByNameRoundTrips() throws {
        let id = ASN1.ResponderID.byName(
            ASN1.DistinguishedName(elements: [
                RelativeDistinguishedName(elements: [
                    RFC5280AttributeTypeAndValue(type: .NameAttributes.name,
                                                      value: .utf8String(.init(contentBytes: [1, 2, 3, 4]))),
                ])
            ])
        )

        try self.assertRoundTrips(id)
    }

    func testResponderIDByKeyIDRoundTrips() throws {
        let id = ASN1.ResponderID.byKey(
            ASN1OctetString(contentBytes: [1, 2, 3, 4])
        )

        try self.assertRoundTrips(id)
    }

    func testResponderIDByNameSerialization() throws {
        let id = ASN1.ResponderID.byName(
            ASN1.DistinguishedName(elements: [
                RelativeDistinguishedName(elements: [
                    RFC5280AttributeTypeAndValue(type: .NameAttributes.name,
                                                      value: .utf8String(.init(contentBytes: [1, 2, 3, 4]))),
                ])
            ])
        )

        let expected: [UInt8] = [161, 17, 48, 15, 49, 13, 48, 11, 6, 3, 85, 4, 41, 12, 4, 1, 2, 3, 4]

        var serializer = DER.Serializer()
        try serializer.serialize(id)
        XCTAssertEqual(serializer.serializedBytes, expected)
    }

    func testResponderIDByKeySerialization() throws {
        let id = ASN1.ResponderID.byKey(
            ASN1OctetString(contentBytes: [1, 2, 3, 4])
        )

        let expected: [UInt8] = [162, 6, 4, 4, 1, 2, 3, 4]

        var serializer = DER.Serializer()
        try serializer.serialize(id)
        XCTAssertEqual(serializer.serializedBytes, expected)
    }

    func testCertIDRoundTrips() throws {
        let certID = ASN1.OCSPCertID(
            hashAlgorithm: .p256PublicKey,
            issuerNameHash: ASN1OctetString(contentBytes: [1, 2, 3, 4]),
            issuerKeyHash: ASN1OctetString(contentBytes: [5, 6, 7, 8]),
            serialNumber: [9, 10, 11, 12]
        )

        try self.assertRoundTrips(certID)
    }

    func testOCSPCertIDSerialization() throws {
        let certID = ASN1.OCSPCertID(
            hashAlgorithm: .p256PublicKey,
            issuerNameHash: ASN1OctetString(contentBytes: [1, 2, 3, 4]),
            issuerKeyHash: ASN1OctetString(contentBytes: [5, 6, 7, 8]),
            serialNumber: [9, 10, 11, 12]
        )

        let expected: [UInt8] = [
            48, 39, 48, 19, 6, 7, 42, 134, 72, 206, 61, 2, 1, 6, 8, 42, 134,
            72, 206, 61, 3, 1, 7, 4, 4, 1, 2, 3, 4, 4, 4, 5, 6, 7, 8, 2, 4,
            9, 10, 11, 12
        ]

        var serializer = DER.Serializer()
        try serializer.serialize(certID)
        XCTAssertEqual(serializer.serializedBytes, expected)
    }

    func testCRLReasonRoundTrips() throws {
        let fixtures: [ASN1.CRLReason] = [
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

    func testCRLReasionSerialization() throws {
        let fixtures: [(ASN1.CRLReason, Int)] = [
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

            var expected = Array<UInt8>()
            expected.writeIdentifier(ASN1Identifier.enumerated)
            expected.append(1)
            expected.append(UInt8(expectedPayload))
            XCTAssertEqual(serializer.serializedBytes, expected)
        }
    }

    func testOCSPRevokedInfoRoundTrips() throws {
        var revokedInfo = ASN1.OCSPRevokedInfo(
            revocationTime: try .init(year: 2021, month: 01, day: 02, hours: 03, minutes: 04, seconds: 05, fractionalSeconds: 0.06),
            revocationReason: nil
        )
        try self.assertRoundTrips(revokedInfo)

        revokedInfo.revocationReason = .caCompromise
        try self.assertRoundTrips(revokedInfo)
    }

    func testOCSPRevokedInfoSerializesWithoutReason() throws {
        let revokedInfo = ASN1.OCSPRevokedInfo(
            revocationTime: try .init(year: 2021, month: 01, day: 02, hours: 03, minutes: 04, seconds: 05, fractionalSeconds: 0.06),
            revocationReason: nil
        )
        let expected: [UInt8] = [48, 20, 24, 18, 50, 48, 50, 49, 48, 49, 48, 50, 48, 51, 48, 52, 48, 53, 46, 48, 54, 90]

        var serializer = DER.Serializer()
        try serializer.serialize(revokedInfo)
        XCTAssertEqual(serializer.serializedBytes, expected)
    }

    func testOCSPRevokedInfoSerializesWithReason() throws {
        let revokedInfo = ASN1.OCSPRevokedInfo(
            revocationTime: try .init(year: 2021, month: 01, day: 02, hours: 03, minutes: 04, seconds: 05, fractionalSeconds: 0.06),
            revocationReason: .cessationOfOperation
        )
        let expected: [UInt8] = [48, 25, 24, 18, 50, 48, 50, 49, 48, 49, 48, 50, 48, 51, 48, 52, 48, 53, 46, 48, 54, 90, 160, 3, 10, 1, 5]

        var serializer = DER.Serializer()
        try serializer.serialize(revokedInfo)
        XCTAssertEqual(serializer.serializedBytes, expected)
    }

    func testOCSPCertStatusRoundTrips() throws {
        let fixtures: [ASN1.OCSPCertStatus] = [
            .good,
            .revoked(
                ASN1.OCSPRevokedInfo(
                revocationTime: try .init(year: 2021, month: 01, day: 02, hours: 03, minutes: 04, seconds: 05, fractionalSeconds: 0.06),
                revocationReason: .cessationOfOperation)
            ),
            .unknown,
        ]

        for fixture in fixtures {
            try self.assertRoundTrips(fixture)
        }
    }

    func testOCSPCertStatusGoodSerializes() throws {
        let value = ASN1.OCSPCertStatus.good
        let expected: [UInt8] = [128, 0]

        var serializer = DER.Serializer()
        try serializer.serialize(value)
        XCTAssertEqual(serializer.serializedBytes, expected)
    }

    func testOCSPCertStatusRevokedSerializes() throws {
        let value = ASN1.OCSPCertStatus.revoked(
            ASN1.OCSPRevokedInfo(
            revocationTime: try .init(year: 2021, month: 01, day: 02, hours: 03, minutes: 04, seconds: 05, fractionalSeconds: 0.06),
            revocationReason: .cessationOfOperation)
        )
        let expected: [UInt8] = [161, 25, 24, 18, 50, 48, 50, 49, 48, 49, 48, 50, 48, 51, 48, 52, 48, 53, 46, 48, 54, 90, 160, 3, 10, 1, 5]

        var serializer = DER.Serializer()
        try serializer.serialize(value)
        XCTAssertEqual(serializer.serializedBytes, expected)
    }

    func testOCSPCertStatusUnknownSerializes() throws {
        let value = ASN1.OCSPCertStatus.unknown
        let expected: [UInt8] = [130, 0]

        var serializer = DER.Serializer()
        try serializer.serialize(value)
        XCTAssertEqual(serializer.serializedBytes, expected)
    }

    func testRFC5280ExtensionRoundTrip() throws {
        let fixtures: [ASN1.RFC5280Extension] = [
            .init(extensionID: [1, 2, 3, 4], critical: true, extensionValue: .init(contentBytes: [5, 6, 7, 8])),
            .init(extensionID: [2, 10, 11, 12], critical: false, extensionValue: .init(contentBytes: [13, 14, 15, 16])),
        ]

        for fixture in fixtures {
            try self.assertRoundTrips(fixture)
        }
    }

    func testRFC5280ExtensionEncodesCorrectly() throws {
        let fixtures: [(ASN1.RFC5280Extension, [UInt8])] = [
            (
                .init(extensionID: [1, 2, 3, 4], critical: true, extensionValue: .init(contentBytes: [5, 6, 7, 8])),
                [48, 14, 6, 3, 42, 3, 4, 1, 1, 255, 4, 4, 5, 6, 7, 8]
            ),
            (
                .init(extensionID: [2, 10, 11, 12], critical: false, extensionValue: .init(contentBytes: [13, 14, 15, 16])),
                [48, 11, 6, 3, 90, 11, 12, 4, 4, 13, 14, 15, 16]
            ),
        ]

        for (value, expected) in fixtures {
            var serializer = DER.Serializer()
            try serializer.serialize(value)
            XCTAssertEqual(serializer.serializedBytes, expected)
        }
    }

    func testRFC5280ExtensionRejectsParsingFalse() throws {
        let bytes: [UInt8] = [48, 14, 6, 3, 42, 3, 4, 1, 1, 0, 4, 4, 5, 6, 7, 8]
        XCTAssertThrowsError(try ASN1.RFC5280Extension(derEncoded: bytes))
    }

    func testOCSPSingleResponseRoundTrips() throws {
        let fixtures: [ASN1.OCSPSingleResponse] = [
            .init(
                certID: ASN1.OCSPCertID(
                    hashAlgorithm: .p256PublicKey,
                    issuerNameHash: ASN1OctetString(contentBytes: [1, 2, 3, 4]),
                    issuerKeyHash: ASN1OctetString(contentBytes: [5, 6, 7, 8]),
                    serialNumber: [9, 10, 11, 12]
                ),
                certStatus: .good,
                thisUpdate: try .init(year: 1, month: 2, day: 3, hours: 4, minutes: 5, seconds: 6, fractionalSeconds: 0.7),
                nextUpdate: nil,
                extensions: nil
            ),
            .init(
                certID: ASN1.OCSPCertID(
                    hashAlgorithm: .p256PublicKey,
                    issuerNameHash: ASN1OctetString(contentBytes: [1, 2, 3, 4]),
                    issuerKeyHash: ASN1OctetString(contentBytes: [5, 6, 7, 8]),
                    serialNumber: [9, 10, 11, 12]
                ),
                certStatus: .good,
                thisUpdate: try .init(year: 1, month: 2, day: 3, hours: 4, minutes: 5, seconds: 6, fractionalSeconds: 0.7),
                nextUpdate: try .init(year: 8, month: 9, day: 10, hours: 11, minutes: 12, seconds: 13, fractionalSeconds: 0.14),
                extensions: nil
            ),
            .init(
                certID: ASN1.OCSPCertID(
                    hashAlgorithm: .p256PublicKey,
                    issuerNameHash: ASN1OctetString(contentBytes: [1, 2, 3, 4]),
                    issuerKeyHash: ASN1OctetString(contentBytes: [5, 6, 7, 8]),
                    serialNumber: [9, 10, 11, 12]
                ),
                certStatus: .good,
                thisUpdate: try .init(year: 1, month: 2, day: 3, hours: 4, minutes: 5, seconds: 6, fractionalSeconds: 0.7),
                nextUpdate: nil,
                extensions: [.init(extensionID: [1, 2, 3, 4], critical: true, extensionValue: .init(contentBytes: [5, 6, 7, 8]))]
            ),
            .init(
                certID: ASN1.OCSPCertID(
                    hashAlgorithm: .p256PublicKey,
                    issuerNameHash: ASN1OctetString(contentBytes: [1, 2, 3, 4]),
                    issuerKeyHash: ASN1OctetString(contentBytes: [5, 6, 7, 8]),
                    serialNumber: [9, 10, 11, 12]
                ),
                certStatus: .good,
                thisUpdate: try .init(year: 1, month: 2, day: 3, hours: 4, minutes: 5, seconds: 6, fractionalSeconds: 0.7),
                nextUpdate: try .init(year: 8, month: 9, day: 10, hours: 11, minutes: 12, seconds: 13, fractionalSeconds: 0.14),
                extensions: [.init(extensionID: [1, 2, 3, 4], critical: true, extensionValue: .init(contentBytes: [5, 6, 7, 8]))]
            ),
        ]

        for fixture in fixtures {
            try self.assertRoundTrips(fixture)
        }
    }

    func testOCSPResponseDataRoundTrips() throws {
        let responderID = ASN1.ResponderID.byName(
            ASN1.DistinguishedName(elements: [
                RelativeDistinguishedName(elements: [
                    RFC5280AttributeTypeAndValue(type: .NameAttributes.name,
                                                      value: .utf8String(.init(contentBytes: [1, 2, 3, 4]))),
                ])
            ])
        )

        let response = ASN1.OCSPSingleResponse(
            certID: ASN1.OCSPCertID(
                hashAlgorithm: .p256PublicKey,
                issuerNameHash: ASN1OctetString(contentBytes: [1, 2, 3, 4]),
                issuerKeyHash: ASN1OctetString(contentBytes: [5, 6, 7, 8]),
                serialNumber: [9, 10, 11, 12]
            ),
            certStatus: .good,
            thisUpdate: try .init(year: 1, month: 2, day: 3, hours: 4, minutes: 5, seconds: 6, fractionalSeconds: 0.7),
            nextUpdate: try .init(year: 8, month: 9, day: 10, hours: 11, minutes: 12, seconds: 13, fractionalSeconds: 0.14),
            extensions: [.init(extensionID: [1, 2, 3, 4], critical: true, extensionValue: .init(contentBytes: [5, 6, 7, 8]))]
        )

        let extensions: [ASN1.RFC5280Extension] = [
            .init(extensionID: [1, 2, 3, 4], critical: true, extensionValue: .init(contentBytes: [5, 6, 7, 8])),
            .init(extensionID: [2, 10, 11, 12], critical: false, extensionValue: .init(contentBytes: [13, 14, 15, 16])),
        ]

        let fixtures: [ASN1.OCSPResponseData] = [
            .init(
                responderID: responderID,
                producedAt: try .init(year: 1, month: 2, day: 3, hours: 4, minutes: 5, seconds: 6, fractionalSeconds: 0.7),
                responses: [response, response, response],
                responseExtensions: nil
            ),
            .init(
                version: 3,
                responderID: responderID,
                producedAt: try .init(year: 1, month: 2, day: 3, hours: 4, minutes: 5, seconds: 6, fractionalSeconds: 0.7),
                responses: [response, response, response],
                responseExtensions: nil
            ),
            .init(
                responderID: responderID,
                producedAt: try .init(year: 1, month: 2, day: 3, hours: 4, minutes: 5, seconds: 6, fractionalSeconds: 0.7),
                responses: [response, response, response],
                responseExtensions: extensions
            ),
            .init(
                version: 3,
                responderID: responderID,
                producedAt: try .init(year: 1, month: 2, day: 3, hours: 4, minutes: 5, seconds: 6, fractionalSeconds: 0.7),
                responses: [response, response, response],
                responseExtensions: extensions
            ),
        ]

        for fixture in fixtures {
            try self.assertRoundTrips(fixture)
        }
    }

    func testBasicOCSPResponseRoundTrips() throws {
        let responderID = ASN1.ResponderID.byName(
            ASN1.DistinguishedName(elements: [
                RelativeDistinguishedName(elements: [
                    RFC5280AttributeTypeAndValue(type: .NameAttributes.name,
                                                      value: .utf8String(.init(contentBytes: [1, 2, 3, 4]))),
                ])
            ])
        )

        let response = ASN1.OCSPSingleResponse(
            certID: ASN1.OCSPCertID(
                hashAlgorithm: .p256PublicKey,
                issuerNameHash: ASN1OctetString(contentBytes: [1, 2, 3, 4]),
                issuerKeyHash: ASN1OctetString(contentBytes: [5, 6, 7, 8]),
                serialNumber: [9, 10, 11, 12]
            ),
            certStatus: .good,
            thisUpdate: try .init(year: 1, month: 2, day: 3, hours: 4, minutes: 5, seconds: 6, fractionalSeconds: 0.7),
            nextUpdate: try .init(year: 8, month: 9, day: 10, hours: 11, minutes: 12, seconds: 13, fractionalSeconds: 0.14),
            extensions: [.init(extensionID: [1, 2, 3, 4], critical: true, extensionValue: .init(contentBytes: [5, 6, 7, 8]))]
        )

        let extensions: [ASN1.RFC5280Extension] = [
            .init(extensionID: [1, 2, 3, 4], critical: true, extensionValue: .init(contentBytes: [5, 6, 7, 8])),
            .init(extensionID: [2, 10, 11, 12], critical: false, extensionValue: .init(contentBytes: [13, 14, 15, 16])),
        ]

        let responseData = ASN1.OCSPResponseData(
            responderID: responderID,
            producedAt: try .init(year: 1, month: 2, day: 3, hours: 4, minutes: 5, seconds: 6, fractionalSeconds: 0.7),
            responses: [response, response, response],
            responseExtensions: extensions
        )

        // This is massive, so we don't have more than one fixture. Takes a lot of space to even write it down!
        let basicResponse = ASN1.BasicOCSPResponse(
            responseData: responseData,
            signatureAlgorithm: .p256PublicKey,
            signature: ASN1BitString(bytes: [1, 2, 3, 4]))
        try self.assertRoundTrips(basicResponse)
    }

    func testOCSPResponseBytesRoundTrips() throws {
        let bytes = ASN1.OCSPResponseBytes(responseType: .OCSP.basicResponse, response: ASN1OctetString(contentBytes: [1, 2, 3, 4]))
        try self.assertRoundTrips(bytes)
    }

    func testOCSPResponseBytesFromBasicResponse() throws {
        let responderID = ASN1.ResponderID.byName(
            ASN1.DistinguishedName(elements: [
                RelativeDistinguishedName(elements: [
                    RFC5280AttributeTypeAndValue(type: .NameAttributes.name,
                                                      value: .utf8String(.init(contentBytes: [1, 2, 3, 4]))),
                ])
            ])
        )

        let response = ASN1.OCSPSingleResponse(
            certID: ASN1.OCSPCertID(
                hashAlgorithm: .p256PublicKey,
                issuerNameHash: ASN1OctetString(contentBytes: [1, 2, 3, 4]),
                issuerKeyHash: ASN1OctetString(contentBytes: [5, 6, 7, 8]),
                serialNumber: [9, 10, 11, 12]
            ),
            certStatus: .good,
            thisUpdate: try .init(year: 1, month: 2, day: 3, hours: 4, minutes: 5, seconds: 6, fractionalSeconds: 0.7),
            nextUpdate: try .init(year: 8, month: 9, day: 10, hours: 11, minutes: 12, seconds: 13, fractionalSeconds: 0.14),
            extensions: [.init(extensionID: [1, 2, 3, 4], critical: true, extensionValue: .init(contentBytes: [5, 6, 7, 8]))]
        )

        let extensions: [ASN1.RFC5280Extension] = [
            .init(extensionID: [1, 2, 3, 4], critical: true, extensionValue: .init(contentBytes: [5, 6, 7, 8])),
            .init(extensionID: [2, 10, 11, 12], critical: false, extensionValue: .init(contentBytes: [13, 14, 15, 16])),
        ]

        let responseData = ASN1.OCSPResponseData(
            responderID: responderID,
            producedAt: try .init(year: 1, month: 2, day: 3, hours: 4, minutes: 5, seconds: 6, fractionalSeconds: 0.7),
            responses: [response, response, response],
            responseExtensions: extensions
        )

        // This is massive, so we don't have more than one fixture. Takes a lot of space to even write it down!
        let basicResponse = ASN1.BasicOCSPResponse(
            responseData: responseData,
            signatureAlgorithm: .p256PublicKey,
            signature: ASN1BitString(bytes: [1, 2, 3, 4]))

        let bytes = try ASN1.OCSPResponseBytes(encoding: basicResponse)
        XCTAssertEqual(bytes.responseType, .OCSP.basicResponse)
        XCTAssertEqual(try ASN1.BasicOCSPResponse(derEncoded: bytes.response.bytes), basicResponse)
        XCTAssertEqual(try ASN1.BasicOCSPResponse(decoding: bytes), basicResponse)
        try assertRoundTrips(bytes)
    }

    func testCannotDecodeBasicOCSPResponseWithWrongOID() throws {
        let bytes = ASN1.OCSPResponseBytes(responseType: .AlgorithmIdentifier.idEcPublicKey, response: ASN1OctetString(contentBytes: [1, 2, 3, 4]))
        XCTAssertThrowsError(try ASN1.BasicOCSPResponse(decoding: bytes))
    }

    func testOCSPResponseStatusRoundTrips() throws {
        let fixtures: [ASN1.OCSPResponseStatus] = [
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

        XCTAssertThrowsError(try ASN1.OCSPResponseStatus(derEncoded: serializer.serializedBytes))
    }

    func testOCSPResponse() throws {
        let fixtures: [ASN1.OCSPResponse] = [
            .init(responseStatus: .successful, responseBytes: nil),
            .init(responseStatus: .malformedRequest, responseBytes: nil),
            .init(responseStatus: .successful, responseBytes: ASN1.OCSPResponseBytes(responseType: .AlgorithmIdentifier.idEcPublicKey, response: ASN1OctetString(contentBytes: [1, 2, 3, 4]))),
        ]

        for fixture in fixtures {
            try self.assertRoundTrips(fixture)
        }
    }
    #endif
}
