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

import SwiftASN1

/// An OCSPResponse is defined as:
///
/// ```
/// OCSPResponse ::= SEQUENCE {
///    responseStatus         OCSPResponseStatus,
///    responseBytes          [0] EXPLICIT ResponseBytes OPTIONAL }
///
/// ```
///
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
enum OCSPResponse: DERImplicitlyTaggable, Hashable {
    static var defaultIdentifier: ASN1Identifier {
        .sequence
    }

    case successful(BasicOCSPResponse)
    case malformedRequest
    case internalError
    case tryLater
    case sigRequired
    case unauthorized

    init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let responseStatus = try OCSPResponseStatus(derEncoded: &nodes)
            let responseBytes = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 0, tagClass: .contextSpecific) {
                node in
                try OCSPResponseBytes(derEncoded: node)
            }
            switch responseStatus {
            case .successful:
                guard let responseBytes,
                    responseBytes.responseType == .OCSP.basicResponse
                else {
                    throw ASN1Error.invalidASN1Object(
                        reason:
                            "Successful response does not have appropriate response bytes: \(String(describing: responseBytes))"
                    )
                }
                return .successful(try BasicOCSPResponse(derEncoded: responseBytes.response.bytes))
            case .malformedRequest:
                return try .init(unsuccessfulStatus: .malformedRequest, responseBytes: responseBytes)
            case .internalError:
                return try .init(unsuccessfulStatus: .internalError, responseBytes: responseBytes)
            case .tryLater:
                return try .init(unsuccessfulStatus: .tryLater, responseBytes: responseBytes)
            case .sigRequired:
                return try .init(unsuccessfulStatus: .sigRequired, responseBytes: responseBytes)
            case .unauthorized:
                return try .init(unsuccessfulStatus: .unauthorized, responseBytes: responseBytes)
            }
        }
    }

    private init(unsuccessfulStatus: OCSPResponse, responseBytes: OCSPResponseBytes?) throws {
        if case .successful = unsuccessfulStatus {
            preconditionFailure("this init is not allowed to be called with a successful response status")
        }
        guard responseBytes == nil else {
            throw ASN1Error.invalidASN1Object(reason: "Must not have response bytes for unsuccessful OCSP response")
        }
        self = unsuccessfulStatus
    }

    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(OCSPResponseStatus(self))
            switch self {
            case .successful(let basicResponse):
                let responseBytes = try OCSPResponseBytes(encoding: basicResponse)
                try coder.serialize(responseBytes, explicitlyTaggedWithTagNumber: 0, tagClass: .contextSpecific)

            case .malformedRequest,
                .internalError,
                .tryLater,
                .sigRequired,
                .unauthorized:
                break
            }
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension OCSPResponseStatus {
    init(_ response: OCSPResponse) {
        switch response {
        case .successful:
            self = .successful
        case .malformedRequest:
            self = .malformedRequest
        case .internalError:
            self = .internalError
        case .tryLater:
            self = .tryLater
        case .sigRequired:
            self = .sigRequired
        case .unauthorized:
            self = .unauthorized
        }
    }
}
