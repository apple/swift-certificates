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
            let responseBytes = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 0, tagClass: .contextSpecific) { node in
                try OCSPResponseBytes(derEncoded: node)
            }
            switch responseStatus {
            case .successful:
                guard let responseBytes,
                      responseBytes.responseType == .OCSP.basicResponse
                else {
                    throw ASN1Error.invalidASN1Object
                }
                return .successful(try BasicOCSPResponse(derEncoded: responseBytes.response.bytes))
            case .malformedRequest:
                guard responseBytes == nil else { throw ASN1Error.invalidASN1Object }
                return .malformedRequest
            case .internalError:
                guard responseBytes == nil else { throw ASN1Error.invalidASN1Object }
                return .internalError
            case .tryLater:
                guard responseBytes == nil else { throw ASN1Error.invalidASN1Object }
                return .tryLater
            case .sigRequired:
                guard responseBytes == nil else { throw ASN1Error.invalidASN1Object }
                return .sigRequired
            case .unauthorized:
                guard responseBytes == nil else { throw ASN1Error.invalidASN1Object }
                return .unauthorized
            }
        }
    }

    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(OCSPResponseStatus(self))
            switch self {
            case .successful(let basicResponse):
                var serializer = DER.Serializer()
                try serializer.serialize(basicResponse)
                let responseBytes = OCSPResponseBytes(responseType: .OCSP.basicResponse, response: .init(contentBytes: serializer.serializedBytes[...]))
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
