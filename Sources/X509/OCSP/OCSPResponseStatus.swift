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

/// A OCSPResponseStatus is defined as:
///
/// ```
/// OCSPResponseStatus ::= ENUMERATED {
///     successful            (0),  -- Response has valid confirmations
///     malformedRequest      (1),  -- Illegal confirmation request
///     internalError         (2),  -- Internal error in issuer
///     tryLater              (3),  -- Try again later
///                                 -- (4) is not used
///     sigRequired           (5),  -- Must sign the request
///     unauthorized          (6)   -- Request unauthorized
/// }

/// ```
///
enum OCSPResponseStatus: DERImplicitlyTaggable, Hashable {
    static var defaultIdentifier: ASN1Identifier {
        .enumerated
    }

    case successful
    case malformedRequest
    case internalError
    case tryLater
    case sigRequired
    case unauthorized

    init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        let rawValue = try Int(derEncoded: rootNode, withIdentifier: identifier)

        switch rawValue {
        case 0:
            self = .successful
        case 1:
            self = .malformedRequest
        case 2:
            self = .internalError
        case 3:
            self = .tryLater
        case 5:
            self = .sigRequired
        case 6:
            self = .unauthorized
        default:
            throw ASN1Error.invalidASN1Object(reason: "Unexpected OCSP response status: \(rawValue)")
        }
    }

    var integerValue: Int {
        switch self {
        case .successful: return 0
        case .malformedRequest: return 1
        case .internalError: return 2
        case .tryLater: return 3
        case .sigRequired: return 5
        case .unauthorized: return 6
        }
    }

    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try self.integerValue.serialize(into: &coder, withIdentifier: identifier)
    }
}

extension OCSPResponseStatus: CustomStringConvertible {
    var description: String {
        switch self {
        case .successful: return "successful"
        case .malformedRequest: return "malformedRequest"
        case .internalError: return "internalError"
        case .tryLater: return "tryLater"
        case .sigRequired: return "sigRequired"
        case .unauthorized: return "unauthorized"
        }
    }
}
