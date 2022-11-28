//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCertificates open source project
//
// Copyright (c) 2022 Apple Inc. and the SwiftCertificates project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.md for the list of SwiftCertificates project authors
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
            throw ASN1Error.invalidASN1Object
        }
    }

    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        let integerValue: Int

        switch self {
        case .successful:
            integerValue = 0
        case .malformedRequest:
            integerValue = 1
        case .internalError:
            integerValue = 2
        case .tryLater:
            integerValue = 3
        case .sigRequired:
            integerValue = 5
        case .unauthorized:
            integerValue = 6
        }

        try integerValue.serialize(into: &coder, withIdentifier: identifier)
    }
}
