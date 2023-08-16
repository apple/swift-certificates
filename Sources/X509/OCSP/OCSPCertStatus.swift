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

/// A CertID is defined as:
///
/// ```
/// CertStatus ::= CHOICE {
///     good        [0]     IMPLICIT NULL,
///     revoked     [1]     IMPLICIT RevokedInfo,
///     unknown     [2]     IMPLICIT UnknownInfo }
///
/// RevokedInfo ::= SEQUENCE {
///     revocationTime              GeneralizedTime,
///     revocationReason    [0]     EXPLICIT CRLReason OPTIONAL }
///
/// UnknownInfo ::= NULL
///
/// CRLReason ::= ENUMERATED {
///      unspecified             (0),
///      keyCompromise           (1),
///      cACompromise            (2),
///      affiliationChanged      (3),
///      superseded              (4),
///      cessationOfOperation    (5),
///      certificateHold         (6),
///           -- value 7 is not used
///      removeFromCRL           (8),
///      privilegeWithdrawn      (9),
///      aACompromise           (10) }
/// ```
///
enum OCSPCertStatus: DERParseable, DERSerializable, Hashable {
    case good
    case revoked(OCSPRevokedInfo)
    case unknown

    private static let goodIdentifier = ASN1Identifier(tagWithNumber: 0, tagClass: .contextSpecific)
    private static let revokedIdentifier = ASN1Identifier(tagWithNumber: 1, tagClass: .contextSpecific)
    private static let unknownIdentifier = ASN1Identifier(tagWithNumber: 2, tagClass: .contextSpecific)

    init(derEncoded node: ASN1Node) throws {
        switch node.identifier {
        case OCSPCertStatus.goodIdentifier:
            _ = try ASN1Null(derEncoded: node, withIdentifier: OCSPCertStatus.goodIdentifier)
            self = .good

        case OCSPCertStatus.revokedIdentifier:
            self = try .revoked(.init(derEncoded: node, withIdentifier: OCSPCertStatus.revokedIdentifier))

        case OCSPCertStatus.unknownIdentifier:
            _ = try ASN1Null(derEncoded: node, withIdentifier: OCSPCertStatus.unknownIdentifier)
            self = .unknown

        default:
            throw ASN1Error.unexpectedFieldType(node.identifier)
        }
    }

    func serialize(into coder: inout DER.Serializer) throws {
        switch self {
        case .good:
            ASN1Null().serialize(into: &coder, withIdentifier: OCSPCertStatus.goodIdentifier)

        case .revoked(let revokedInfo):
            try revokedInfo.serialize(into: &coder, withIdentifier: OCSPCertStatus.revokedIdentifier)

        case .unknown:
            ASN1Null().serialize(into: &coder, withIdentifier: OCSPCertStatus.unknownIdentifier)
        }
    }
}

struct OCSPRevokedInfo: DERImplicitlyTaggable, Hashable {
    static var defaultIdentifier: ASN1Identifier {
        .sequence
    }

    var revocationTime: GeneralizedTime

    var revocationReason: CRLReason?

    init(revocationTime: GeneralizedTime, revocationReason: CRLReason?) {
        self.revocationTime = revocationTime
        self.revocationReason = revocationReason
    }

    init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let revocationTime = try GeneralizedTime(derEncoded: &nodes)
            let revocationReason = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 0, tagClass: .contextSpecific) {
                node in
                try CRLReason(derEncoded: node)
            }

            return .init(revocationTime: revocationTime, revocationReason: revocationReason)
        }
    }

    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(self.revocationTime)

            if let revocationReason = self.revocationReason {
                try coder.serialize(revocationReason, explicitlyTaggedWithTagNumber: 0, tagClass: .contextSpecific)
            }
        }
    }
}

struct CRLReason: DERImplicitlyTaggable, Hashable, RawRepresentable {
    static var defaultIdentifier: ASN1Identifier {
        .enumerated
    }

    var rawValue: Int

    init(rawValue: Int) {
        self.rawValue = rawValue
    }

    init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self.rawValue = try .init(derEncoded: rootNode, withIdentifier: identifier)
    }

    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try self.rawValue.serialize(into: &coder, withIdentifier: identifier)
    }

    static let unspecified = CRLReason(rawValue: 0)
    static let keyCompromise = CRLReason(rawValue: 1)
    static let caCompromise = CRLReason(rawValue: 2)
    static let affiliationChanged = CRLReason(rawValue: 3)
    static let superseded = CRLReason(rawValue: 4)
    static let cessationOfOperation = CRLReason(rawValue: 5)
    static let certificateHold = CRLReason(rawValue: 6)
    static let removeFromCRL = CRLReason(rawValue: 8)
    static let privilegeWithdrawn = CRLReason(rawValue: 9)
    static let aaCompromise = CRLReason(rawValue: 10)
}

extension CRLReason: CustomStringConvertible {
    var description: String {
        switch rawValue {
        case 0: return "unspecified"
        case 1: return "keyCompromise"
        case 2: return "caCompromise"
        case 3: return "affiliationChanged"
        case 4: return "superseded"
        case 5: return "cessationOfOperation"
        case 6: return "certificateHold"
        case 8: return "removeFromCRL"
        case 9: return "privilegeWithdrawn"
        case 10: return "aaCompromise"
        default: return "unknown reason \(rawValue)"
        }
    }
}
