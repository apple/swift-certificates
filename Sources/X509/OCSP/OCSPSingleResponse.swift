//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCertificate open source project
//
// Copyright (c) 2022 Apple Inc. and the SwiftCertificate project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.md for the list of SwiftCertificate project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import SwiftASN1

/// An OCSPSingleResponse is defined as:
///
/// ```
/// SingleResponse ::= SEQUENCE {
///    certID                       CertID,
///    certStatus                   CertStatus,
///    thisUpdate                   GeneralizedTime,
///    nextUpdate         [0]       EXPLICIT GeneralizedTime OPTIONAL,
///    singleExtensions   [1]       EXPLICIT Extensions OPTIONAL }
/// ```
///
struct OCSPSingleResponse: ASN1ImplicitlyTaggable, Hashable {
    static var defaultIdentifier: ASN1.ASN1Identifier {
        .sequence
    }

    var certID: OCSPCertID

    var certStatus: OCSPCertStatus

    var thisUpdate: ASN1.GeneralizedTime

    var nextUpdate: ASN1.GeneralizedTime?

    var extensions: [Certificate.Extension]?

    init(certID: OCSPCertID,
         certStatus: OCSPCertStatus,
         thisUpdate: ASN1.GeneralizedTime,
         nextUpdate: ASN1.GeneralizedTime?,
         extensions: [Certificate.Extension]?) {
        self.certID = certID
        self.certStatus = certStatus
        self.thisUpdate = thisUpdate
        self.nextUpdate = nextUpdate
        self.extensions = extensions
    }

    init(asn1Encoded rootNode: ASN1.ASN1Node, withIdentifier identifier: ASN1.ASN1Identifier) throws {
        self = try ASN1.sequence(rootNode, identifier: identifier) { nodes in
            let certID = try OCSPCertID(asn1Encoded: &nodes)
            let certStatus = try OCSPCertStatus(asn1Encoded: &nodes)
            let thisUpdate = try ASN1.GeneralizedTime(asn1Encoded: &nodes)
            let nextUpdate = try ASN1.optionalExplicitlyTagged(&nodes, tagNumber: 0, tagClass: .contextSpecific) { node in
                try ASN1.GeneralizedTime(asn1Encoded: node)
            }
            let extensions = try ASN1.optionalExplicitlyTagged(&nodes, tagNumber: 1, tagClass: .contextSpecific) { node in
                try ASN1.sequence(of: Certificate.Extension.self, identifier: .sequence, rootNode: node)
            }

            return .init(certID: certID,
                         certStatus: certStatus,
                         thisUpdate: thisUpdate,
                         nextUpdate: nextUpdate,
                         extensions: extensions)
        }
    }

    func serialize(into coder: inout ASN1.Serializer, withIdentifier identifier: ASN1.ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(self.certID)
            try coder.serialize(self.certStatus)
            try coder.serialize(self.thisUpdate)
            if let nextUpdate = self.nextUpdate {
                try coder.serialize(nextUpdate, explicitlyTaggedWithTagNumber: 0, tagClass: .contextSpecific)
            }
            if let extensions = self.extensions {
                try coder.serialize(explicitlyTaggedWithTagNumber: 1, tagClass: .contextSpecific) { coder in
                    try coder.appendConstructedNode(identifier: .sequence) { coder in
                        for ext in extensions {
                            try coder.serialize(ext)
                        }
                    }
                }
            }
        }
    }
}
