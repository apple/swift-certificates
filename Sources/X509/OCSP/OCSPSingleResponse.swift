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
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
struct OCSPSingleResponse: DERImplicitlyTaggable, Hashable {
    static var defaultIdentifier: ASN1Identifier {
        .sequence
    }

    var certID: OCSPCertID

    var certStatus: OCSPCertStatus

    var thisUpdate: GeneralizedTime

    var nextUpdate: GeneralizedTime?

    var extensions: Certificate.Extensions?

    init(
        certID: OCSPCertID,
        certStatus: OCSPCertStatus,
        thisUpdate: GeneralizedTime,
        nextUpdate: GeneralizedTime?,
        extensions: Certificate.Extensions? = nil
    ) {
        self.certID = certID
        self.certStatus = certStatus
        self.thisUpdate = thisUpdate
        self.nextUpdate = nextUpdate
        self.extensions = extensions
    }

    init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let certID = try OCSPCertID(derEncoded: &nodes)
            let certStatus = try OCSPCertStatus(derEncoded: &nodes)
            let thisUpdate = try GeneralizedTime(derEncoded: &nodes)
            let nextUpdate = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 0, tagClass: .contextSpecific) {
                node in
                try GeneralizedTime(derEncoded: node)
            }
            let extensions = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 1, tagClass: .contextSpecific) {
                node in
                try DER.sequence(of: Certificate.Extension.self, identifier: .sequence, rootNode: node)
            }

            return .init(
                certID: certID,
                certStatus: certStatus,
                thisUpdate: thisUpdate,
                nextUpdate: nextUpdate,
                extensions: try extensions.map { try .init($0) }
            )
        }
    }

    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
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
