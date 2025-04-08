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

/// ``OCSPTBSRequest`` is defined in ASN.1 as:
/// ```
/// TBSRequest ::= SEQUENCE {
///    version             [0] EXPLICIT Version DEFAULT v1,
///    requestorName       [1] EXPLICIT GeneralName OPTIONAL,
///    requestList             SEQUENCE OF Request,
///    requestExtensions   [2] EXPLICIT Extensions OPTIONAL }
///
/// Version ::= INTEGER { v1(0) }
/// ```
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
struct OCSPTBSRequest: DERImplicitlyTaggable, Hashable {
    static var defaultIdentifier: ASN1Identifier {
        .sequence
    }

    var version: OCSPVersion

    var requestorName: GeneralName?

    var requestList: [OCSPSingleRequest]

    var requestExtensions: Certificate.Extensions?

    init(
        version: OCSPVersion,
        requestorName: GeneralName? = nil,
        requestList: [OCSPSingleRequest],
        requestExtensions: Certificate.Extensions? = nil
    ) {
        self.version = version
        self.requestorName = requestorName
        self.requestList = requestList
        self.requestExtensions = requestExtensions
    }

    init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let version = try DER.decodeDefaultExplicitlyTagged(
                &nodes,
                tagNumber: 0,
                tagClass: .contextSpecific,
                defaultValue: Int(0)
            )
            let requestorName = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 1, tagClass: .contextSpecific) {
                try GeneralName(derEncoded: $0)
            }
            let requestList = try DER.sequence(of: OCSPSingleRequest.self, identifier: .sequence, nodes: &nodes)
            let extensions = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 2, tagClass: .contextSpecific) {
                try DER.sequence(of: Certificate.Extension.self, identifier: .sequence, rootNode: $0)
            }

            return .init(
                version: .init(rawValue: version),
                requestorName: requestorName,
                requestList: requestList,
                requestExtensions: try extensions.map { try .init($0) }
            )
        }
    }

    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            if self.version != .v1 {
                try coder.serialize(self.version.rawValue, explicitlyTaggedWithTagNumber: 0, tagClass: .contextSpecific)
            }
            if let requestorName = self.requestorName {
                try coder.serialize(requestorName, explicitlyTaggedWithTagNumber: 1, tagClass: .contextSpecific)
            }
            try coder.serializeSequenceOf(requestList)
            if let requestExtensions = self.requestExtensions {
                try coder.serialize(explicitlyTaggedWithTagNumber: 2, tagClass: .contextSpecific) { coder in
                    try coder.serializeSequenceOf(requestExtensions)
                }
            }
        }
    }
}
