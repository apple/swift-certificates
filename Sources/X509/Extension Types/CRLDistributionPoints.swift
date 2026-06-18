//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCertificates open source project
//
// Copyright (c) 2024 Apple Inc. and the SwiftCertificates project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCertificates project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import SwiftASN1

/// Represents the CRL Distribution Points extension (RFC 5280 §4.2.1.13).
///
/// CRLDistributionPoints ::= SEQUENCE SIZE (1..MAX) OF DistributionPoint
public struct CRLDistributionPoints: Hashable, Sendable {
    public var distributionPoints: [DistributionPoint]

    public init(_ distributionPoints: [DistributionPoint]) {
        self.distributionPoints = distributionPoints
    }

    @inlinable
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    public init(_ ext: Certificate.Extension) throws {
        guard ext.oid == .X509ExtensionID.crlDistributionPoints else {
            throw CertificateError.incorrectOIDForExtension(
                reason: "Expected \(ASN1ObjectIdentifier.X509ExtensionID.crlDistributionPoints), got \(ext.oid)"
            )
        }
        let parsed = try DER.parse(Array(ext.value))
        self = try .init(derEncoded: parsed)
    }

    /// Returns all HTTP/HTTPS URIs from all distribution points.
    public var urls: [String] {
        distributionPoints.flatMap { $0.urls }
    }

    public struct DistributionPoint: Hashable, Sendable {
        public var fullNames: [GeneralName]

        public init(fullNames: [GeneralName]) {
            self.fullNames = fullNames
        }

        /// Returns all URIs from this distribution point.
        public var urls: [String] {
            fullNames.compactMap {
                if case .uniformResourceIdentifier(let uri) = $0 { return uri }
                return nil
            }
        }
    }
}

extension CRLDistributionPoints: DERParseable {
    @inlinable
    public init(derEncoded rootNode: ASN1Node) throws {
        self.distributionPoints = try DER.sequence(
            of: DistributionPoint.self,
            identifier: .sequence,
            rootNode: rootNode
        )
    }
}

extension CRLDistributionPoints.DistributionPoint: DERParseable {
    // DistributionPoint ::= SEQUENCE {
    //     distributionPoint  [0] DistributionPointName OPTIONAL,
    //     reasons            [1] ReasonFlags OPTIONAL,
    //     cRLIssuer          [2] GeneralNames OPTIONAL }
    // DistributionPointName ::= CHOICE {
    //     fullName           [0] GeneralNames,
    //     nameRelativeToCRLIssuer [1] RelativeDistinguishedName }
    @inlinable
    public init(derEncoded rootNode: ASN1Node) throws {
        self.fullNames = try DER.sequence(rootNode, identifier: .sequence) { nodes in
            // [0] distributionPoint (context-specific, constructed)
            let dpTag = ASN1Identifier(tagWithNumber: 0, tagClass: .contextSpecific)
            guard let dpNode = nodes.next(), dpNode.identifier == dpTag else {
                return [GeneralName]()
            }
            // Inside distributionPoint, [0] is fullName (GeneralNames)
            let fullNameTag = ASN1Identifier(tagWithNumber: 0, tagClass: .contextSpecific)
            guard case .constructed(let dpChildren) = dpNode.content else {
                return [GeneralName]()
            }
            var names = [GeneralName]()
            for child in dpChildren {
                if child.identifier == fullNameTag {
                    guard case .constructed(let nameNodes) = child.content else { continue }
                    for nameNode in nameNodes {
                        names.append(try GeneralName(derEncoded: nameNode))
                    }
                }
            }
            return names
        }
    }
}
