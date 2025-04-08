//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCertificates open source project
//
// Copyright (c) 2023 Apple Inc. and the SwiftCertificates project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCertificates project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import SwiftASN1

extension ASN1ObjectIdentifier {
    /// Cryptographic Message Syntax (CMS) Data.
    ///
    /// ASN.1 definition:
    /// ```
    /// id-data OBJECT IDENTIFIER ::= { iso(1) member-body(2)
    ///    us(840) rsadsi(113549) pkcs(1) pkcs7(7) 1 }
    /// ```
    @usableFromInline
    static let cmsData: ASN1ObjectIdentifier = [1, 2, 840, 113549, 1, 7, 1]

    /// Cryptographic Message Syntax (CMS) Signed Data.
    ///
    /// ASN.1 definition:
    /// ```
    /// id-signedData OBJECT IDENTIFIER ::= { iso(1) member-body(2)
    ///    us(840) rsadsi(113549) pkcs(1) pkcs7(7) 2 }
    /// ```
    @usableFromInline
    static let cmsSignedData: ASN1ObjectIdentifier = [1, 2, 840, 113549, 1, 7, 2]
}

/// ``ContentInfo`` is defined in ASN.1 as:
/// ```
/// ContentInfo ::= SEQUENCE {
///   contentType ContentType,
///   content [0] EXPLICIT ANY DEFINED BY contentType }
/// ContentType ::= OBJECT IDENTIFIER
/// ```
@usableFromInline
struct CMSContentInfo: DERImplicitlyTaggable, BERImplicitlyTaggable, Hashable, Sendable {
    @inlinable
    static var defaultIdentifier: ASN1Identifier {
        .sequence
    }

    @usableFromInline
    var contentType: ASN1ObjectIdentifier

    @usableFromInline
    var content: ASN1Any

    @inlinable
    init(contentType: ASN1ObjectIdentifier, content: ASN1Any) {
        self.contentType = contentType
        self.content = content
    }

    @inlinable
    init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let contentType = try ASN1ObjectIdentifier(derEncoded: &nodes)

            let content = try DER.explicitlyTagged(&nodes, tagNumber: 0, tagClass: .contextSpecific) { node in
                ASN1Any(derEncoded: node)
            }
            return .init(contentType: contentType, content: content)
        }
    }

    @inlinable
    init(berEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try BER.sequence(rootNode, identifier: identifier) { nodes in
            let contentType = try ASN1ObjectIdentifier(derEncoded: &nodes)

            let content = try BER.explicitlyTagged(&nodes, tagNumber: 0, tagClass: .contextSpecific) { node in
                ASN1Any(berEncoded: node)
            }
            return .init(contentType: contentType, content: content)
        }
    }

    @inlinable
    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(contentType)
            try coder.serialize(explicitlyTaggedWithTagNumber: 0, tagClass: .contextSpecific) { coder in
                try coder.serialize(content)
            }
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension CMSContentInfo {
    @inlinable
    init(_ signedData: CMSSignedData) throws {
        self.contentType = .cmsSignedData
        self.content = try ASN1Any(erasing: signedData)
    }

    @inlinable
    var signedData: CMSSignedData? {
        get throws {
            guard contentType == .cmsSignedData else {
                return nil
            }
            return try CMSSignedData(asn1Any: content)
        }
    }
}
