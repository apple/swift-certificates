//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCertificates open source project
//
// Copyright (c) 2026 Apple Inc. and the SwiftCertificates project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCertificates project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import SwiftASN1

/// ``DigestedData`` is defined in ASN.1 as:
/// ```
/// DigestedData ::= SEQUENCE {
///   version CMSVersion,
///   digestAlgorithm DigestAlgorithmIdentifier,
///   encapContentInfo EncapsulatedContentInfo,
///   digest OCTET STRING }
///
/// DigestAlgorithmIdentifier ::= AlgorithmIdentifier
/// ```
@usableFromInline
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
struct CMSDigestedData: DERImplicitlyTaggable, BERImplicitlyTaggable, Hashable, Sendable {
    @inlinable
    static var defaultIdentifier: ASN1Identifier {
        .sequence
    }

    @usableFromInline var version: CMSVersion
    @usableFromInline var digestAlgorithm: AlgorithmIdentifier
    @usableFromInline var encapContentInfo: CMSEncapsulatedContentInfo
    @usableFromInline var digest: ASN1OctetString

    @inlinable
    init(
        version: CMSVersion,
        digestAlgorithm: AlgorithmIdentifier,
        encapContentInfo: CMSEncapsulatedContentInfo,
        digest: ASN1OctetString
    ) {
        self.version = version
        self.digestAlgorithm = digestAlgorithm
        self.encapContentInfo = encapContentInfo
        self.digest = digest
    }

    @inlinable
    init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let version = try CMSVersion(rawValue: Int(derEncoded: &nodes))
            let digestAlgorithm = try AlgorithmIdentifier(derEncoded: &nodes)
            let encapContentInfo = try CMSEncapsulatedContentInfo(derEncoded: &nodes)
            let digest = try ASN1OctetString(derEncoded: &nodes)

            return .init(
                version: version,
                digestAlgorithm: digestAlgorithm,
                encapContentInfo: encapContentInfo,
                digest: digest
            )
        }
    }

    @inlinable
    init(berEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try BER.sequence(rootNode, identifier: identifier) { nodes in
            let version = try CMSVersion(rawValue: Int(berEncoded: &nodes))
            let digestAlgorithm = try AlgorithmIdentifier(berEncoded: &nodes)
            let encapContentInfo = try CMSEncapsulatedContentInfo(berEncoded: &nodes)
            let digest = try ASN1OctetString(berEncoded: &nodes)

            return .init(
                version: version,
                digestAlgorithm: digestAlgorithm,
                encapContentInfo: encapContentInfo,
                digest: digest
            )
        }
    }

    @inlinable
    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(self.version.rawValue)
            try coder.serialize(self.digestAlgorithm)
            try coder.serialize(self.encapContentInfo)
            try coder.serialize(self.digest)
        }
    }
}
