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

/// ``SignedData`` is defined in ASN.1 as:
/// ```
/// SignedData ::= SEQUENCE {
///   version CMSVersion,
///   digestAlgorithms DigestAlgorithmIdentifiers,
///   encapContentInfo EncapsulatedContentInfo,
///   certificates [0] IMPLICIT CertificateSet OPTIONAL,
///   crls [1] IMPLICIT RevocationInfoChoices OPTIONAL,
///   signerInfos SignerInfos }
///
/// DigestAlgorithmIdentifiers ::= SET OF DigestAlgorithmIdentifier
/// DigestAlgorithmIdentifier ::= AlgorithmIdentifier
/// SignerInfos ::= SET OF SignerInfo
/// CertificateSet ::= SET OF CertificateChoices
///
/// CertificateChoices ::= CHOICE {
///  certificate Certificate,
///  extendedCertificate [0] IMPLICIT ExtendedCertificate, -- Obsolete
///  v1AttrCert [1] IMPLICIT AttributeCertificateV1,       -- Obsolete
///  v2AttrCert [2] IMPLICIT AttributeCertificateV2,
///  other [3] IMPLICIT OtherCertificateFormat }
///
/// OtherCertificateFormat ::= SEQUENCE {
///   otherCertFormat OBJECT IDENTIFIER,
///   otherCert ANY DEFINED BY otherCertFormat }
/// ```
/// - Note: At the moment we don't support `crls` (`RevocationInfoChoices`)
@usableFromInline
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
struct CMSSignedData: DERImplicitlyTaggable, BERImplicitlyTaggable, Hashable, Sendable {
    @inlinable
    static var defaultIdentifier: ASN1Identifier {
        .sequence
    }

    @usableFromInline var version: CMSVersion
    @usableFromInline var digestAlgorithms: [AlgorithmIdentifier]
    @usableFromInline var encapContentInfo: CMSEncapsulatedContentInfo
    @usableFromInline var certificates: [Certificate]?
    @usableFromInline var signerInfos: [CMSSignerInfo]

    @inlinable
    init(
        version: CMSVersion,
        digestAlgorithms: [AlgorithmIdentifier],
        encapContentInfo: CMSEncapsulatedContentInfo,
        certificates: [Certificate]?,
        signerInfos: [CMSSignerInfo]
    ) {
        self.version = version
        self.digestAlgorithms = digestAlgorithms
        self.encapContentInfo = encapContentInfo
        self.certificates = certificates
        self.signerInfos = signerInfos
    }

    @inlinable
    init(derEncoded: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(derEncoded, identifier: identifier) { nodes in
            let version = try CMSVersion(rawValue: Int.init(derEncoded: &nodes))
            let digestAlgorithms = try DER.set(of: AlgorithmIdentifier.self, identifier: .set, nodes: &nodes)

            let encapContentInfo = try CMSEncapsulatedContentInfo(derEncoded: &nodes)
            let certificates = try DER.optionalImplicitlyTagged(&nodes, tagNumber: 0, tagClass: .contextSpecific) {
                node in
                try DER.set(
                    of: Certificate.self,
                    identifier: .init(tagWithNumber: 0, tagClass: .contextSpecific),
                    rootNode: node
                )
            }

            // we need to skip this node even though we don't support it
            _ = DER.optionalImplicitlyTagged(&nodes, tagNumber: 1, tagClass: .contextSpecific) { _ in }

            let signerInfos = try DER.set(of: CMSSignerInfo.self, identifier: .set, nodes: &nodes)

            return .init(
                version: version,
                digestAlgorithms: digestAlgorithms,
                encapContentInfo: encapContentInfo,
                certificates: certificates,
                signerInfos: signerInfos
            )
        }
    }

    @inlinable
    init(berEncoded: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try BER.sequence(berEncoded, identifier: identifier) { nodes in
            let version = try CMSVersion(rawValue: Int.init(derEncoded: &nodes))
            let digestAlgorithms = try BER.set(of: AlgorithmIdentifier.self, identifier: .set, nodes: &nodes)

            let encapContentInfo = try CMSEncapsulatedContentInfo(berEncoded: &nodes)
            let certificates = try BER.optionalImplicitlyTagged(&nodes, tagNumber: 0, tagClass: .contextSpecific) {
                node in
                // Certificates should be DER encoded. Technically they can be in BER, but requires round-tripping for verification.
                try DER.set(
                    of: Certificate.self,
                    identifier: .init(tagWithNumber: 0, tagClass: .contextSpecific),
                    rootNode: node
                )
            }

            // we need to skip this node even though we don't support it
            _ = BER.optionalImplicitlyTagged(&nodes, tagNumber: 1, tagClass: .contextSpecific) { _ in }

            let signerInfos = try BER.set(of: CMSSignerInfo.self, identifier: .set, nodes: &nodes)

            return .init(
                version: version,
                digestAlgorithms: digestAlgorithms,
                encapContentInfo: encapContentInfo,
                certificates: certificates,
                signerInfos: signerInfos
            )
        }
    }

    @inlinable
    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(version.rawValue)
            try coder.serializeSetOf(self.digestAlgorithms)
            try coder.serialize(self.encapContentInfo)
            if let certificates {
                try coder.serializeSetOf(certificates, identifier: .init(tagWithNumber: 0, tagClass: .contextSpecific))
            }
            try coder.serializeSetOf(self.signerInfos, identifier: .set)
        }
    }
}
