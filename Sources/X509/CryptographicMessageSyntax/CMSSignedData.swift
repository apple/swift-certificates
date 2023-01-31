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
struct CMSSignedData: DERImplicitlyTaggable, Hashable {
    private enum Error: Swift.Error {
        case multipleDigestAlgorithmsAreNotSupportedYet
        case multipleSignerInfosAreNotSupportedYet
    }
    static var defaultIdentifier: ASN1Identifier {
        .sequence
    }
    
    var version: CMSVersion
    var digestAlgorithms: [AlgorithmIdentifier]
    var encapContentInfo: CMSEncapsulatedContentInfo
    var certificates: [Certificate]?
    var signerInfos: [CMSSignerInfo]
    
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
    
    init(derEncoded: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(derEncoded, identifier: identifier) { nodes in
            let version = try CMSVersion(rawValue: Int.init(derEncoded: &nodes))
            let digestAlgorithms = try DER.sequence(of: AlgorithmIdentifier.self, identifier: .set, nodes: &nodes)
            // TODO: support multiple digest algorithms. For this we need to validate that the binary representation of each element is lexicographically sorted.
            guard digestAlgorithms.count <= 1 else {
                throw Error.multipleDigestAlgorithmsAreNotSupportedYet
            }
            
            let encapContentInfo = try CMSEncapsulatedContentInfo(derEncoded: &nodes)
            let certificates = try DER._optionalImplicitlyTagged(&nodes, tag: .init(tagWithNumber: 0, tagClass: .contextSpecific)) { node in
                // TODO: this is actually a SET OF so we need to verify that the binary representation of each element is lexicographically sorted.
                try DER.sequence(of: Certificate.self, identifier: .init(tagWithNumber: 0, tagClass: .contextSpecific), rootNode: node)
            }
            
            // we need to skip this node even though we don't support it
            let _: CMSRevocationInfoChoices? = try DER._optionalImplicitlyTagged(
                &nodes,
                tag: .init(tagWithNumber: 1, tagClass: .contextSpecific)
            )
            
            let signerInfos = try DER.sequence(of: CMSSignerInfo.self, identifier: .set, nodes: &nodes)
            
            // TODO: support multiple signer infos. For this we need to validate that the binary representation of each element is lexicographically sorted.
            guard signerInfos.count <= 1 else {
                throw Error.multipleDigestAlgorithmsAreNotSupportedYet
            }
            
            return .init(
                version: version,
                digestAlgorithms: digestAlgorithms,
                encapContentInfo: encapContentInfo,
                certificates: certificates,
                signerInfos: signerInfos
            )
        }
    }
    
    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(version.rawValue)
            guard self.digestAlgorithms.count <= 1 else {
                throw Error.multipleDigestAlgorithmsAreNotSupportedYet
            }
            // TODO: this is actually a SET OF. We need to sort the binary representation of each element lexicographically before encoding.
            try coder.serializeSequenceOf(self.digestAlgorithms, identifier: .set)
            try coder.serialize(self.encapContentInfo)
            if let certificates {
                // TODO: this is actually a SET OF. We need to sort the binary representation of each element lexicographically before encoding.
                try coder.serializeSequenceOf(certificates, identifier: .init(tagWithNumber: 0, tagClass: .contextSpecific))
            }
            guard self.signerInfos.count <= 1 else {
                throw Error.multipleSignerInfosAreNotSupportedYet
            }
            // TODO: this is actually a SET OF. We need to sort the binary representation of each element lexicographically before encoding.
            try coder.serializeSequenceOf(self.signerInfos, identifier: .set)
        }
    }
}

fileprivate enum CMSCertificateChoices: DERParseable, DERSerializable {
    static var defaultIdentifier: SwiftASN1.ASN1Identifier {
        .enumerated
    }
    
    case certificate(Certificate)
    
    init(derEncoded: ASN1Node) throws {
        guard derEncoded.identifier == Certificate.defaultIdentifier else {
            throw ASN1Error.unexpectedFieldType
        }
        self = try .certificate(.init(derEncoded: derEncoded))
    }
    func serialize(into coder: inout DER.Serializer) throws {
        switch self {
        case .certificate(let certificate):
            try coder.serialize(certificate)
        }
    }
}

/// Not yet supported
fileprivate struct CMSRevocationInfoChoices: DERParseable, DERSerializable {
    init(derEncoded: ASN1Node) throws {}
    func serialize(into coder: inout DER.Serializer) throws {}
}

extension DER {
    /// Parses an optional implicitly tagged element.
    ///
    /// - parameters:
    ///     - nodes: The ``ASN1NodeCollection/Iterator`` to parse this element out of.
    ///     - tag: The implicit tag.
    ///
    /// - returns: The parsed element, if it was present, or `nil` if it was not.
    static func _optionalImplicitlyTagged<T: DERParseable>(
        _ nodes: inout ASN1NodeCollection.Iterator,
        tag: ASN1Identifier
    ) throws -> T? {
        
        var localNodesCopy = nodes
        guard let node = localNodesCopy.next() else {
            // Node not present, return nil.
            return nil
        }
        
        guard node.identifier == tag else {
            // Node is a mismatch, with the wrong tag. Our optional isn't present.
            return nil
        }
        
        // We're good: pass the node on.
        return try T(derEncoded: &nodes)
    }
    
    /// Parses an optional implicitly tagged element.
    ///
    /// - parameters:
    ///     - nodes: The ``ASN1NodeCollection/Iterator`` to parse this element out of.
    ///     - tag: The implicit tag.
    ///
    /// - returns: The parsed element, if it was present, or `nil` if it was not.
    static func _optionalImplicitlyTagged<T>(
        _ nodes: inout ASN1NodeCollection.Iterator,
        tag: ASN1Identifier,
        _ builder: (ASN1Node) throws -> T
    ) throws -> T? {
        
        var localNodesCopy = nodes
        guard let node = localNodesCopy.next() else {
            // Node not present, return nil.
            return nil
        }
        
        guard node.identifier == tag else {
            // Node is a mismatch, with the wrong tag. Our optional isn't present.
            return nil
        }
        nodes = localNodesCopy
        
        // We're good: pass the node on.
        return try builder(node)
    }
}
