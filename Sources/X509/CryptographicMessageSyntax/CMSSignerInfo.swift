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

/// ``CMSSignerInfo`` is defined in ASN.1 as:
/// ```
/// SignerInfo ::= SEQUENCE {
///   version CMSVersion,
///   sid SignerIdentifier,
///   digestAlgorithm DigestAlgorithmIdentifier,
///   signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
///   signatureAlgorithm SignatureAlgorithmIdentifier,
///   signature SignatureValue,
///   unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL }
///
/// SignatureValue ::= OCTET STRING
/// DigestAlgorithmIdentifier ::= AlgorithmIdentifier
/// SignatureAlgorithmIdentifier ::= AlgorithmIdentifier
/// ```
/// - Note: If the `SignerIdentifier` is the CHOICE `issuerAndSerialNumber`,
/// then the `version` MUST be 1.  If the `SignerIdentifier` is `subjectKeyIdentifier`,
/// then the `version` MUST be 3.
/// - Note: At the moment we neither support `signedAttrs` (`SignedAttributes`) nor `unsignedAttrs` (`UnsignedAttributes`)
@usableFromInline
struct CMSSignerInfo: DERImplicitlyTaggable, Hashable, Sendable {
    @usableFromInline
    enum Error: Swift.Error {
        case versionAndSignerIdentifierMismatch(String)
    }

    @inlinable
    static var defaultIdentifier: ASN1Identifier {
        .sequence
    }
    
    @usableFromInline var version: CMSVersion
    @usableFromInline var signerIdentifier: CMSSignerIdentifier
    @usableFromInline var digestAlgorithm: AlgorithmIdentifier
    @usableFromInline var signatureAlgorithm: AlgorithmIdentifier
    @usableFromInline var signature: ASN1OctetString

    @inlinable
    init(
        signerIdentifier: CMSSignerIdentifier,
        digestAlgorithm: AlgorithmIdentifier,
        signatureAlgorithm: AlgorithmIdentifier,
        signature: ASN1OctetString
    ) {
        switch signerIdentifier {
        case .issuerAndSerialNumber:
            self.version = .v1
        case .subjectKeyIdentifier:
            self.version = .v3
        }
        self.signerIdentifier = signerIdentifier
        self.digestAlgorithm = digestAlgorithm
        self.signatureAlgorithm = signatureAlgorithm
        self.signature = signature
    }

    @inlinable
    init(
        version: CMSVersion,
        signerIdentifier: CMSSignerIdentifier,
        digestAlgorithm: AlgorithmIdentifier,
        signatureAlgorithm: AlgorithmIdentifier,
        signature: ASN1OctetString
    ) {
        self.version = version
        self.signerIdentifier = signerIdentifier
        self.digestAlgorithm = digestAlgorithm
        self.signatureAlgorithm = signatureAlgorithm
        self.signature = signature
    }

    @inlinable
    init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let version = try CMSVersion(rawValue: Int(derEncoded: &nodes))
            let signerIdentifier = try CMSSignerIdentifier(derEncoded: &nodes)
            switch signerIdentifier {
            case .issuerAndSerialNumber:
                guard version == .v1 else {
                    throw Error.versionAndSignerIdentifierMismatch("expected \(CMSVersion.v1) but got \(version) where signerIdentifier is \(signerIdentifier)")
                }
            case .subjectKeyIdentifier:
                guard version == .v3 else {
                    throw Error.versionAndSignerIdentifierMismatch("expected \(CMSVersion.v3) but got \(version) where signerIdentifier is \(signerIdentifier)")
                }
            }
            let digestAlgorithm = try AlgorithmIdentifier(derEncoded: &nodes)
            
            // we don't support signedAttrs yet but we still need to skip them
            _ = DER.optionalImplicitlyTagged(&nodes, tagNumber: 0, tagClass: .contextSpecific) { _ in }
            
            let signatureAlgorithm = try AlgorithmIdentifier(derEncoded: &nodes)
            let signature = try ASN1OctetString(derEncoded: &nodes)
            
            // we don't support unsignedAttrs yet but we still need to skip them
            _ = DER.optionalImplicitlyTagged(&nodes, tagNumber: 1, tagClass: .contextSpecific) { _ in }
            
            return .init(
                version: version,
                signerIdentifier: signerIdentifier,
                digestAlgorithm: digestAlgorithm,
                signatureAlgorithm: signatureAlgorithm,
                signature: signature
            )
        }
    }

    @inlinable
    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(self.version.rawValue)
            try coder.serialize(self.signerIdentifier)
            try coder.serialize(self.digestAlgorithm)
            try coder.serialize(self.signatureAlgorithm)
            try coder.serialize(self.signature)
        }
    }
}
