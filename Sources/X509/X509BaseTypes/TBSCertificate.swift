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

// TBSCertificate  ::=  SEQUENCE  {
//      version         [0]  Version DEFAULT v1,
//      serialNumber         CertificateSerialNumber,
//      signature            AlgorithmIdentifier,
//      issuer               Name,
//      validity             Validity,
//      subject              Name,
//      subjectPublicKeyInfo SubjectPublicKeyInfo,
//      issuerUniqueID  [1]  IMPLICIT UniqueIdentifier OPTIONAL,
//                           -- If present, version MUST be v2 or v3
//      subjectUniqueID [2]  IMPLICIT UniqueIdentifier OPTIONAL,
//                           -- If present, version MUST be v2 or v3
//      extensions      [3]  Extensions OPTIONAL
//                           -- If present, version MUST be v3 --  }
//
// Version  ::=  INTEGER  {  v1(0), v2(1), v3(2)  }
//
// CertificateSerialNumber  ::=  INTEGER
//
// UniqueIdentifier  ::=  BIT STRING
//
// Extensions  ::=  SEQUENCE SIZE (1..MAX) OF Extension
@usableFromInline
typealias UniqueIdentifier = ASN1BitString

@usableFromInline
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
struct TBSCertificate: DERImplicitlyTaggable, Hashable, Sendable {
    @inlinable
    static var defaultIdentifier: ASN1Identifier {
        .sequence
    }

    @usableFromInline
    var version: Certificate.Version

    @usableFromInline
    var serialNumber: Certificate.SerialNumber

    @usableFromInline
    var signature: Certificate.SignatureAlgorithm

    @usableFromInline
    var issuer: DistinguishedName

    @usableFromInline
    var validity: Validity

    @usableFromInline
    var subject: DistinguishedName

    @usableFromInline
    var publicKey: Certificate.PublicKey

    @usableFromInline
    var issuerUniqueID: UniqueIdentifier?

    @usableFromInline
    var subjectUniqueID: UniqueIdentifier?

    @usableFromInline
    var extensions: Certificate.Extensions

    @inlinable
    internal init(
        version: Certificate.Version,
        serialNumber: Certificate.SerialNumber,
        signature: Certificate.SignatureAlgorithm,
        issuer: DistinguishedName,
        validity: Validity,
        subject: DistinguishedName,
        publicKey: Certificate.PublicKey,
        issuerUniqueID: UniqueIdentifier? = nil,
        subjectUniqueID: UniqueIdentifier? = nil,
        extensions: Certificate.Extensions
    ) {
        self.version = version
        self.serialNumber = serialNumber
        self.signature = signature
        self.issuer = issuer
        self.validity = validity
        self.subject = subject
        self.publicKey = publicKey
        self.issuerUniqueID = issuerUniqueID
        self.subjectUniqueID = subjectUniqueID
        self.extensions = extensions
    }

    @inlinable
    init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let version = try DER.decodeDefaultExplicitlyTagged(
                &nodes,
                tagNumber: 0,
                tagClass: .contextSpecific,
                defaultValue: Int(0)
            )
            guard (0...2).contains(version) else {
                throw ASN1Error.invalidASN1Object(reason: "Invalid X.509 version \(version)")
            }

            let serialNumber = try ArraySlice<UInt8>(derEncoded: &nodes)
            let signature = try AlgorithmIdentifier(derEncoded: &nodes)
            let issuer = try DistinguishedName.derEncoded(&nodes)
            let validity = try Validity(derEncoded: &nodes)
            let subject = try DistinguishedName.derEncoded(&nodes)
            let subjectPublicKeyInfo = try SubjectPublicKeyInfo(derEncoded: &nodes)
            let issuerUniqueID = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 1, tagClass: .contextSpecific) {
                try UniqueIdentifier(derEncoded: $0)
            }
            let subjectUniqueID = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 2, tagClass: .contextSpecific) {
                try UniqueIdentifier(derEncoded: $0)
            }
            let extensions = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 3, tagClass: .contextSpecific) {
                try DER.sequence(of: Certificate.Extension.self, identifier: .sequence, rootNode: $0)
            }

            return TBSCertificate(
                version: Certificate.Version(rawValue: version),
                serialNumber: Certificate.SerialNumber(bytes: serialNumber),
                signature: Certificate.SignatureAlgorithm(algorithmIdentifier: signature),
                issuer: issuer,
                validity: validity,
                subject: subject,
                publicKey: try Certificate.PublicKey(spki: subjectPublicKeyInfo),
                issuerUniqueID: issuerUniqueID,
                subjectUniqueID: subjectUniqueID,
                extensions: try Certificate.Extensions(extensions ?? [])
            )
        }
    }

    @inlinable
    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            if self.version != .v1 {
                try coder.serialize(self.version.rawValue, explicitlyTaggedWithTagNumber: 0, tagClass: .contextSpecific)
            }
            try coder.serialize(self.serialNumber.bytes)
            try coder.serialize(AlgorithmIdentifier(self.signature))
            try coder.serialize(self.issuer)
            try coder.serialize(self.validity)
            try coder.serialize(self.subject)
            try coder.serialize(SubjectPublicKeyInfo(self.publicKey))
            if let issuerUniqueID = self.issuerUniqueID {
                try coder.serialize(issuerUniqueID, explicitlyTaggedWithTagNumber: 1, tagClass: .contextSpecific)
            }
            if let subjectUniqueID = self.subjectUniqueID {
                try coder.serialize(subjectUniqueID, explicitlyTaggedWithTagNumber: 2, tagClass: .contextSpecific)
            }
            if self.extensions.count > 0 {
                try coder.serialize(explicitlyTaggedWithTagNumber: 3, tagClass: .contextSpecific) { coder in
                    try coder.serializeSequenceOf(extensions)
                }
            }
        }
    }
}
