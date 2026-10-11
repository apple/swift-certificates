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

extension ASN1ObjectIdentifier {
    /// Cryptographic Message Syntax (CMS) Enveloped Data.
    @usableFromInline
    static let cmsEnvelopedData: ASN1ObjectIdentifier = [1, 2, 840, 113549, 1, 7, 3]

    /// Cryptographic Message Syntax (CMS) Digested Data.
    @usableFromInline
    static let cmsDigestedData: ASN1ObjectIdentifier = [1, 2, 840, 113549, 1, 7, 5]

    /// Cryptographic Message Syntax (CMS) Encrypted Data.
    @usableFromInline
    static let cmsEncryptedData: ASN1ObjectIdentifier = [1, 2, 840, 113549, 1, 7, 6]
}

extension ASN1ObjectIdentifier.AlgorithmIdentifier {
    @usableFromInline
    static let rsaESOAEP: ASN1ObjectIdentifier = [1, 2, 840, 113549, 1, 1, 7]

    @usableFromInline
    static let mgf1: ASN1ObjectIdentifier = [1, 2, 840, 113549, 1, 1, 8]

    @usableFromInline
    static let pSpecified: ASN1ObjectIdentifier = [1, 2, 840, 113549, 1, 1, 9]

    @usableFromInline
    static let aes128CBC: ASN1ObjectIdentifier = [2, 16, 840, 1, 101, 3, 4, 1, 2]

    @usableFromInline
    static let aes256CBC: ASN1ObjectIdentifier = [2, 16, 840, 1, 101, 3, 4, 1, 42]

    @usableFromInline
    static let aes192CBC: ASN1ObjectIdentifier = [2, 16, 840, 1, 101, 3, 4, 1, 22]

    @usableFromInline
    static let aes128GCM: ASN1ObjectIdentifier = [2, 16, 840, 1, 101, 3, 4, 1, 6]

    @usableFromInline
    static let aes192GCM: ASN1ObjectIdentifier = [2, 16, 840, 1, 101, 3, 4, 1, 26]

    @usableFromInline
    static let aes256GCM: ASN1ObjectIdentifier = [2, 16, 840, 1, 101, 3, 4, 1, 46]

    @usableFromInline
    static let aesKeyWrap128: ASN1ObjectIdentifier = [2, 16, 840, 1, 101, 3, 4, 1, 5]

    @usableFromInline
    static let aesKeyWrap256: ASN1ObjectIdentifier = [2, 16, 840, 1, 101, 3, 4, 1, 45]

    @usableFromInline
    static let pbkdf2: ASN1ObjectIdentifier = [1, 2, 840, 113549, 1, 5, 12]

    @usableFromInline
    static let hmacWithSHA256: ASN1ObjectIdentifier = [1, 2, 840, 113549, 2, 9]

    @usableFromInline
    static let hmacWithSHA1: ASN1ObjectIdentifier = [1, 2, 840, 113549, 2, 7]

}

extension AlgorithmIdentifier {
    @usableFromInline
    static let cmsAES256CBC = AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.aes256CBC,
        parameters: nil
    )

    @usableFromInline
    static func cmsAES256CBC(iv: ASN1OctetString) throws -> AlgorithmIdentifier {
        AlgorithmIdentifier(
            algorithm: .AlgorithmIdentifier.aes256CBC,
            parameters: try ASN1Any(erasing: iv)
        )
    }

    @usableFromInline
    static let cmsAES128CBC = AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.aes128CBC,
        parameters: nil
    )

    @usableFromInline
    static func cmsAES128CBC(iv: ASN1OctetString) throws -> AlgorithmIdentifier {
        AlgorithmIdentifier(
            algorithm: .AlgorithmIdentifier.aes128CBC,
            parameters: try ASN1Any(erasing: iv)
        )
    }

    @usableFromInline
    static let cmsAES192CBC = AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.aes192CBC,
        parameters: nil
    )

    @usableFromInline
    static func cmsAES192CBC(iv: ASN1OctetString) throws -> AlgorithmIdentifier {
        AlgorithmIdentifier(
            algorithm: .AlgorithmIdentifier.aes192CBC,
            parameters: try ASN1Any(erasing: iv)
        )
    }

    @usableFromInline
    static func cmsAES128GCM(parameters: CMSGCMParameters) throws -> AlgorithmIdentifier {
        AlgorithmIdentifier(
            algorithm: .AlgorithmIdentifier.aes128GCM,
            parameters: try ASN1Any(erasing: parameters)
        )
    }

    @usableFromInline
    static func cmsAES192GCM(parameters: CMSGCMParameters) throws -> AlgorithmIdentifier {
        AlgorithmIdentifier(
            algorithm: .AlgorithmIdentifier.aes192GCM,
            parameters: try ASN1Any(erasing: parameters)
        )
    }

    @usableFromInline
    static func cmsAES256GCM(parameters: CMSGCMParameters) throws -> AlgorithmIdentifier {
        AlgorithmIdentifier(
            algorithm: .AlgorithmIdentifier.aes256GCM,
            parameters: try ASN1Any(erasing: parameters)
        )
    }

    @usableFromInline
    static let cmsMGF1WithSHA1 = AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.mgf1,
        parameters: try! ASN1Any(erasing: AlgorithmIdentifier.sha1)
    )

    @usableFromInline
    static let cmsMGF1WithSHA256 = AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.mgf1,
        parameters: try! ASN1Any(erasing: AlgorithmIdentifier.sha256)
    )

    @usableFromInline
    static let cmsPSpecifiedEmpty = AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.pSpecified,
        parameters: try! ASN1Any(erasing: ASN1OctetString(contentBytes: []))
    )

    @usableFromInline
    static let cmsRSAESOAEPWithSHA1 = AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.rsaESOAEP,
        parameters: try! ASN1Any(erasing: CMSRSAESOAEPParams())
    )

    @usableFromInline
    static let cmsRSAESOAEPWithSHA256 = AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.rsaESOAEP,
        parameters: try! ASN1Any(
            erasing: CMSRSAESOAEPParams(
                hashAlgorithm: .sha256,
                maskGenAlgorithm: .cmsMGF1WithSHA256
            )
        )
    )

    @usableFromInline
    static let hmacWithSHA256 = AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.hmacWithSHA256,
        parameters: try! ASN1Any(erasing: ASN1Null())
    )

    @usableFromInline
    static let hmacWithSHA1 = AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.hmacWithSHA1,
        parameters: try! ASN1Any(erasing: ASN1Null())
    )

    @usableFromInline
    static let cmsAESKeyWrap128 = AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.aesKeyWrap128,
        parameters: nil
    )

    @usableFromInline
    static let cmsAESKeyWrap256 = AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.aesKeyWrap256,
        parameters: nil
    )

    @usableFromInline
    static func cmsPBKDF2(
        salt: ASN1OctetString,
        iterationCount: Int,
        keyLength: Int = 32
    ) throws -> AlgorithmIdentifier {
        AlgorithmIdentifier(
            algorithm: .AlgorithmIdentifier.pbkdf2,
            parameters: try ASN1Any(
                erasing: CMSPBKDF2Params(
                    salt: salt,
                    iterationCount: iterationCount,
                    keyLength: keyLength,
                    prf: .hmacWithSHA256
                )
            )
        )
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
@usableFromInline
struct CMSGCMParameters: DERImplicitlyTaggable, BERImplicitlyTaggable, Hashable, Sendable {
    @usableFromInline
    static let defaultICVLength = 12

    @usableFromInline
    static let supportedICVLength = 16

    @usableFromInline
    static var defaultIdentifier: ASN1Identifier {
        .sequence
    }

    @usableFromInline
    var nonce: ASN1OctetString

    @usableFromInline
    var icvLength: Int

    @inlinable
    init(nonce: ASN1OctetString, icvLength: Int = CMSGCMParameters.supportedICVLength) {
        self.nonce = nonce
        self.icvLength = icvLength
    }

    @inlinable
    init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let nonce = try ASN1OctetString(derEncoded: &nodes)
            let icvLength = try nodes.next().map { try Int(derEncoded: $0) } ?? Self.defaultICVLength
            return .init(nonce: nonce, icvLength: icvLength)
        }
    }

    @inlinable
    init(berEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try BER.sequence(rootNode, identifier: identifier) { nodes in
            let nonce = try ASN1OctetString(berEncoded: &nodes)
            let icvLength = try nodes.next().map { try Int(berEncoded: $0) } ?? Self.defaultICVLength
            return .init(nonce: nonce, icvLength: icvLength)
        }
    }

    @inlinable
    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(self.nonce)
            if self.icvLength != Self.defaultICVLength {
                try coder.serialize(self.icvLength)
            }
        }
    }
}

@usableFromInline
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
struct CMSEncryptedContentInfo: DERImplicitlyTaggable, BERImplicitlyTaggable, Hashable, Sendable {
    @usableFromInline
    static let encryptedContentIdentifier = ASN1Identifier(tagWithNumber: 0, tagClass: .contextSpecific)

    @inlinable
    static var defaultIdentifier: ASN1Identifier {
        .sequence
    }

    @usableFromInline var contentType: ASN1ObjectIdentifier
    @usableFromInline var contentEncryptionAlgorithm: AlgorithmIdentifier
    @usableFromInline var encryptedContent: ASN1OctetString?

    @inlinable
    init(
        contentType: ASN1ObjectIdentifier,
        contentEncryptionAlgorithm: AlgorithmIdentifier,
        encryptedContent: ASN1OctetString? = nil
    ) {
        self.contentType = contentType
        self.contentEncryptionAlgorithm = contentEncryptionAlgorithm
        self.encryptedContent = encryptedContent
    }

    @inlinable
    init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let contentType = try ASN1ObjectIdentifier(derEncoded: &nodes)
            let contentEncryptionAlgorithm = try AlgorithmIdentifier(derEncoded: &nodes)
            let encryptedContent = try DER.optionalImplicitlyTagged(
                &nodes,
                tagNumber: Self.encryptedContentIdentifier.tagNumber,
                tagClass: Self.encryptedContentIdentifier.tagClass
            ) { node in
                try ASN1OctetString(derEncoded: node, withIdentifier: Self.encryptedContentIdentifier)
            }

            return .init(
                contentType: contentType,
                contentEncryptionAlgorithm: contentEncryptionAlgorithm,
                encryptedContent: encryptedContent
            )
        }
    }

    @inlinable
    init(berEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try BER.sequence(rootNode, identifier: identifier) { nodes in
            let contentType = try ASN1ObjectIdentifier(berEncoded: &nodes)
            let contentEncryptionAlgorithm = try AlgorithmIdentifier(berEncoded: &nodes)
            let encryptedContent = try BER.optionalImplicitlyTagged(
                &nodes,
                tagNumber: Self.encryptedContentIdentifier.tagNumber,
                tagClass: Self.encryptedContentIdentifier.tagClass
            ) { node in
                try ASN1OctetString(berEncoded: node, withIdentifier: Self.encryptedContentIdentifier)
            }

            return .init(
                contentType: contentType,
                contentEncryptionAlgorithm: contentEncryptionAlgorithm,
                encryptedContent: encryptedContent
            )
        }
    }

    @inlinable
    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(self.contentType)
            try coder.serialize(self.contentEncryptionAlgorithm)
            if let encryptedContent {
                try encryptedContent.serialize(into: &coder, withIdentifier: Self.encryptedContentIdentifier)
            }
        }
    }
}

@usableFromInline
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
struct CMSEncryptedData: DERImplicitlyTaggable, BERImplicitlyTaggable, Hashable, Sendable {
    @usableFromInline
    static let unprotectedAttrsIdentifier = ASN1Identifier(tagWithNumber: 1, tagClass: .contextSpecific)

    @inlinable
    static var defaultIdentifier: ASN1Identifier {
        .sequence
    }

    @usableFromInline var version: CMSVersion
    @usableFromInline var encryptedContentInfo: CMSEncryptedContentInfo
    @usableFromInline var unprotectedAttrs: [CMSAttribute]?

    @inlinable
    init(
        version: CMSVersion,
        encryptedContentInfo: CMSEncryptedContentInfo,
        unprotectedAttrs: [CMSAttribute]?
    ) {
        self.version = version
        self.encryptedContentInfo = encryptedContentInfo
        self.unprotectedAttrs = unprotectedAttrs
    }

    @inlinable
    init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let version = try CMSVersion(rawValue: Int(derEncoded: &nodes))
            let encryptedContentInfo = try CMSEncryptedContentInfo(derEncoded: &nodes)
            let unprotectedAttrs = try DER.optionalImplicitlyTagged(
                &nodes,
                tagNumber: Self.unprotectedAttrsIdentifier.tagNumber,
                tagClass: Self.unprotectedAttrsIdentifier.tagClass
            ) { node in
                try DER.set(of: CMSAttribute.self, identifier: Self.unprotectedAttrsIdentifier, rootNode: node)
            }

            return .init(
                version: version,
                encryptedContentInfo: encryptedContentInfo,
                unprotectedAttrs: unprotectedAttrs
            )
        }
    }

    @inlinable
    init(berEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try BER.sequence(rootNode, identifier: identifier) { nodes in
            let version = try CMSVersion(rawValue: Int(berEncoded: &nodes))
            let encryptedContentInfo = try CMSEncryptedContentInfo(berEncoded: &nodes)
            let unprotectedAttrs = try BER.optionalImplicitlyTagged(
                &nodes,
                tagNumber: Self.unprotectedAttrsIdentifier.tagNumber,
                tagClass: Self.unprotectedAttrsIdentifier.tagClass
            ) { node in
                try BER.set(of: CMSAttribute.self, identifier: Self.unprotectedAttrsIdentifier, rootNode: node)
            }

            return .init(
                version: version,
                encryptedContentInfo: encryptedContentInfo,
                unprotectedAttrs: unprotectedAttrs
            )
        }
    }

    @inlinable
    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(self.version.rawValue)
            try coder.serialize(self.encryptedContentInfo)
            if let unprotectedAttrs {
                try coder.serializeSetOf(unprotectedAttrs, identifier: Self.unprotectedAttrsIdentifier)
            }
        }
    }
}

@usableFromInline
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
struct CMSEnvelopedData: DERImplicitlyTaggable, BERImplicitlyTaggable, Hashable, Sendable {
    @usableFromInline
    static let originatorInfoIdentifier = ASN1Identifier(tagWithNumber: 0, tagClass: .contextSpecific)

    @usableFromInline
    static let unprotectedAttrsIdentifier = ASN1Identifier(tagWithNumber: 1, tagClass: .contextSpecific)

    @inlinable
    static var defaultIdentifier: ASN1Identifier {
        .sequence
    }

    @usableFromInline var version: CMSVersion
    @usableFromInline var originatorInfo: CMSOriginatorInfo?
    @usableFromInline var recipientInfos: [CMSRecipientInfo]
    @usableFromInline var encryptedContentInfo: CMSEncryptedContentInfo
    @usableFromInline var unprotectedAttrs: [CMSAttribute]?

    @inlinable
    init(
        version: CMSVersion,
        originatorInfo: CMSOriginatorInfo?,
        recipientInfos: [CMSRecipientInfo],
        encryptedContentInfo: CMSEncryptedContentInfo,
        unprotectedAttrs: [CMSAttribute]?
    ) {
        self.version = version
        self.originatorInfo = originatorInfo
        self.recipientInfos = recipientInfos
        self.encryptedContentInfo = encryptedContentInfo
        self.unprotectedAttrs = unprotectedAttrs
    }

    @inlinable
    init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let version = try CMSVersion(rawValue: Int(derEncoded: &nodes))
            let originatorInfo = try DER.optionalImplicitlyTagged(
                &nodes,
                tagNumber: Self.originatorInfoIdentifier.tagNumber,
                tagClass: Self.originatorInfoIdentifier.tagClass
            ) { node in
                try CMSOriginatorInfo(derEncoded: node, withIdentifier: Self.originatorInfoIdentifier)
            }
            let recipientInfos = try DER.set(of: CMSRecipientInfo.self, identifier: .set, nodes: &nodes)
            let encryptedContentInfo = try CMSEncryptedContentInfo(derEncoded: &nodes)
            let unprotectedAttrs = try DER.optionalImplicitlyTagged(
                &nodes,
                tagNumber: Self.unprotectedAttrsIdentifier.tagNumber,
                tagClass: Self.unprotectedAttrsIdentifier.tagClass
            ) { node in
                try DER.set(of: CMSAttribute.self, identifier: Self.unprotectedAttrsIdentifier, rootNode: node)
            }

            return .init(
                version: version,
                originatorInfo: originatorInfo,
                recipientInfos: recipientInfos,
                encryptedContentInfo: encryptedContentInfo,
                unprotectedAttrs: unprotectedAttrs
            )
        }
    }

    @inlinable
    init(berEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try BER.sequence(rootNode, identifier: identifier) { nodes in
            let version = try CMSVersion(rawValue: Int(berEncoded: &nodes))
            let originatorInfo = try BER.optionalImplicitlyTagged(
                &nodes,
                tagNumber: Self.originatorInfoIdentifier.tagNumber,
                tagClass: Self.originatorInfoIdentifier.tagClass
            ) { node in
                try CMSOriginatorInfo(berEncoded: node, withIdentifier: Self.originatorInfoIdentifier)
            }
            let recipientInfos = try BER.set(of: CMSRecipientInfo.self, identifier: .set, nodes: &nodes)
            let encryptedContentInfo = try CMSEncryptedContentInfo(berEncoded: &nodes)
            let unprotectedAttrs = try BER.optionalImplicitlyTagged(
                &nodes,
                tagNumber: Self.unprotectedAttrsIdentifier.tagNumber,
                tagClass: Self.unprotectedAttrsIdentifier.tagClass
            ) { node in
                try BER.set(of: CMSAttribute.self, identifier: Self.unprotectedAttrsIdentifier, rootNode: node)
            }

            return .init(
                version: version,
                originatorInfo: originatorInfo,
                recipientInfos: recipientInfos,
                encryptedContentInfo: encryptedContentInfo,
                unprotectedAttrs: unprotectedAttrs
            )
        }
    }

    @inlinable
    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(self.version.rawValue)
            if let originatorInfo {
                try originatorInfo.serialize(into: &coder, withIdentifier: Self.originatorInfoIdentifier)
            }
            try coder.serializeSetOf(self.recipientInfos)
            try coder.serialize(self.encryptedContentInfo)
            if let unprotectedAttrs {
                try coder.serializeSetOf(unprotectedAttrs, identifier: Self.unprotectedAttrsIdentifier)
            }
        }
    }

    @usableFromInline
    var expectedVersion: CMSVersion {
        if self.recipientInfos.contains(where: { $0.cmsVersion == .v4 }) {
            return .v4
        }

        if self.recipientInfos.contains(where: { $0.requiresEnvelopedDataVersion3 }) {
            return .v3
        }

        if self.originatorInfo == nil
            && self.unprotectedAttrs == nil
            && self.recipientInfos.allSatisfy({ $0.cmsVersion == .v0 })
        {
            return .v0
        }

        return .v2
    }
}

@usableFromInline
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
struct CMSOriginatorInfo: DERImplicitlyTaggable, BERImplicitlyTaggable, Hashable, Sendable {
    @usableFromInline
    static let certificatesIdentifier = ASN1Identifier(tagWithNumber: 0, tagClass: .contextSpecific)

    @usableFromInline
    static let crlsIdentifier = ASN1Identifier(tagWithNumber: 1, tagClass: .contextSpecific)

    @inlinable
    static var defaultIdentifier: ASN1Identifier {
        .sequence
    }

    @usableFromInline var certificates: [Certificate]?

    @inlinable
    init(certificates: [Certificate]?) {
        self.certificates = certificates
    }

    @inlinable
    init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let certificates = try DER.optionalImplicitlyTagged(
                &nodes,
                tagNumber: Self.certificatesIdentifier.tagNumber,
                tagClass: Self.certificatesIdentifier.tagClass
            ) { node in
                try DER.set(of: Certificate.self, identifier: Self.certificatesIdentifier, rootNode: node)
            }

            _ = DER.optionalImplicitlyTagged(
                &nodes,
                tagNumber: Self.crlsIdentifier.tagNumber,
                tagClass: Self.crlsIdentifier.tagClass
            ) { _ in }

            return .init(certificates: certificates)
        }
    }

    @inlinable
    init(berEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try BER.sequence(rootNode, identifier: identifier) { nodes in
            let certificates = try BER.optionalImplicitlyTagged(
                &nodes,
                tagNumber: Self.certificatesIdentifier.tagNumber,
                tagClass: Self.certificatesIdentifier.tagClass
            ) { node in
                try BER.set(node, identifier: Self.certificatesIdentifier) { nodes in
                    var certificates: [Certificate] = []
                    while let node = nodes.next() {
                        // Certificates should be DER encoded. Technically they can be in BER, but
                        // that requires round-tripping their encoded bytes for verification.
                        try certificates.append(Certificate(derEncoded: node))
                    }
                    return certificates
                }
            }

            _ = BER.optionalImplicitlyTagged(
                &nodes,
                tagNumber: Self.crlsIdentifier.tagNumber,
                tagClass: Self.crlsIdentifier.tagClass
            ) { _ in }

            return .init(certificates: certificates)
        }
    }

    @inlinable
    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            if let certificates {
                try coder.serializeSetOf(certificates, identifier: Self.certificatesIdentifier)
            }
        }
    }
}

@usableFromInline
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
enum CMSRecipientInfo: DERParseable, BERParseable, DERSerializable, BERSerializable, Hashable, Sendable {
    @usableFromInline
    static let keyAgreeRecipientInfoIdentifier = ASN1Identifier(tagWithNumber: 1, tagClass: .contextSpecific)

    @usableFromInline
    static let kekRecipientInfoIdentifier = ASN1Identifier(tagWithNumber: 2, tagClass: .contextSpecific)

    @usableFromInline
    static let passwordRecipientInfoIdentifier = ASN1Identifier(tagWithNumber: 3, tagClass: .contextSpecific)

    @usableFromInline
    static let otherRecipientInfoIdentifier = ASN1Identifier(tagWithNumber: 4, tagClass: .contextSpecific)

    case keyTransRecipientInfo(CMSKeyTransRecipientInfo)
    case keyAgreeRecipientInfo(CMSKeyAgreeRecipientInfo)
    case kekRecipientInfo(CMSKEKRecipientInfo)
    case passwordRecipientInfo(CMSPasswordRecipientInfo)
    case otherRecipientInfo(CMSOtherRecipientInfo)

    @inlinable
    init(derEncoded node: ASN1Node) throws {
        switch node.identifier {
        case CMSKeyTransRecipientInfo.defaultIdentifier:
            self = try .keyTransRecipientInfo(.init(derEncoded: node))

        case Self.keyAgreeRecipientInfoIdentifier:
            self = try .keyAgreeRecipientInfo(
                .init(derEncoded: node, withIdentifier: Self.keyAgreeRecipientInfoIdentifier)
            )

        case Self.kekRecipientInfoIdentifier:
            self = try .kekRecipientInfo(.init(derEncoded: node, withIdentifier: Self.kekRecipientInfoIdentifier))

        case Self.passwordRecipientInfoIdentifier:
            self = try .passwordRecipientInfo(
                .init(derEncoded: node, withIdentifier: Self.passwordRecipientInfoIdentifier)
            )

        case Self.otherRecipientInfoIdentifier:
            self = try .otherRecipientInfo(.init(derEncoded: node, withIdentifier: Self.otherRecipientInfoIdentifier))

        default:
            throw ASN1Error.unexpectedFieldType(node.identifier)
        }
    }

    @inlinable
    init(berEncoded node: ASN1Node) throws {
        switch node.identifier {
        case CMSKeyTransRecipientInfo.defaultIdentifier:
            self = try .keyTransRecipientInfo(.init(berEncoded: node))

        case Self.keyAgreeRecipientInfoIdentifier:
            self = try .keyAgreeRecipientInfo(
                .init(berEncoded: node, withIdentifier: Self.keyAgreeRecipientInfoIdentifier)
            )

        case Self.kekRecipientInfoIdentifier:
            self = try .kekRecipientInfo(.init(berEncoded: node, withIdentifier: Self.kekRecipientInfoIdentifier))

        case Self.passwordRecipientInfoIdentifier:
            self = try .passwordRecipientInfo(
                .init(berEncoded: node, withIdentifier: Self.passwordRecipientInfoIdentifier)
            )

        case Self.otherRecipientInfoIdentifier:
            self = try .otherRecipientInfo(.init(berEncoded: node, withIdentifier: Self.otherRecipientInfoIdentifier))

        default:
            throw ASN1Error.unexpectedFieldType(node.identifier)
        }
    }

    @inlinable
    func serialize(into coder: inout DER.Serializer) throws {
        switch self {
        case .keyTransRecipientInfo(let keyTransRecipientInfo):
            try coder.serialize(keyTransRecipientInfo)

        case .keyAgreeRecipientInfo(let keyAgreeRecipientInfo):
            try keyAgreeRecipientInfo.serialize(
                into: &coder,
                withIdentifier: Self.keyAgreeRecipientInfoIdentifier
            )

        case .kekRecipientInfo(let kekRecipientInfo):
            try kekRecipientInfo.serialize(into: &coder, withIdentifier: Self.kekRecipientInfoIdentifier)

        case .passwordRecipientInfo(let passwordRecipientInfo):
            try passwordRecipientInfo.serialize(into: &coder, withIdentifier: Self.passwordRecipientInfoIdentifier)

        case .otherRecipientInfo(let otherRecipientInfo):
            try otherRecipientInfo.serialize(into: &coder, withIdentifier: Self.otherRecipientInfoIdentifier)
        }
    }

    @usableFromInline
    var cmsVersion: CMSVersion {
        switch self {
        case .keyTransRecipientInfo(let keyTransRecipientInfo):
            return keyTransRecipientInfo.version
        case .keyAgreeRecipientInfo:
            return .v3
        case .kekRecipientInfo:
            return .v4
        case .passwordRecipientInfo:
            return .v0
        case .otherRecipientInfo:
            return .v0
        }
    }

    @usableFromInline
    var requiresEnvelopedDataVersion3: Bool {
        switch self {
        case .passwordRecipientInfo, .otherRecipientInfo:
            return true
        case .keyTransRecipientInfo, .keyAgreeRecipientInfo, .kekRecipientInfo:
            return false
        }
    }
}

@usableFromInline
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
struct CMSKeyTransRecipientInfo: DERImplicitlyTaggable, BERImplicitlyTaggable, Hashable, Sendable {
    @usableFromInline
    enum Error: Swift.Error {
        case versionAndRecipientIdentifierMismatch(String)
    }

    @inlinable
    static var defaultIdentifier: ASN1Identifier {
        .sequence
    }

    @usableFromInline var version: CMSVersion
    @usableFromInline var recipientIdentifier: CMSRecipientIdentifier
    @usableFromInline var keyEncryptionAlgorithm: AlgorithmIdentifier
    @usableFromInline var encryptedKey: ASN1OctetString

    @inlinable
    init(
        recipientIdentifier: CMSRecipientIdentifier,
        keyEncryptionAlgorithm: AlgorithmIdentifier,
        encryptedKey: ASN1OctetString
    ) {
        switch recipientIdentifier {
        case .issuerAndSerialNumber:
            self.version = .v0
        case .subjectKeyIdentifier:
            self.version = .v2
        }
        self.recipientIdentifier = recipientIdentifier
        self.keyEncryptionAlgorithm = keyEncryptionAlgorithm
        self.encryptedKey = encryptedKey
    }

    @inlinable
    init(
        version: CMSVersion,
        recipientIdentifier: CMSRecipientIdentifier,
        keyEncryptionAlgorithm: AlgorithmIdentifier,
        encryptedKey: ASN1OctetString
    ) {
        self.version = version
        self.recipientIdentifier = recipientIdentifier
        self.keyEncryptionAlgorithm = keyEncryptionAlgorithm
        self.encryptedKey = encryptedKey
    }

    @inlinable
    init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let version = try CMSVersion(rawValue: Int(derEncoded: &nodes))
            let recipientIdentifier = try CMSRecipientIdentifier(derEncoded: &nodes)
            try Self.validate(version: version, recipientIdentifier: recipientIdentifier)
            let keyEncryptionAlgorithm = try AlgorithmIdentifier(derEncoded: &nodes)
            let encryptedKey = try ASN1OctetString(derEncoded: &nodes)

            return .init(
                version: version,
                recipientIdentifier: recipientIdentifier,
                keyEncryptionAlgorithm: keyEncryptionAlgorithm,
                encryptedKey: encryptedKey
            )
        }
    }

    @inlinable
    init(berEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try BER.sequence(rootNode, identifier: identifier) { nodes in
            let version = try CMSVersion(rawValue: Int(berEncoded: &nodes))
            let recipientIdentifier = try CMSRecipientIdentifier(berEncoded: &nodes)
            try Self.validate(version: version, recipientIdentifier: recipientIdentifier)
            let keyEncryptionAlgorithm = try AlgorithmIdentifier(berEncoded: &nodes)
            let encryptedKey = try ASN1OctetString(berEncoded: &nodes)

            return .init(
                version: version,
                recipientIdentifier: recipientIdentifier,
                keyEncryptionAlgorithm: keyEncryptionAlgorithm,
                encryptedKey: encryptedKey
            )
        }
    }

    @inlinable
    static func validate(version: CMSVersion, recipientIdentifier: CMSRecipientIdentifier) throws {
        switch recipientIdentifier {
        case .issuerAndSerialNumber:
            guard version == .v0 else {
                throw Error.versionAndRecipientIdentifierMismatch("issuerAndSerialNumber requires CMSv0")
            }
        case .subjectKeyIdentifier:
            guard version == .v2 else {
                throw Error.versionAndRecipientIdentifierMismatch("subjectKeyIdentifier requires CMSv2")
            }
        }
    }

    @inlinable
    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(self.version.rawValue)
            try coder.serialize(self.recipientIdentifier)
            try coder.serialize(self.keyEncryptionAlgorithm)
            try coder.serialize(self.encryptedKey)
        }
    }
}

@usableFromInline
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
enum CMSRecipientIdentifier: DERParseable, BERParseable, DERSerializable, BERSerializable, Hashable, Sendable {
    @usableFromInline
    static let subjectKeyIdentifierIdentifier = ASN1Identifier(tagWithNumber: 0, tagClass: .contextSpecific)

    case issuerAndSerialNumber(CMSIssuerAndSerialNumber)
    case subjectKeyIdentifier(SubjectKeyIdentifier)

    @inlinable
    init(derEncoded node: ASN1Node) throws {
        switch node.identifier {
        case CMSIssuerAndSerialNumber.defaultIdentifier:
            self = try .issuerAndSerialNumber(.init(derEncoded: node))

        case Self.subjectKeyIdentifierIdentifier:
            self = try .subjectKeyIdentifier(
                .init(
                    keyIdentifier: ASN1OctetString(
                        derEncoded: node,
                        withIdentifier: Self.subjectKeyIdentifierIdentifier
                    ).bytes
                )
            )

        default:
            throw ASN1Error.unexpectedFieldType(node.identifier)
        }
    }

    @inlinable
    init(berEncoded node: ASN1Node) throws {
        switch node.identifier {
        case CMSIssuerAndSerialNumber.defaultIdentifier:
            self = try .issuerAndSerialNumber(.init(berEncoded: node))

        case Self.subjectKeyIdentifierIdentifier:
            self = try .subjectKeyIdentifier(
                .init(
                    keyIdentifier: ASN1OctetString(
                        berEncoded: node,
                        withIdentifier: Self.subjectKeyIdentifierIdentifier
                    ).bytes
                )
            )

        default:
            throw ASN1Error.unexpectedFieldType(node.identifier)
        }
    }

    @inlinable
    func serialize(into coder: inout DER.Serializer) throws {
        switch self {
        case .issuerAndSerialNumber(let issuerAndSerialNumber):
            try issuerAndSerialNumber.serialize(into: &coder)
        case .subjectKeyIdentifier(let subjectKeyIdentifier):
            try ASN1OctetString(contentBytes: subjectKeyIdentifier.keyIdentifier).serialize(
                into: &coder,
                withIdentifier: Self.subjectKeyIdentifierIdentifier
            )
        }
    }

    @inlinable
    init(issuerAndSerialNumber certificate: Certificate) {
        self = .issuerAndSerialNumber(.init(issuer: certificate.issuer, serialNumber: certificate.serialNumber))
    }
}

@usableFromInline
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
struct CMSKeyAgreeRecipientInfo: DERImplicitlyTaggable, BERImplicitlyTaggable, Hashable, Sendable {
    @usableFromInline
    enum Error: Swift.Error {
        case versionMustBe3(String)
    }

    @usableFromInline
    static let originatorIdentifier = ASN1Identifier(tagWithNumber: 0, tagClass: .contextSpecific)

    @usableFromInline
    static let userKeyingMaterialIdentifier = ASN1Identifier(tagWithNumber: 1, tagClass: .contextSpecific)

    @inlinable
    static var defaultIdentifier: ASN1Identifier {
        .sequence
    }

    @usableFromInline var version: CMSVersion
    @usableFromInline var originator: CMSOriginatorIdentifierOrKey
    @usableFromInline var userKeyingMaterial: ASN1OctetString?
    @usableFromInline var keyEncryptionAlgorithm: AlgorithmIdentifier
    @usableFromInline var recipientEncryptedKeys: [CMSRecipientEncryptedKey]

    @inlinable
    init(
        originator: CMSOriginatorIdentifierOrKey,
        userKeyingMaterial: ASN1OctetString? = nil,
        keyEncryptionAlgorithm: AlgorithmIdentifier,
        recipientEncryptedKeys: [CMSRecipientEncryptedKey]
    ) {
        self.version = .v3
        self.originator = originator
        self.userKeyingMaterial = userKeyingMaterial
        self.keyEncryptionAlgorithm = keyEncryptionAlgorithm
        self.recipientEncryptedKeys = recipientEncryptedKeys
    }

    @inlinable
    init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let version = try CMSVersion(rawValue: Int(derEncoded: &nodes))
            guard version == .v3 else {
                throw Error.versionMustBe3("expected CMSv3 but got \(version)")
            }

            let originator = try DER.explicitlyTagged(
                &nodes,
                tagNumber: Self.originatorIdentifier.tagNumber,
                tagClass: Self.originatorIdentifier.tagClass
            ) { node in
                try CMSOriginatorIdentifierOrKey(derEncoded: node)
            }
            let userKeyingMaterial = try DER.optionalExplicitlyTagged(
                &nodes,
                tagNumber: Self.userKeyingMaterialIdentifier.tagNumber,
                tagClass: Self.userKeyingMaterialIdentifier.tagClass
            ) { node in
                try ASN1OctetString(derEncoded: node)
            }
            let keyEncryptionAlgorithm = try AlgorithmIdentifier(derEncoded: &nodes)
            let recipientEncryptedKeys = try DER.sequence(
                of: CMSRecipientEncryptedKey.self,
                identifier: .sequence,
                nodes: &nodes
            )

            return .init(
                originator: originator,
                userKeyingMaterial: userKeyingMaterial,
                keyEncryptionAlgorithm: keyEncryptionAlgorithm,
                recipientEncryptedKeys: recipientEncryptedKeys
            )
        }
    }

    @inlinable
    init(berEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try BER.sequence(rootNode, identifier: identifier) { nodes in
            let version = try CMSVersion(rawValue: Int(berEncoded: &nodes))
            guard version == .v3 else {
                throw Error.versionMustBe3("expected CMSv3 but got \(version)")
            }

            let originator = try BER.explicitlyTagged(
                &nodes,
                tagNumber: Self.originatorIdentifier.tagNumber,
                tagClass: Self.originatorIdentifier.tagClass
            ) { node in
                try CMSOriginatorIdentifierOrKey(berEncoded: node)
            }
            let userKeyingMaterial = try BER.optionalExplicitlyTagged(
                &nodes,
                tagNumber: Self.userKeyingMaterialIdentifier.tagNumber,
                tagClass: Self.userKeyingMaterialIdentifier.tagClass
            ) { node in
                try ASN1OctetString(berEncoded: node)
            }
            let keyEncryptionAlgorithm = try AlgorithmIdentifier(berEncoded: &nodes)
            let recipientEncryptedKeys = try BER.sequence(
                of: CMSRecipientEncryptedKey.self,
                identifier: .sequence,
                nodes: &nodes
            )

            return .init(
                originator: originator,
                userKeyingMaterial: userKeyingMaterial,
                keyEncryptionAlgorithm: keyEncryptionAlgorithm,
                recipientEncryptedKeys: recipientEncryptedKeys
            )
        }
    }

    @inlinable
    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(self.version.rawValue)
            try coder.serialize(self.originator, explicitlyTaggedWithIdentifier: Self.originatorIdentifier)
            if let userKeyingMaterial {
                try coder.serialize(userKeyingMaterial, explicitlyTaggedWithIdentifier: Self.userKeyingMaterialIdentifier)
            }
            try coder.serialize(self.keyEncryptionAlgorithm)
            try coder.serializeSequenceOf(self.recipientEncryptedKeys)
        }
    }
}

@usableFromInline
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
enum CMSOriginatorIdentifierOrKey: DERParseable, BERParseable, DERSerializable, BERSerializable, Hashable, Sendable {
    @usableFromInline
    static let subjectKeyIdentifierIdentifier = ASN1Identifier(tagWithNumber: 0, tagClass: .contextSpecific)

    @usableFromInline
    static let originatorKeyIdentifier = ASN1Identifier(tagWithNumber: 1, tagClass: .contextSpecific)

    case issuerAndSerialNumber(CMSIssuerAndSerialNumber)
    case subjectKeyIdentifier(SubjectKeyIdentifier)
    case originatorKey(CMSOriginatorPublicKey)

    @inlinable
    init(derEncoded node: ASN1Node) throws {
        switch node.identifier {
        case CMSIssuerAndSerialNumber.defaultIdentifier:
            self = try .issuerAndSerialNumber(.init(derEncoded: node))

        case Self.subjectKeyIdentifierIdentifier:
            self = try .subjectKeyIdentifier(
                .init(
                    keyIdentifier: ASN1OctetString(
                        derEncoded: node,
                        withIdentifier: Self.subjectKeyIdentifierIdentifier
                    ).bytes
                )
            )

        case Self.originatorKeyIdentifier:
            self = try .originatorKey(
                .init(derEncoded: node, withIdentifier: Self.originatorKeyIdentifier)
            )

        default:
            throw ASN1Error.unexpectedFieldType(node.identifier)
        }
    }

    @inlinable
    init(berEncoded node: ASN1Node) throws {
        switch node.identifier {
        case CMSIssuerAndSerialNumber.defaultIdentifier:
            self = try .issuerAndSerialNumber(.init(berEncoded: node))

        case Self.subjectKeyIdentifierIdentifier:
            self = try .subjectKeyIdentifier(
                .init(
                    keyIdentifier: ASN1OctetString(
                        berEncoded: node,
                        withIdentifier: Self.subjectKeyIdentifierIdentifier
                    ).bytes
                )
            )

        case Self.originatorKeyIdentifier:
            self = try .originatorKey(
                .init(berEncoded: node, withIdentifier: Self.originatorKeyIdentifier)
            )

        default:
            throw ASN1Error.unexpectedFieldType(node.identifier)
        }
    }

    @inlinable
    func serialize(into coder: inout DER.Serializer) throws {
        switch self {
        case .issuerAndSerialNumber(let issuerAndSerialNumber):
            try issuerAndSerialNumber.serialize(into: &coder)
        case .subjectKeyIdentifier(let subjectKeyIdentifier):
            try ASN1OctetString(contentBytes: subjectKeyIdentifier.keyIdentifier).serialize(
                into: &coder,
                withIdentifier: Self.subjectKeyIdentifierIdentifier
            )
        case .originatorKey(let originatorKey):
            try originatorKey.serialize(into: &coder, withIdentifier: Self.originatorKeyIdentifier)
        }
    }
}

@usableFromInline
struct CMSOriginatorPublicKey: DERImplicitlyTaggable, BERImplicitlyTaggable, Hashable, Sendable {
    @inlinable
    static var defaultIdentifier: ASN1Identifier {
        .sequence
    }

    @usableFromInline var algorithmIdentifier: AlgorithmIdentifier
    @usableFromInline var key: ASN1BitString

    @inlinable
    init(algorithmIdentifier: AlgorithmIdentifier, key: ASN1BitString) {
        self.algorithmIdentifier = algorithmIdentifier
        self.key = key
    }

    @inlinable
    init(algorithmIdentifier: AlgorithmIdentifier, key: [UInt8]) {
        self.init(algorithmIdentifier: algorithmIdentifier, key: ASN1BitString(bytes: key[...]))
    }

    @inlinable
    init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let algorithmIdentifier = try AlgorithmIdentifier(derEncoded: &nodes)
            let key = try ASN1BitString(derEncoded: &nodes)
            return .init(algorithmIdentifier: algorithmIdentifier, key: key)
        }
    }

    @inlinable
    init(berEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try BER.sequence(rootNode, identifier: identifier) { nodes in
            let algorithmIdentifier = try AlgorithmIdentifier(berEncoded: &nodes)
            let key = try ASN1BitString(berEncoded: &nodes)
            return .init(algorithmIdentifier: algorithmIdentifier, key: key)
        }
    }

    @inlinable
    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(self.algorithmIdentifier)
            try coder.serialize(self.key)
        }
    }
}

@usableFromInline
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
struct CMSRecipientEncryptedKey: DERImplicitlyTaggable, BERImplicitlyTaggable, Hashable, Sendable {
    @inlinable
    static var defaultIdentifier: ASN1Identifier {
        .sequence
    }

    @usableFromInline var recipientIdentifier: CMSKeyAgreeRecipientIdentifier
    @usableFromInline var encryptedKey: ASN1OctetString

    @inlinable
    init(recipientIdentifier: CMSKeyAgreeRecipientIdentifier, encryptedKey: ASN1OctetString) {
        self.recipientIdentifier = recipientIdentifier
        self.encryptedKey = encryptedKey
    }

    @inlinable
    init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let recipientIdentifier = try CMSKeyAgreeRecipientIdentifier(derEncoded: &nodes)
            let encryptedKey = try ASN1OctetString(derEncoded: &nodes)
            return .init(recipientIdentifier: recipientIdentifier, encryptedKey: encryptedKey)
        }
    }

    @inlinable
    init(berEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try BER.sequence(rootNode, identifier: identifier) { nodes in
            let recipientIdentifier = try CMSKeyAgreeRecipientIdentifier(berEncoded: &nodes)
            let encryptedKey = try ASN1OctetString(berEncoded: &nodes)
            return .init(recipientIdentifier: recipientIdentifier, encryptedKey: encryptedKey)
        }
    }

    @inlinable
    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(self.recipientIdentifier)
            try coder.serialize(self.encryptedKey)
        }
    }
}

@usableFromInline
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
enum CMSKeyAgreeRecipientIdentifier: DERParseable, BERParseable, DERSerializable, BERSerializable, Hashable, Sendable {
    @usableFromInline
    static let recipientKeyIdentifierIdentifier = ASN1Identifier(tagWithNumber: 0, tagClass: .contextSpecific)

    case issuerAndSerialNumber(CMSIssuerAndSerialNumber)
    case recipientKeyIdentifier(CMSRecipientKeyIdentifier)

    @inlinable
    init(derEncoded node: ASN1Node) throws {
        switch node.identifier {
        case CMSIssuerAndSerialNumber.defaultIdentifier:
            self = try .issuerAndSerialNumber(.init(derEncoded: node))
        case Self.recipientKeyIdentifierIdentifier:
            self = try .recipientKeyIdentifier(
                .init(derEncoded: node, withIdentifier: Self.recipientKeyIdentifierIdentifier)
            )
        default:
            throw ASN1Error.unexpectedFieldType(node.identifier)
        }
    }

    @inlinable
    init(berEncoded node: ASN1Node) throws {
        switch node.identifier {
        case CMSIssuerAndSerialNumber.defaultIdentifier:
            self = try .issuerAndSerialNumber(.init(berEncoded: node))
        case Self.recipientKeyIdentifierIdentifier:
            self = try .recipientKeyIdentifier(
                .init(berEncoded: node, withIdentifier: Self.recipientKeyIdentifierIdentifier)
            )
        default:
            throw ASN1Error.unexpectedFieldType(node.identifier)
        }
    }

    @inlinable
    func serialize(into coder: inout DER.Serializer) throws {
        switch self {
        case .issuerAndSerialNumber(let issuerAndSerialNumber):
            try issuerAndSerialNumber.serialize(into: &coder)
        case .recipientKeyIdentifier(let recipientKeyIdentifier):
            try recipientKeyIdentifier.serialize(
                into: &coder,
                withIdentifier: Self.recipientKeyIdentifierIdentifier
            )
        }
    }
}

@usableFromInline
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
struct CMSRecipientKeyIdentifier: DERImplicitlyTaggable, BERImplicitlyTaggable, Hashable, Sendable {
    @inlinable
    static var defaultIdentifier: ASN1Identifier {
        .sequence
    }

    @usableFromInline var subjectKeyIdentifier: SubjectKeyIdentifier
    @usableFromInline var date: GeneralizedTime?
    @usableFromInline var other: CMSOtherKeyAttribute?

    @inlinable
    init(
        subjectKeyIdentifier: SubjectKeyIdentifier,
        date: GeneralizedTime? = nil,
        other: CMSOtherKeyAttribute? = nil
    ) {
        self.subjectKeyIdentifier = subjectKeyIdentifier
        self.date = date
        self.other = other
    }

    @inlinable
    init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let subjectKeyIdentifier = SubjectKeyIdentifier(
                keyIdentifier: try ASN1OctetString(derEncoded: &nodes).bytes
            )
            let date = try Self.nextDate(&nodes) { node in
                try GeneralizedTime(derEncoded: node)
            }
            let other = try Self.nextOtherKeyAttribute(&nodes) { node in
                try CMSOtherKeyAttribute(derEncoded: node)
            }
            return .init(subjectKeyIdentifier: subjectKeyIdentifier, date: date, other: other)
        }
    }

    @inlinable
    init(berEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try BER.sequence(rootNode, identifier: identifier) { nodes in
            let subjectKeyIdentifier = SubjectKeyIdentifier(
                keyIdentifier: try ASN1OctetString(berEncoded: &nodes).bytes
            )
            let date = try Self.nextDate(&nodes) { node in
                try GeneralizedTime(berEncoded: node)
            }
            let other = try Self.nextOtherKeyAttribute(&nodes) { node in
                try CMSOtherKeyAttribute(berEncoded: node)
            }
            return .init(subjectKeyIdentifier: subjectKeyIdentifier, date: date, other: other)
        }
    }

    @inlinable
    static func nextDate(
        _ nodes: inout ASN1NodeCollection.Iterator,
        using parser: (ASN1Node) throws -> GeneralizedTime
    ) throws -> GeneralizedTime? {
        var localNodes = nodes
        guard let node = localNodes.next(), node.identifier == .generalizedTime else {
            return nil
        }
        nodes = localNodes
        return try parser(node)
    }

    @inlinable
    static func nextOtherKeyAttribute(
        _ nodes: inout ASN1NodeCollection.Iterator,
        using parser: (ASN1Node) throws -> CMSOtherKeyAttribute
    ) throws -> CMSOtherKeyAttribute? {
        var localNodes = nodes
        guard let node = localNodes.next(), node.identifier == CMSOtherKeyAttribute.defaultIdentifier else {
            return nil
        }
        nodes = localNodes
        return try parser(node)
    }

    @inlinable
    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(ASN1OctetString(contentBytes: self.subjectKeyIdentifier.keyIdentifier))
            if let date {
                try coder.serialize(date)
            }
            if let other {
                try coder.serialize(other)
            }
        }
    }
}

@usableFromInline
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
struct CMSKEKRecipientInfo: DERImplicitlyTaggable, BERImplicitlyTaggable, Hashable, Sendable {
    @usableFromInline
    enum Error: Swift.Error {
        case versionMustBe4(String)
    }

    @inlinable
    static var defaultIdentifier: ASN1Identifier {
        .sequence
    }

    @usableFromInline var version: CMSVersion
    @usableFromInline var kekIdentifier: CMSKEKIdentifier
    @usableFromInline var keyEncryptionAlgorithm: AlgorithmIdentifier
    @usableFromInline var encryptedKey: ASN1OctetString

    @inlinable
    init(
        kekIdentifier: CMSKEKIdentifier,
        keyEncryptionAlgorithm: AlgorithmIdentifier,
        encryptedKey: ASN1OctetString
    ) {
        self.version = .v4
        self.kekIdentifier = kekIdentifier
        self.keyEncryptionAlgorithm = keyEncryptionAlgorithm
        self.encryptedKey = encryptedKey
    }

    @inlinable
    init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let version = try CMSVersion(rawValue: Int(derEncoded: &nodes))
            guard version == .v4 else {
                throw Error.versionMustBe4("expected CMSv4 but got \(version)")
            }
            let kekIdentifier = try CMSKEKIdentifier(derEncoded: &nodes)
            let keyEncryptionAlgorithm = try AlgorithmIdentifier(derEncoded: &nodes)
            let encryptedKey = try ASN1OctetString(derEncoded: &nodes)
            return .init(
                kekIdentifier: kekIdentifier,
                keyEncryptionAlgorithm: keyEncryptionAlgorithm,
                encryptedKey: encryptedKey
            )
        }
    }

    @inlinable
    init(berEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try BER.sequence(rootNode, identifier: identifier) { nodes in
            let version = try CMSVersion(rawValue: Int(berEncoded: &nodes))
            guard version == .v4 else {
                throw Error.versionMustBe4("expected CMSv4 but got \(version)")
            }
            let kekIdentifier = try CMSKEKIdentifier(berEncoded: &nodes)
            let keyEncryptionAlgorithm = try AlgorithmIdentifier(berEncoded: &nodes)
            let encryptedKey = try ASN1OctetString(berEncoded: &nodes)
            return .init(
                kekIdentifier: kekIdentifier,
                keyEncryptionAlgorithm: keyEncryptionAlgorithm,
                encryptedKey: encryptedKey
            )
        }
    }

    @inlinable
    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(self.version.rawValue)
            try coder.serialize(self.kekIdentifier)
            try coder.serialize(self.keyEncryptionAlgorithm)
            try coder.serialize(self.encryptedKey)
        }
    }
}

@usableFromInline
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
struct CMSKEKIdentifier: DERImplicitlyTaggable, BERImplicitlyTaggable, Hashable, Sendable {
    @inlinable
    static var defaultIdentifier: ASN1Identifier {
        .sequence
    }

    @usableFromInline var keyIdentifier: ASN1OctetString
    @usableFromInline var date: GeneralizedTime?
    @usableFromInline var other: CMSOtherKeyAttribute?

    @inlinable
    init(keyIdentifier: ASN1OctetString, date: GeneralizedTime? = nil, other: CMSOtherKeyAttribute? = nil) {
        self.keyIdentifier = keyIdentifier
        self.date = date
        self.other = other
    }

    @inlinable
    init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let keyIdentifier = try ASN1OctetString(derEncoded: &nodes)
            let date = try CMSRecipientKeyIdentifier.nextDate(&nodes) { node in
                try GeneralizedTime(derEncoded: node)
            }
            let other = try CMSRecipientKeyIdentifier.nextOtherKeyAttribute(&nodes) { node in
                try CMSOtherKeyAttribute(derEncoded: node)
            }
            return .init(keyIdentifier: keyIdentifier, date: date, other: other)
        }
    }

    @inlinable
    init(berEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try BER.sequence(rootNode, identifier: identifier) { nodes in
            let keyIdentifier = try ASN1OctetString(berEncoded: &nodes)
            let date = try CMSRecipientKeyIdentifier.nextDate(&nodes) { node in
                try GeneralizedTime(berEncoded: node)
            }
            let other = try CMSRecipientKeyIdentifier.nextOtherKeyAttribute(&nodes) { node in
                try CMSOtherKeyAttribute(berEncoded: node)
            }
            return .init(keyIdentifier: keyIdentifier, date: date, other: other)
        }
    }

    @inlinable
    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(self.keyIdentifier)
            if let date {
                try coder.serialize(date)
            }
            if let other {
                try coder.serialize(other)
            }
        }
    }
}

@usableFromInline
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
struct CMSPasswordRecipientInfo: DERImplicitlyTaggable, BERImplicitlyTaggable, Hashable, Sendable {
    @usableFromInline
    enum Error: Swift.Error {
        case versionMustBe0(String)
    }

    @usableFromInline
    static let keyDerivationAlgorithmIdentifier = ASN1Identifier(tagWithNumber: 0, tagClass: .contextSpecific)

    @inlinable
    static var defaultIdentifier: ASN1Identifier {
        .sequence
    }

    @usableFromInline var version: CMSVersion
    @usableFromInline var keyDerivationAlgorithm: AlgorithmIdentifier?
    @usableFromInline var keyEncryptionAlgorithm: AlgorithmIdentifier
    @usableFromInline var encryptedKey: ASN1OctetString

    @inlinable
    init(
        keyDerivationAlgorithm: AlgorithmIdentifier? = nil,
        keyEncryptionAlgorithm: AlgorithmIdentifier,
        encryptedKey: ASN1OctetString
    ) {
        self.version = .v0
        self.keyDerivationAlgorithm = keyDerivationAlgorithm
        self.keyEncryptionAlgorithm = keyEncryptionAlgorithm
        self.encryptedKey = encryptedKey
    }

    @inlinable
    init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let version = try CMSVersion(rawValue: Int(derEncoded: &nodes))
            guard version == .v0 else {
                throw Error.versionMustBe0("expected CMSv0 but got \(version)")
            }
            let keyDerivationAlgorithm = try DER.optionalImplicitlyTagged(
                &nodes,
                tagNumber: Self.keyDerivationAlgorithmIdentifier.tagNumber,
                tagClass: Self.keyDerivationAlgorithmIdentifier.tagClass
            ) { node in
                try AlgorithmIdentifier(derEncoded: node, withIdentifier: Self.keyDerivationAlgorithmIdentifier)
            }
            let keyEncryptionAlgorithm = try AlgorithmIdentifier(derEncoded: &nodes)
            let encryptedKey = try ASN1OctetString(derEncoded: &nodes)
            return .init(
                keyDerivationAlgorithm: keyDerivationAlgorithm,
                keyEncryptionAlgorithm: keyEncryptionAlgorithm,
                encryptedKey: encryptedKey
            )
        }
    }

    @inlinable
    init(berEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try BER.sequence(rootNode, identifier: identifier) { nodes in
            let version = try CMSVersion(rawValue: Int(berEncoded: &nodes))
            guard version == .v0 else {
                throw Error.versionMustBe0("expected CMSv0 but got \(version)")
            }
            let keyDerivationAlgorithm = try BER.optionalImplicitlyTagged(
                &nodes,
                tagNumber: Self.keyDerivationAlgorithmIdentifier.tagNumber,
                tagClass: Self.keyDerivationAlgorithmIdentifier.tagClass
            ) { node in
                try AlgorithmIdentifier(berEncoded: node, withIdentifier: Self.keyDerivationAlgorithmIdentifier)
            }
            let keyEncryptionAlgorithm = try AlgorithmIdentifier(berEncoded: &nodes)
            let encryptedKey = try ASN1OctetString(berEncoded: &nodes)
            return .init(
                keyDerivationAlgorithm: keyDerivationAlgorithm,
                keyEncryptionAlgorithm: keyEncryptionAlgorithm,
                encryptedKey: encryptedKey
            )
        }
    }

    @inlinable
    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(self.version.rawValue)
            if let keyDerivationAlgorithm {
                try keyDerivationAlgorithm.serialize(into: &coder, withIdentifier: Self.keyDerivationAlgorithmIdentifier)
            }
            try coder.serialize(self.keyEncryptionAlgorithm)
            try coder.serialize(self.encryptedKey)
        }
    }
}

@usableFromInline
struct CMSOtherRecipientInfo: DERImplicitlyTaggable, BERImplicitlyTaggable, Hashable, Sendable {
    @inlinable
    static var defaultIdentifier: ASN1Identifier {
        .sequence
    }

    @usableFromInline var type: ASN1ObjectIdentifier
    @usableFromInline var value: ASN1Any

    @inlinable
    init(type: ASN1ObjectIdentifier, value: ASN1Any) {
        self.type = type
        self.value = value
    }

    @inlinable
    init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let type = try ASN1ObjectIdentifier(derEncoded: &nodes)
            let value = try ASN1Any(derEncoded: &nodes)
            return .init(type: type, value: value)
        }
    }

    @inlinable
    init(berEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try BER.sequence(rootNode, identifier: identifier) { nodes in
            let type = try ASN1ObjectIdentifier(berEncoded: &nodes)
            let value = try ASN1Any(berEncoded: &nodes)
            return .init(type: type, value: value)
        }
    }

    @inlinable
    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(self.type)
            try coder.serialize(self.value)
        }
    }
}

@usableFromInline
struct CMSOtherKeyAttribute: DERImplicitlyTaggable, BERImplicitlyTaggable, Hashable, Sendable {
    @inlinable
    static var defaultIdentifier: ASN1Identifier {
        .sequence
    }

    @usableFromInline var keyAttributeIdentifier: ASN1ObjectIdentifier
    @usableFromInline var keyAttribute: ASN1Any?

    @inlinable
    init(keyAttributeIdentifier: ASN1ObjectIdentifier, keyAttribute: ASN1Any? = nil) {
        self.keyAttributeIdentifier = keyAttributeIdentifier
        self.keyAttribute = keyAttribute
    }

    @inlinable
    init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let keyAttributeIdentifier = try ASN1ObjectIdentifier(derEncoded: &nodes)
            let keyAttribute = nodes.next().map(ASN1Any.init(derEncoded:))
            return .init(keyAttributeIdentifier: keyAttributeIdentifier, keyAttribute: keyAttribute)
        }
    }

    @inlinable
    init(berEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try BER.sequence(rootNode, identifier: identifier) { nodes in
            let keyAttributeIdentifier = try ASN1ObjectIdentifier(berEncoded: &nodes)
            let keyAttribute = nodes.next().map(ASN1Any.init(berEncoded:))
            return .init(keyAttributeIdentifier: keyAttributeIdentifier, keyAttribute: keyAttribute)
        }
    }

    @inlinable
    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(self.keyAttributeIdentifier)
            if let keyAttribute {
                try coder.serialize(keyAttribute)
            }
        }
    }
}

@usableFromInline
struct CMSRSAESOAEPParams: DERImplicitlyTaggable, BERImplicitlyTaggable, Hashable, Sendable {
    @usableFromInline
    static let hashAlgorithmIdentifier = ASN1Identifier(tagWithNumber: 0, tagClass: .contextSpecific)

    @usableFromInline
    static let maskGenAlgorithmIdentifier = ASN1Identifier(tagWithNumber: 1, tagClass: .contextSpecific)

    @usableFromInline
    static let pSourceAlgorithmIdentifier = ASN1Identifier(tagWithNumber: 2, tagClass: .contextSpecific)

    @inlinable
    static var defaultIdentifier: ASN1Identifier {
        .sequence
    }

    @usableFromInline var hashAlgorithm: AlgorithmIdentifier
    @usableFromInline var maskGenAlgorithm: AlgorithmIdentifier
    @usableFromInline var pSourceAlgorithm: AlgorithmIdentifier

    @inlinable
    init(
        hashAlgorithm: AlgorithmIdentifier = .sha1,
        maskGenAlgorithm: AlgorithmIdentifier = .cmsMGF1WithSHA1,
        pSourceAlgorithm: AlgorithmIdentifier = .cmsPSpecifiedEmpty
    ) {
        self.hashAlgorithm = hashAlgorithm
        self.maskGenAlgorithm = maskGenAlgorithm
        self.pSourceAlgorithm = pSourceAlgorithm
    }

    @inlinable
    init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let hashAlgorithm = try DER.optionalExplicitlyTagged(
                &nodes,
                tagNumber: Self.hashAlgorithmIdentifier.tagNumber,
                tagClass: Self.hashAlgorithmIdentifier.tagClass
            ) { node in
                try AlgorithmIdentifier(derEncoded: node)
            } ?? .sha1
            let maskGenAlgorithm = try DER.optionalExplicitlyTagged(
                &nodes,
                tagNumber: Self.maskGenAlgorithmIdentifier.tagNumber,
                tagClass: Self.maskGenAlgorithmIdentifier.tagClass
            ) { node in
                try AlgorithmIdentifier(derEncoded: node)
            } ?? .cmsMGF1WithSHA1
            let pSourceAlgorithm = try DER.optionalExplicitlyTagged(
                &nodes,
                tagNumber: Self.pSourceAlgorithmIdentifier.tagNumber,
                tagClass: Self.pSourceAlgorithmIdentifier.tagClass
            ) { node in
                try AlgorithmIdentifier(derEncoded: node)
            } ?? .cmsPSpecifiedEmpty

            return .init(
                hashAlgorithm: hashAlgorithm,
                maskGenAlgorithm: maskGenAlgorithm,
                pSourceAlgorithm: pSourceAlgorithm
            )
        }
    }

    @inlinable
    init(berEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try BER.sequence(rootNode, identifier: identifier) { nodes in
            let hashAlgorithm = try BER.optionalExplicitlyTagged(
                &nodes,
                tagNumber: Self.hashAlgorithmIdentifier.tagNumber,
                tagClass: Self.hashAlgorithmIdentifier.tagClass
            ) { node in
                try AlgorithmIdentifier(berEncoded: node)
            } ?? .sha1
            let maskGenAlgorithm = try BER.optionalExplicitlyTagged(
                &nodes,
                tagNumber: Self.maskGenAlgorithmIdentifier.tagNumber,
                tagClass: Self.maskGenAlgorithmIdentifier.tagClass
            ) { node in
                try AlgorithmIdentifier(berEncoded: node)
            } ?? .cmsMGF1WithSHA1
            let pSourceAlgorithm = try BER.optionalExplicitlyTagged(
                &nodes,
                tagNumber: Self.pSourceAlgorithmIdentifier.tagNumber,
                tagClass: Self.pSourceAlgorithmIdentifier.tagClass
            ) { node in
                try AlgorithmIdentifier(berEncoded: node)
            } ?? .cmsPSpecifiedEmpty

            return .init(
                hashAlgorithm: hashAlgorithm,
                maskGenAlgorithm: maskGenAlgorithm,
                pSourceAlgorithm: pSourceAlgorithm
            )
        }
    }

    @inlinable
    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            if self.hashAlgorithm != .sha1 {
                try coder.serialize(self.hashAlgorithm, explicitlyTaggedWithIdentifier: Self.hashAlgorithmIdentifier)
            }
            if self.maskGenAlgorithm != .cmsMGF1WithSHA1 {
                try coder.serialize(self.maskGenAlgorithm, explicitlyTaggedWithIdentifier: Self.maskGenAlgorithmIdentifier)
            }
            if self.pSourceAlgorithm != .cmsPSpecifiedEmpty {
                try coder.serialize(self.pSourceAlgorithm, explicitlyTaggedWithIdentifier: Self.pSourceAlgorithmIdentifier)
            }
        }
    }
}
@usableFromInline
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
struct CMSPBKDF2Params: DERImplicitlyTaggable, BERImplicitlyTaggable, Hashable, Sendable {
    @inlinable
    static var defaultIdentifier: ASN1Identifier {
        .sequence
    }

    @usableFromInline var salt: ASN1OctetString
    @usableFromInline var iterationCount: Int
    @usableFromInline var keyLength: Int?
    @usableFromInline var prf: AlgorithmIdentifier

    @inlinable
    init(
        salt: ASN1OctetString,
        iterationCount: Int,
        keyLength: Int? = 32,
        prf: AlgorithmIdentifier = .hmacWithSHA1
    ) {
        self.salt = salt
        self.iterationCount = iterationCount
        self.keyLength = keyLength
        self.prf = prf
    }

    @inlinable
    init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let salt = try ASN1OctetString(derEncoded: &nodes)
            let iterationCount = try Int(derEncoded: &nodes)
            let keyLength: Int? = try DER.optionalImplicitlyTagged(&nodes)
            let prf: AlgorithmIdentifier = try DER.optionalImplicitlyTagged(&nodes) ?? .hmacWithSHA1

            return .init(
                salt: salt,
                iterationCount: iterationCount,
                keyLength: keyLength,
                prf: prf
            )
        }
    }

    @inlinable
    init(berEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try BER.sequence(rootNode, identifier: identifier) { nodes in
            let salt = try ASN1OctetString(berEncoded: &nodes)
            let iterationCount = try Int(berEncoded: &nodes)
            let keyLength: Int? = try BER.optionalImplicitlyTagged(&nodes)
            let prf: AlgorithmIdentifier = try BER.optionalImplicitlyTagged(&nodes) ?? .hmacWithSHA1

            return .init(
                salt: salt,
                iterationCount: iterationCount,
                keyLength: keyLength,
                prf: prf
            )
        }
    }

    @inlinable
    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(self.salt)
            try coder.serialize(self.iterationCount)
            if let keyLength {
                try coder.serialize(keyLength)
            }
            if self.prf.algorithm != .AlgorithmIdentifier.hmacWithSHA1 {
                try coder.serialize(self.prf)
            }
        }
    }
}

