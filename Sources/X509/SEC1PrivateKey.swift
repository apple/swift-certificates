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

//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftASN1 open source project
//
// Copyright (c) 2019-2020 Apple Inc. and the SwiftASN1 project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftASN1 project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import SwiftASN1

// For private keys, SEC 1 uses:
//
// ECPrivateKey ::= SEQUENCE {
//   version INTEGER { ecPrivkeyVer1(1) } (ecPrivkeyVer1),
//   privateKey OCTET STRING,
//   parameters [0] EXPLICIT ECDomainParameters OPTIONAL,
//   publicKey [1] EXPLICIT BIT STRING OPTIONAL
// }
@usableFromInline
struct SEC1PrivateKey: DERImplicitlyTaggable, PEMRepresentable, Sendable {
    @usableFromInline
    static let defaultPEMDiscriminator: String = "EC PRIVATE KEY"

    @inlinable
    static var defaultIdentifier: ASN1Identifier {
        return .sequence
    }

    @usableFromInline
    var algorithm: AlgorithmIdentifier?

    @usableFromInline
    var privateKey: ASN1OctetString

    @usableFromInline
    var publicKey: ASN1BitString?

    @inlinable
    init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let version = try Int(derEncoded: &nodes)
            guard 1 == version else {
                throw ASN1Error.invalidASN1Object(reason: "Invalid version \(version)")
            }

            let privateKey = try ASN1OctetString(derEncoded: &nodes)
            let parameters = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 0, tagClass: .contextSpecific) {
                node in
                return try ASN1ObjectIdentifier(derEncoded: node)
            }
            let publicKey = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 1, tagClass: .contextSpecific) { node in
                return try ASN1BitString(derEncoded: node)
            }

            return try .init(privateKey: privateKey, algorithm: parameters, publicKey: publicKey)
        }
    }

    @inlinable
    internal init(privateKey: ASN1OctetString, algorithm: ASN1ObjectIdentifier?, publicKey: ASN1BitString?) throws {
        self.privateKey = privateKey
        self.publicKey = publicKey
        self.algorithm = try algorithm.map { algorithmOID in
            switch algorithmOID {
            case ASN1ObjectIdentifier.NamedCurves.secp256r1:
                return .ecdsaP256
            case ASN1ObjectIdentifier.NamedCurves.secp384r1:
                return .ecdsaP384
            case ASN1ObjectIdentifier.NamedCurves.secp521r1:
                return .ecdsaP521
            default:
                throw ASN1Error.invalidASN1Object(reason: "Invalid algorithm ID")
            }
        }
    }

    @inlinable
    init(privateKey: [UInt8], algorithm: AlgorithmIdentifier?, publicKey: [UInt8]) {
        self.privateKey = ASN1OctetString(contentBytes: privateKey[...])
        self.algorithm = algorithm
        self.publicKey = ASN1BitString(bytes: publicKey[...])
    }

    @inlinable
    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(1)  // version
            try coder.serialize(self.privateKey)

            if let algorithm = self.algorithm {
                let oid: ASN1ObjectIdentifier
                switch algorithm {
                case .ecdsaP256:
                    oid = ASN1ObjectIdentifier.NamedCurves.secp256r1
                case .ecdsaP384:
                    oid = ASN1ObjectIdentifier.NamedCurves.secp384r1
                case .ecdsaP521:
                    oid = ASN1ObjectIdentifier.NamedCurves.secp521r1
                default:
                    throw ASN1Error.invalidASN1Object(reason: "Unsupported algorithm")
                }

                try coder.serialize(oid, explicitlyTaggedWithTagNumber: 0, tagClass: .contextSpecific)
            }

            if let publicKey = self.publicKey {
                try coder.serialize(publicKey, explicitlyTaggedWithTagNumber: 1, tagClass: .contextSpecific)
            }
        }
    }
}
