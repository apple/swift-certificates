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

// For PKCS#8 we need the following for the private key:
//
// PrivateKeyInfo ::= SEQUENCE {
//   version                   Version,
//   privateKeyAlgorithm       PrivateKeyAlgorithmIdentifier,
//   privateKey                PrivateKey,
//   attributes           [0]  IMPLICIT Attributes OPTIONAL }
//
// Version ::= INTEGER
//
// PrivateKeyAlgorithmIdentifier ::= AlgorithmIdentifier
//
// PrivateKey ::= OCTET STRING
//
// Attributes ::= SET OF Attribute
//
// We disregard the attributes because we don't support them anyway.
//
@usableFromInline
struct PKCS8PrivateKey: DERImplicitlyTaggable, Sendable {
    @inlinable
    static var defaultIdentifier: ASN1Identifier {
        return .sequence
    }

    @usableFromInline
    var algorithm: AlgorithmIdentifier

    @usableFromInline
    var privateKey: ASN1OctetString

    @inlinable
    init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let version = try Int(derEncoded: &nodes)
            guard version == 0 else {
                throw ASN1Error.invalidASN1Object(reason: "Invalid version")
            }

            let algorithm = try AlgorithmIdentifier(derEncoded: &nodes)
            let privateKeyBytes = try ASN1OctetString(derEncoded: &nodes)

            // We ignore the attributes
            _ = try DER.optionalExplicitlyTagged(&nodes, tagNumber: 0, tagClass: .contextSpecific) { _ in }

            return .init(algorithm: algorithm, privateKey: privateKeyBytes)
        }
    }

    @inlinable
    init(algorithm: AlgorithmIdentifier, privateKey: ASN1OctetString) {
        self.privateKey = privateKey
        self.algorithm = algorithm
    }

    @inlinable
    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(0)  // version
            try coder.serialize(self.algorithm)

            // Here's a weird one: we recursively serialize the private key, and then turn the bytes into an octet string.
            var subCoder = DER.Serializer()
            try subCoder.serialize(self.privateKey)
            let serializedKey = ASN1OctetString(contentBytes: subCoder.serializedBytes[...])

            try coder.serialize(serializedKey)
        }
    }
}
