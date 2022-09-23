//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCertificate open source project
//
// Copyright (c) 2022 Apple Inc. and the SwiftCertificate project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.md for the list of SwiftCertificate project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import SwiftASN1

@usableFromInline
struct SubjectPublicKeyInfo: ASN1ImplicitlyTaggable, Hashable, Sendable {
    @inlinable
    static var defaultIdentifier: ASN1.ASN1Identifier {
        .sequence
    }

    @usableFromInline
    var algorithmIdentifier: AlgorithmIdentifier

    @usableFromInline
    var key: ASN1.ASN1BitString

    @inlinable
    init(asn1Encoded rootNode: ASN1.ASN1Node, withIdentifier identifier: ASN1.ASN1Identifier) throws {
        // The SPKI block looks like this:
        //
        // SubjectPublicKeyInfo  ::=  SEQUENCE  {
        //   algorithm         AlgorithmIdentifier,
        //   subjectPublicKey  BIT STRING
        // }
        self = try ASN1.sequence(rootNode, identifier: identifier) { nodes in
            let algorithmIdentifier = try AlgorithmIdentifier(asn1Encoded: &nodes)
            let key = try ASN1.ASN1BitString(asn1Encoded: &nodes)

            return SubjectPublicKeyInfo(algorithmIdentifier: algorithmIdentifier, key: key)
        }
    }

    @inlinable
    init(algorithmIdentifier: AlgorithmIdentifier, key: ASN1.ASN1BitString) {
        self.algorithmIdentifier = algorithmIdentifier
        self.key = key
    }

    @inlinable
    internal init(algorithmIdentifier: AlgorithmIdentifier, key: [UInt8]) {
        self.algorithmIdentifier = algorithmIdentifier
        self.key = ASN1.ASN1BitString(bytes: key[...])
    }

    @inlinable
    func serialize(into coder: inout ASN1.Serializer, withIdentifier identifier: ASN1.ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(self.algorithmIdentifier)
            try coder.serialize(self.key)
        }
    }
}
