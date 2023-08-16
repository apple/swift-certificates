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

/// An RSA PKCS1 Public Key looks like this:
///
/// ```
/// RSAPublicKey ::= SEQUENCE {
///     modulus           INTEGER,  -- n
///     publicExponent    INTEGER   -- e
/// }
/// ```
///
/// This type can decode that format.
@usableFromInline
struct RSAPKCS1PublicKey: DERImplicitlyTaggable, Hashable, Sendable {
    @inlinable
    static var defaultIdentifier: ASN1Identifier {
        .sequence
    }

    @usableFromInline
    var modulus: ArraySlice<UInt8>

    @usableFromInline
    var publicExponent: ArraySlice<UInt8>

    @inlinable
    init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let modulus = try ArraySlice(derEncoded: &nodes)
            let publicExponent = try ArraySlice(derEncoded: &nodes)

            return RSAPKCS1PublicKey(modulus: modulus, publicExponent: publicExponent)
        }
    }

    @inlinable
    init(modulus: ArraySlice<UInt8>, publicExponent: ArraySlice<UInt8>) {
        self.modulus = modulus
        self.publicExponent = publicExponent
    }

    @inlinable
    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(self.modulus)
            try coder.serialize(self.publicExponent)
        }
    }
}
