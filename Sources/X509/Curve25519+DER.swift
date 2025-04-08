//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCertificates open source project
//
// Copyright (c) 2024 Apple Inc. and the SwiftCertificates project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCertificates project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import SwiftASN1
import Crypto

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Curve25519.Signing.PrivateKey {
    @inlinable
    init(pkcs8Key: PKCS8PrivateKey) throws {
        // Annoyingly, the PKCS8 key has the raw bytes wrapped inside an octet string.
        let rawRepresentation = try ASN1OctetString(derEncoded: pkcs8Key.privateKey.bytes)
        self = try .init(rawRepresentation: rawRepresentation.bytes)
    }

    @inlinable
    var derRepresentation: [UInt8] {
        // The DER representation we want is a PKCS8 private key. Somewhat annoyingly
        // for us, we have to wrap the key bytes in an extra layer of ASN1OctetString
        // which we encode separately.
        let pkcs8Key = PKCS8PrivateKey(
            algorithm: .ed25519,
            privateKey: ASN1OctetString(contentBytes: ArraySlice(self.rawRepresentation))
        )
        var serializer = DER.Serializer()
        try! serializer.serialize(pkcs8Key)
        return serializer.serializedBytes
    }

    @inlinable
    var pemRepresentation: PEMDocument {
        return PEMDocument(type: "PRIVATE KEY", derBytes: self.derRepresentation)
    }
}
