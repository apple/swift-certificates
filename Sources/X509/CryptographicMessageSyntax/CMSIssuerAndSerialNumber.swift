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

/// ``CMSIssuerAndSerialNumber`` is defined in ASN.1 as:
/// ```
/// IssuerAndSerialNumber ::= SEQUENCE {
///         issuer Name,
///         serialNumber CertificateSerialNumber }
/// ```
/// The definition of `Name` is taken from X.501 [X.501-88], and the
/// definition of `CertificateSerialNumber` is taken from X.509 [X.509-97].
@usableFromInline
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
struct CMSIssuerAndSerialNumber: DERImplicitlyTaggable, Hashable, Sendable {
    @inlinable
    static var defaultIdentifier: ASN1Identifier {
        .sequence
    }

    @usableFromInline var issuer: DistinguishedName
    @usableFromInline var serialNumber: Certificate.SerialNumber

    @inlinable
    init(
        issuer: DistinguishedName,
        serialNumber: Certificate.SerialNumber
    ) {
        self.issuer = issuer
        self.serialNumber = serialNumber
    }

    @inlinable
    init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let issuer = try DistinguishedName.derEncoded(&nodes)
            let serialNumber = try ArraySlice<UInt8>(derEncoded: &nodes)
            return .init(issuer: issuer, serialNumber: .init(bytes: serialNumber))
        }
    }

    @inlinable
    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(self.issuer)
            try coder.serialize(self.serialNumber.bytes)
        }
    }
}
