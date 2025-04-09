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

/// ``OCSPNonce`` is defined in ASN.1 as:
/// ```
/// Nonce ::= OCTET STRING(SIZE(1..32))
/// ```
/// RFC: https://www.rfc-editor.org/rfc/rfc8954.html
struct OCSPNonce: DERImplicitlyTaggable, Hashable, Sendable {
    static var defaultIdentifier: ASN1Identifier {
        ASN1OctetString.defaultIdentifier
    }
    var rawValue: ASN1OctetString

    init() {
        var generator = SystemRandomNumberGenerator()
        self.init(generator: &generator)
    }

    init(generator: inout some RandomNumberGenerator) {
        self.rawValue = .init(contentBytes: generator.bytes(count: 32))
    }

    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    init(_ ext: Certificate.Extension) throws {
        guard ext.oid == .OCSPExtensionID.nonceIdentifier else {
            throw CertificateError.incorrectOIDForExtension(
                reason: "Expected \(ASN1ObjectIdentifier.OCSPExtensionID.nonceIdentifier), got \(ext.oid)"
            )
        }

        try self.init(derEncoded: ext.value)
    }

    init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self.rawValue = try ASN1OctetString(derEncoded: rootNode, withIdentifier: identifier)
        guard (1...32).contains(self.rawValue.bytes.count) else {
            throw ASN1Error.unsupportedFieldLength(
                reason: "OCSP Nonce has invalid number of bytes: \(self.rawValue.bytes.count)"
            )
        }
    }

    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try rawValue.serialize(into: &coder, withIdentifier: identifier)
    }
}

extension ASN1ObjectIdentifier.OCSPExtensionID {
    static let nonceIdentifier: ASN1ObjectIdentifier = [1, 3, 6, 1, 5, 5, 7, 48, 1, 2]
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.Extension {
    /// Construct an opaque ``Certificate/Extension`` from this Key Usage extension.
    ///
    /// - Parameters:
    ///   - keyUsage: The extension to wrap
    ///   - critical: Whether this extension should have the critical bit set.
    init(_ nonce: OCSPNonce, critical: Bool) throws {
        var serializer = DER.Serializer()
        try serializer.serialize(nonce)
        self.init(oid: .OCSPExtensionID.nonceIdentifier, critical: critical, value: serializer.serializedBytes[...])
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension OCSPNonce: CertificateExtensionConvertible {
    func makeCertificateExtension() throws -> Certificate.Extension {
        try .init(self, critical: false)
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.Extensions {
    var ocspNonce: OCSPNonce? {
        get throws {
            try self[oid: .OCSPExtensionID.nonceIdentifier].map { try .init($0) }
        }
    }
}
