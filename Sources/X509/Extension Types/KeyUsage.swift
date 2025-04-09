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

/// Defines the purpose of the key contained in the certificate.
///
/// This usage restriction may be employed when a key that could conceptually be used
/// for more than one operation (such as an RSA key) is to be restricted.
public struct KeyUsage {
    // KeyUsage is only actually 9-bits wide, so we store it in a UInt16 in bits 0 through 8.
    // To avoid the need to do bit swaps, we treat this as though the bits were encoded in ASN.1:
    // bit zero is the highest bit, bit 16 is the lowest.
    @usableFromInline
    internal var rawValue: UInt16

    /// Construct a ``KeyUsage`` extension with no usages set.
    @inlinable
    public init() {
        self.rawValue = 0
    }

    /// Construct a ``KeyUsage`` extension with some usages set.
    ///
    /// - Parameters:
    ///   - digitalSignature: This is true when the subject public key is used for verifying digital signatures,
    ///       other than signatures used in certificates (covered by `keyCertSign`) or in
    ///       CRLs (covered by `cRLSign`).
    ///   - nonRepudiation: This is true when the subject public key is used to verify digital signatures used
    ///       to provide a non-repudiation service that protects against the signing entity denying
    ///       some action. This does not cover signatures used in certificates (covered by `keyCertSign`)
    ///       or in CRLs (`cRLSign`).
    ///   - keyEncipherment: This is true when the subject public key is used to encrypt private or secret keys, e.g.
    ///       for key transport.
    ///   - dataEncipherment: This is true when the subject public key is used to encrypt raw data directly, without the use
    ///       of an intervening symmetric cipher.
    ///   - keyAgreement: This is true when the subject public key is used for key agreement.
    ///   - keyCertSign: This is true when the subject public key is used for verifying signatures on
    ///       certificates.
    ///   - cRLSign: This is true when the subject public key is used for verifying signatures on
    ///       certificate revocation lists.
    ///   - encipherOnly: This only has meaning when the `keyAgreement` field is also `true`. When `true` in that
    ///       case, the subject public key may only be used for encrypting data while performing key
    ///       agreement.
    ///   - decipherOnly: This only has meaning when the `keyAgreement` field is also `true`. When `true` in that
    ///       case, the subject public key may only be used for decrypting data while performing key
    ///       agreement.
    @inlinable
    public init(
        digitalSignature: Bool = false,
        nonRepudiation: Bool = false,
        keyEncipherment: Bool = false,
        dataEncipherment: Bool = false,
        keyAgreement: Bool = false,
        keyCertSign: Bool = false,
        cRLSign: Bool = false,
        encipherOnly: Bool = false,
        decipherOnly: Bool = false
    ) {
        self = Self()
        self.digitalSignature = digitalSignature
        self.nonRepudiation = nonRepudiation
        self.keyEncipherment = keyEncipherment
        self.dataEncipherment = dataEncipherment
        self.keyAgreement = keyAgreement
        self.keyCertSign = keyCertSign
        self.cRLSign = cRLSign
        self.encipherOnly = encipherOnly
        self.decipherOnly = decipherOnly
    }

    /// Create a new ``KeyUsage`` object
    /// by unwrapping a ``Certificate/Extension``.
    ///
    /// - Parameter ext: The ``Certificate/Extension`` to unwrap
    /// - Throws: if the ``Certificate/Extension/oid`` is not equal to
    ///     `ASN1ObjectIdentifier.X509ExtensionID.keyUsage`.
    @inlinable
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    public init(_ ext: Certificate.Extension) throws {
        guard ext.oid == .X509ExtensionID.keyUsage else {
            throw CertificateError.incorrectOIDForExtension(
                reason: "Expected \(ASN1ObjectIdentifier.X509ExtensionID.keyUsage), got \(ext.oid)"
            )
        }

        let keyUsageValue = try ASN1BitString(derEncoded: ext.value)
        try Self.validateBitString(keyUsageValue)
        self.rawValue = UInt16(keyUsageValue)
    }

    /// This is true when the subject public key is used for verifying digital signatures,
    /// other than signatures used in certificates (covered by ``keyCertSign``) or in
    /// CRLs (covered by ``cRLSign``).
    @inlinable
    public var digitalSignature: Bool {
        get {
            return (self.rawValue & 0x8000) == 0x8000
        }
        set {
            if newValue {
                self.rawValue |= 0x8000
            } else {
                self.rawValue &= (~0x8000)
            }
        }
    }

    /// This is true when the subject public key is used to verify digital signatures used
    /// to provide a non-repudiation service that protects against the signing entity denying
    /// some action. This does not cover signatures used in certificates (covered by ``keyCertSign``)
    /// or in CRLs (``cRLSign``).
    @inlinable
    public var nonRepudiation: Bool {
        get {
            return (self.rawValue & 0x4000) == 0x4000
        }
        set {
            if newValue {
                self.rawValue |= 0x4000
            } else {
                self.rawValue &= (~0x4000)
            }
        }
    }

    /// This is true when the subject public key is used to encrypt private or secret keys, e.g.
    /// for key transport.
    @inlinable
    public var keyEncipherment: Bool {
        get {
            return (self.rawValue & 0x2000) == 0x2000
        }
        set {
            if newValue {
                self.rawValue |= 0x2000
            } else {
                self.rawValue &= (~0x2000)
            }
        }
    }

    /// This is true when the subject public key is used to encrypt raw data directly, without the use
    /// of an intervening symmetric cipher.
    @inlinable
    public var dataEncipherment: Bool {
        get {
            return (self.rawValue & 0x1000) == 0x1000
        }
        set {
            if newValue {
                self.rawValue |= 0x1000
            } else {
                self.rawValue &= (~0x1000)
            }
        }
    }

    /// This is true when the subject public key is used for key agreement.
    @inlinable
    public var keyAgreement: Bool {
        get {
            return (self.rawValue & 0x0800) == 0x0800
        }
        set {
            if newValue {
                self.rawValue |= 0x0800
            } else {
                self.rawValue &= (~0x0800)
            }
        }
    }

    /// This is true when the subject public key is used for verifying signatures on
    /// certificates.
    @inlinable
    public var keyCertSign: Bool {
        get {
            return (self.rawValue & 0x0400) == 0x0400
        }
        set {
            if newValue {
                self.rawValue |= 0x0400
            } else {
                self.rawValue &= (~0x0400)
            }
        }
    }

    /// This is true when the subject public key is used for verifying signatures on
    /// certificate revocation lists.
    @inlinable
    public var cRLSign: Bool {
        get {
            return (self.rawValue & 0x0200) == 0x0200
        }
        set {
            if newValue {
                self.rawValue |= 0x0200
            } else {
                self.rawValue &= (~0x0200)
            }
        }
    }

    /// This only has meaning when the ``keyAgreement`` field is also `true`. When `true` in that
    /// case, the subject public key may only be used for encrypting data while performing key
    /// agreement.
    @inlinable
    public var encipherOnly: Bool {
        get {
            return (self.rawValue & 0x0100) == 0x0100
        }
        set {
            if newValue {
                self.rawValue |= 0x0100
            } else {
                self.rawValue &= (~0x0100)
            }
        }
    }

    /// This only has meaning when the ``keyAgreement`` field is also `true`. When `true` in that
    /// case, the subject public key may only be used for decrypting data while performing key
    /// agreement.
    @inlinable
    public var decipherOnly: Bool {
        get {
            return (self.rawValue & 0x0080) == 0x0080
        }
        set {
            if newValue {
                self.rawValue |= 0x0080
            } else {
                self.rawValue &= (~0x0080)
            }
        }
    }

    @inlinable
    internal static func validateBitString(_ bitstring: ASN1BitString) throws {
        switch bitstring.bytes.count {
        case 0:
            // This is fine, no bits are set.
            precondition(bitstring.paddingBits == 0)
        case 1:
            // This is fine, no more than 8 bits.
            // We want to confirm that the bit _before_ the first padding bit isn't 0.
            // We cannot have 8 padding bits.
            precondition(bitstring.paddingBits < 8)
            let bitMask = UInt8(0x01) << bitstring.paddingBits
            if (bitstring.bytes[bitstring.bytes.startIndex] & bitMask) == 0 {
                throw ASN1Error.invalidASN1Object(reason: "Invalid leading padding bit")
            }
        case 2 where bitstring.paddingBits == 7:
            // This is fine, there are 9 valid bits: 8 from the prior byte and 1 here.
            if (bitstring.bytes[bitstring.bytes.startIndex &+ 1] & 0x80) == 0 {
                throw ASN1Error.invalidASN1Object(reason: "Invalid padding bit")
            }
        default:
            // Too many bits!
            throw ASN1Error.invalidASN1Object(reason: "Too many bits for Key Usage")
        }
    }
}

extension KeyUsage: Hashable {}

extension KeyUsage: Sendable {}

extension KeyUsage: CustomStringConvertible {
    public var description: String {
        var enabledUsages: [String] = []

        if self.digitalSignature {
            enabledUsages.append("digitalSignature")
        }
        if self.nonRepudiation {
            enabledUsages.append("nonRepudiation")
        }
        if self.keyEncipherment {
            enabledUsages.append("keyEncipherment")
        }
        if self.dataEncipherment {
            enabledUsages.append("dataEncipherment")
        }
        if self.keyAgreement {
            enabledUsages.append("keyAgreement")
        }
        if self.keyCertSign {
            enabledUsages.append("keyCertSign")
        }
        if self.cRLSign {
            enabledUsages.append("cRLSign")
        }
        if self.encipherOnly {
            enabledUsages.append("encipherOnly")
        }
        if self.decipherOnly {
            enabledUsages.append("decipherOnly")
        }

        return enabledUsages.joined(separator: ", ")
    }
}

extension KeyUsage: CustomDebugStringConvertible {
    public var debugDescription: String {
        "KeyUsage(\(String(describing: self)))"
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.Extension {
    /// Construct an opaque ``Certificate/Extension`` from this Key Usage extension.
    ///
    /// - Parameters:
    ///   - keyUsage: The extension to wrap
    ///   - critical: Whether this extension should have the critical bit set.
    @inlinable
    public init(_ keyUsage: KeyUsage, critical: Bool) throws {
        let asn1Representation = ASN1BitString(keyUsage)
        var serializer = DER.Serializer()
        try serializer.serialize(asn1Representation)
        self.init(oid: .X509ExtensionID.keyUsage, critical: critical, value: serializer.serializedBytes[...])
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension KeyUsage: CertificateExtensionConvertible {
    public func makeCertificateExtension() throws -> Certificate.Extension {
        return try .init(self, critical: false)
    }
}

extension UInt16 {
    @inlinable
    init(_ bitString: ASN1BitString) {
        switch bitString.bytes.count {
        case 0:
            self = 0
        case 1:
            self = UInt16(bitString.bytes[bitString.bytes.startIndex]) << 8
        case 2:
            self = UInt16(bitString.bytes[bitString.bytes.startIndex]) << 8
            self |= UInt16(bitString.bytes[bitString.bytes.startIndex + 1])
        default:
            preconditionFailure()
        }
    }
}

extension ASN1BitString {
    @inlinable
    init(_ ext: KeyUsage) {
        if ext.decipherOnly {
            // We need two bytes here.
            let bytes = [UInt8(truncatingIfNeeded: ext.rawValue >> 8), UInt8(truncatingIfNeeded: ext.rawValue)]
            self = .init(bytes: bytes[...], paddingBits: 7)
        } else {
            // We only need one byte here.
            let byte = UInt8(truncatingIfNeeded: ext.rawValue >> 8)
            self = .init(bytes: [byte], paddingBits: byte.trailingZeroBitCount)
        }
    }
}
