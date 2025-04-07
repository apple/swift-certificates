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
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import SwiftASN1
import Crypto

/// An ECDSA signature is laid out as follows:
///
/// ECDSASignature ::= SEQUENCE {
///   r INTEGER,
///   s INTEGER
/// }
///
/// We define this type here because an X.509 certificate may have an ECDSA signature
/// in it without reference to what key created it. We need to be able to store it
/// abstractly, and then turn it into the signature type we need on request.
@usableFromInline
struct ECDSASignature: DERImplicitlyTaggable, Hashable, Sendable {
    @inlinable
    static var defaultIdentifier: ASN1Identifier {
        .sequence
    }

    @usableFromInline
    var r: ArraySlice<UInt8>

    @usableFromInline
    var s: ArraySlice<UInt8>

    @inlinable
    init(r: ArraySlice<UInt8>, s: ArraySlice<UInt8>) {
        self.r = r
        self.s = s
    }

    @inlinable
    init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let r = try ArraySlice<UInt8>(derEncoded: &nodes)
            let s = try ArraySlice<UInt8>(derEncoded: &nodes)

            return ECDSASignature(r: r, s: s)
        }
    }

    @inlinable
    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(self.r)
            try coder.serialize(self.s)
        }
    }

    @inlinable
    init(rawSignatureBytes raw: Data) {
        let half = raw.count / 2
        let r = ArraySlice(normalisingToASN1IntegerForm: raw.prefix(upTo: half))
        let s = ArraySlice(normalisingToASN1IntegerForm: raw.suffix(from: half))

        self = ECDSASignature(r: r, s: s)
    }

    @inlinable
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    init(_ sig: P256.Signing.ECDSASignature) {
        self = .init(rawSignatureBytes: sig.rawRepresentation)
    }

    @inlinable
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    init(_ sig: P384.Signing.ECDSASignature) {
        self = .init(rawSignatureBytes: sig.rawRepresentation)
    }

    @inlinable
    @available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
    init(_ sig: P521.Signing.ECDSASignature) {
        self = .init(rawSignatureBytes: sig.rawRepresentation)
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension P256.Signing.ECDSASignature {
    @inlinable
    init?(_ signature: ECDSASignature) {
        let coordinateByteCount = 32

        guard signature.r.count <= coordinateByteCount && signature.s.count <= coordinateByteCount else {
            return nil
        }

        // r and s must be padded out to the coordinate byte count.
        // We use Data here because Crypto wants that type anyway.
        var raw = Data()
        raw.reserveCapacity(2 * coordinateByteCount)

        raw.append(contentsOf: repeatElement(0, count: coordinateByteCount - signature.r.count))
        raw.append(contentsOf: signature.r)
        raw.append(contentsOf: repeatElement(0, count: coordinateByteCount - signature.s.count))
        raw.append(contentsOf: signature.s)

        do {
            self = try .init(rawRepresentation: raw)
        } catch {
            return nil
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension P384.Signing.ECDSASignature {
    @inlinable
    init?(_ signature: ECDSASignature) {
        let coordinateByteCount = 48

        guard signature.r.count <= coordinateByteCount && signature.s.count <= coordinateByteCount else {
            return nil
        }

        // r and s must be padded out to the coordinate byte count.
        // We use Data here because Crypto wants that type anyway.
        var raw = Data()
        raw.reserveCapacity(2 * coordinateByteCount)

        raw.append(contentsOf: repeatElement(0, count: coordinateByteCount - signature.r.count))
        raw.append(contentsOf: signature.r)
        raw.append(contentsOf: repeatElement(0, count: coordinateByteCount - signature.s.count))
        raw.append(contentsOf: signature.s)

        do {
            self = try .init(rawRepresentation: raw)
        } catch {
            return nil
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension P521.Signing.ECDSASignature {
    @inlinable
    init?(_ signature: ECDSASignature) {
        let coordinateByteCount = 66

        guard signature.r.count <= coordinateByteCount && signature.s.count <= coordinateByteCount else {
            return nil
        }

        // r and s must be padded out to the coordinate byte count.
        // We use Data here because Crypto wants that type anyway.
        var raw = Data()
        raw.reserveCapacity(2 * coordinateByteCount)

        raw.append(contentsOf: repeatElement(0, count: coordinateByteCount - signature.r.count))
        raw.append(contentsOf: signature.r)
        raw.append(contentsOf: repeatElement(0, count: coordinateByteCount - signature.s.count))
        raw.append(contentsOf: signature.s)

        do {
            self = try .init(rawRepresentation: raw)
        } catch {
            return nil
        }
    }
}

extension ArraySlice where Element == UInt8 {
    /// Normalizes a sequence of bytes that represent an unsigned big endian raw integer into the
    /// form we'd get from decoding an ASN1 integer.
    ///
    /// This means we strip leading zero bytes.
    @inlinable
    init<Bytes: Collection>(normalisingToASN1IntegerForm bigEndianRawInteger: Bytes) where Bytes.Element == UInt8 {
        let realBytes = bigEndianRawInteger.drop(while: { $0 == 0 })
        self = ArraySlice(realBytes)
    }

    @inlinable
    init(normalisingToASN1IntegerForm bigEndianRawInteger: ArraySlice<UInt8>) {
        self = bigEndianRawInteger.drop(while: { $0 == 0 })
    }

    @inlinable
    init(normalisingToASN1IntegerForm bigEndianRawInteger: [UInt8]) {
        self.init(normalisingToASN1IntegerForm: bigEndianRawInteger[...])
    }
}
