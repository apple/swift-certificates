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
@preconcurrency import Crypto

@usableFromInline
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
enum Digest: Sendable {
    case insecureSHA1(Insecure.SHA1Digest)
    case sha256(SHA256Digest)
    case sha384(SHA384Digest)
    case sha512(SHA512Digest)

    @inlinable
    static func computeDigest<Bytes: DataProtocol>(
        for bytes: Bytes,
        using digestIdentifier: AlgorithmIdentifier
    ) throws -> Digest {
        switch digestIdentifier {
        case .sha1, .sha1UsingNil:
            return .insecureSHA1(Insecure.SHA1.hash(data: bytes))
        case .sha256, .sha256UsingNil:
            return .sha256(SHA256.hash(data: bytes))
        case .sha384, .sha384UsingNil:
            return .sha384(SHA384.hash(data: bytes))
        case .sha512, .sha512UsingNil:
            return .sha512(SHA512.hash(data: bytes))
        default:
            throw CertificateError.unsupportedDigestAlgorithm(reason: "Unknown digest algorithm: \(digestIdentifier)")
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Digest: Sequence {
    @usableFromInline
    func makeIterator() -> some IteratorProtocol<UInt8> {
        switch self {
        case .insecureSHA1(let sha1):
            return sha1.makeIterator()
        case .sha256(let sha256):
            return sha256.makeIterator()
        case .sha384(let sha384):
            return sha384.makeIterator()
        case .sha512(let sha512):
            return sha512.makeIterator()
        }
    }
}
