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
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// A representation of a CMS signature over some data.
///
/// This type hides the specifics of how CMS represents data, instead offering a limited
/// view over a CMS signed-data payload. It also abstracts the specific ASN.1 layout of the
/// signature.
@_spi(CMS)
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public struct CMSSignature: Sendable, Hashable {
    @usableFromInline
    let base: CMSSignedData

    /// Returns the certificates associated with the signers
    @inlinable
    public var signers: [Signer] {
        get throws {
            try self.base.signerInfos.compactMap { signerInfo in
                try self.base.certificates?.certificate(signerInfo: signerInfo).map {
                    Signer(certificate: $0, signingTime: try signerInfo.signedAttrs?.signingTime)
                }
            }
        }
    }

    /// The certificates in the signature.
    @inlinable
    public var certificates: [Certificate] {
        self.base.certificates ?? []
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension CMSSignature: DERImplicitlyTaggable, BERImplicitlyTaggable {
    @inlinable
    public static var defaultIdentifier: ASN1Identifier {
        CMSContentInfo.defaultIdentifier
    }

    @inlinable
    public init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        guard let base = try CMSContentInfo(derEncoded: rootNode, withIdentifier: identifier).signedData,
            base.version == .v1 || base.version == .v4
        else {
            throw CMS.Error.unexpectedCMSType
        }

        self.base = base
    }

    @inlinable
    public init(berEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        guard let base = try CMSContentInfo(berEncoded: rootNode, withIdentifier: identifier).signedData,
            base.version == .v1 || base.version == .v4
        else {
            throw CMS.Error.unexpectedCMSType
        }

        self.base = base
    }

    @inlinable
    public func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try CMSContentInfo(self.base).serialize(into: &coder, withIdentifier: identifier)
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension CMSSignature {
    /// One of the "signers" that produced a given CMS block.
    ///
    /// Note that the signer has not been validated, so it is possible that the signer did not actually
    /// sign the block in question.
    @_spi(CMS)
    public struct Signer: Sendable, Hashable {
        public let certificate: Certificate

        public let signingTime: Date?

        @inlinable
        init(certificate: Certificate, signingTime: Date? = nil) {
            self.certificate = certificate
            self.signingTime = signingTime
        }
    }
}
