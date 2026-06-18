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

/// A parsed X.509 Certificate Revocation List (RFC 5280 §5.1).
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public struct CertificateRevocationList: Sendable {
    /// The raw bytes of the TBSCertList, used for signature verification.
    public let tbsCertListBytes: ArraySlice<UInt8>

    /// The signature algorithm used to sign this CRL.
    public let signatureAlgorithm: Certificate.SignatureAlgorithm

    /// The signature over the TBSCertList.
    public let signature: Certificate.Signature

    /// The issuer of this CRL.
    public let issuer: DistinguishedName

    /// The date this CRL was issued.
    public let thisUpdate: Date

    /// The date by which the next CRL will be issued.
    public let nextUpdate: Date?

    /// Serial numbers of revoked certificates.
    public let revokedSerialNumbers: Set<Certificate.SerialNumber>

    /// Parse a CRL from DER-encoded bytes.
    public init(derEncoded bytes: [UInt8]) throws {
        let rootNode = try DER.parse(bytes)
        try self.init(derEncoded: rootNode)
    }

    /// Parse a CRL from a DER ASN1Node.
    public init(derEncoded rootNode: ASN1Node) throws {
        // CertificateList ::= SEQUENCE { tbsCertList, signatureAlgorithm, signatureValue }
        guard rootNode.identifier == .sequence,
              case .constructed(let topLevel) = rootNode.content
        else {
            throw ASN1Error.unexpectedFieldType(rootNode.identifier)
        }

        var topIter = topLevel.makeIterator()
        guard let tbsNode = topIter.next(),
              let sigAlgNode = topIter.next(),
              let sigNode = topIter.next()
        else {
            throw ASN1Error.invalidASN1Object(reason: "Invalid CRL structure")
        }

        self.tbsCertListBytes = tbsNode.encodedBytes
        self.signatureAlgorithm = try Certificate.SignatureAlgorithm(
            algorithmIdentifier: AlgorithmIdentifier(derEncoded: sigAlgNode)
        )
        let signatureBits = try ASN1BitString(derEncoded: sigNode)
        self.signature = try Certificate.Signature(
            signatureAlgorithm: self.signatureAlgorithm,
            signatureBytes: signatureBits
        )

        // Parse TBSCertList
        guard tbsNode.identifier == .sequence,
              case .constructed(let tbsChildren) = tbsNode.content
        else {
            throw ASN1Error.unexpectedFieldType(tbsNode.identifier)
        }

        var tbsIter = tbsChildren.makeIterator()

        // version [OPTIONAL] - INTEGER
        guard var currentNode = tbsIter.next() else {
            throw ASN1Error.invalidASN1Object(reason: "Empty TBSCertList")
        }
        if currentNode.identifier == .integer {
            // Skip version
            guard let next = tbsIter.next() else {
                throw ASN1Error.invalidASN1Object(reason: "TBSCertList too short")
            }
            currentNode = next
        }

        // signature - AlgorithmIdentifier (skip, already have it from outer)
        guard let issuerNode = tbsIter.next() else {
            throw ASN1Error.invalidASN1Object(reason: "Missing issuer in TBSCertList")
        }

        // issuer - Name
        self.issuer = try DistinguishedName(derEncoded: issuerNode)

        // thisUpdate - Time
        guard let thisUpdateNode = tbsIter.next() else {
            throw ASN1Error.invalidASN1Object(reason: "Missing thisUpdate in TBSCertList")
        }
        self.thisUpdate = Date(try Time(derEncoded: thisUpdateNode))

        // nextUpdate - Time OPTIONAL
        var nextUpdateDate: Date? = nil
        if let maybeNextUpdate = tbsIter.next() {
            if maybeNextUpdate.identifier == GeneralizedTime.defaultIdentifier ||
               maybeNextUpdate.identifier == UTCTime.defaultIdentifier {
                nextUpdateDate = Date(try Time(derEncoded: maybeNextUpdate))
            }
        }
        self.nextUpdate = nextUpdateDate

        // revokedCertificates - SEQUENCE OF SEQUENCE OPTIONAL
        var serials = Set<Certificate.SerialNumber>()
        // The remaining nodes might be revokedCertificates or extensions
        // Try to find a SEQUENCE node that contains the revoked entries
        for node in tbsChildren {
            // Skip nodes we've already processed (version, sig, issuer, thisUpdate, nextUpdate)
            // Look for a SEQUENCE that contains SEQUENCE entries (revokedCertificates)
            if node.identifier == .sequence,
               case .constructed(let children) = node.content {
                // Check if this looks like revokedCertificates (first child should be a SEQUENCE)
                var childIter = children.makeIterator()
                if let firstChild = childIter.next(),
                   firstChild.identifier == .sequence {
                    // This is revokedCertificates
                    // Parse first entry
                    if case .constructed(let entryChildren) = firstChild.content {
                        var entryIter = entryChildren.makeIterator()
                        if let serialNode = entryIter.next() {
                            let serialBytes = try ArraySlice<UInt8>(derEncoded: serialNode)
                            serials.insert(Certificate.SerialNumber(bytes: serialBytes))
                        }
                    }
                    // Parse remaining entries
                    while let entry = childIter.next() {
                        if entry.identifier == .sequence,
                           case .constructed(let entryChildren) = entry.content {
                            var entryIter = entryChildren.makeIterator()
                            if let serialNode = entryIter.next() {
                                let serialBytes = try ArraySlice<UInt8>(derEncoded: serialNode)
                                serials.insert(Certificate.SerialNumber(bytes: serialBytes))
                            }
                        }
                    }
                    break
                }
            }
        }
        self.revokedSerialNumbers = serials
    }

    /// Check if a certificate serial number is revoked.
    public func isRevoked(_ serialNumber: Certificate.SerialNumber) -> Bool {
        revokedSerialNumbers.contains(serialNumber)
    }

    /// Verify the CRL signature against the issuer's public key.
    public func verifySignature(issuerPublicKey: Certificate.PublicKey) -> Bool {
        issuerPublicKey.isValidSignature(signature, for: tbsCertListBytes, signatureAlgorithm: signatureAlgorithm)
    }
}
