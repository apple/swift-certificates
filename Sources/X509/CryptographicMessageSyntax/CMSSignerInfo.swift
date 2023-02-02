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

/// ``CMSSignerInfo`` is defined in ASN.1 as:
/// ```
/// SignerInfo ::= SEQUENCE {
///   version CMSVersion,
///   sid SignerIdentifier,
///   digestAlgorithm DigestAlgorithmIdentifier,
///   signedAttrs [0] IMPLICIT SignedAttributes OPTIONAL,
///   signatureAlgorithm SignatureAlgorithmIdentifier,
///   signature SignatureValue,
///   unsignedAttrs [1] IMPLICIT UnsignedAttributes OPTIONAL }
///
/// SignatureValue ::= OCTET STRING
/// DigestAlgorithmIdentifier ::= AlgorithmIdentifier
/// SignatureAlgorithmIdentifier ::= AlgorithmIdentifier
/// ```
/// - Note: If the `SignerIdentifier` is the CHOICE `issuerAndSerialNumber`,
/// then the `version` MUST be 1.  If the `SignerIdentifier` is `subjectKeyIdentifier`,
/// then the `version` MUST be 3.
/// - Note: At the moment we neither support `signedAttrs` (`SignedAttributes`) nor `unsignedAttrs` (`UnsignedAttributes`)
struct CMSSignerInfo {
    var version: CMSVersion
    var signerIdentifier: CMSSignerIdentifier
    var digestAlgorithm: AlgorithmIdentifier
    var signatureAlgorithm: AlgorithmIdentifier
    var signature: ASN1OctetString
}

