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
struct CMSIssuerAndSerialNumber {
    var issuer: DistinguishedName
    var serialNumber: Certificate.SerialNumber
}
