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

extension ASN1ObjectIdentifier {
    /// OIDs that identify known X509 extensions.
    public enum X509ExtensionID: Sendable {
        /// Identifies the authority key identifier extension, corresponding to
        /// ``AuthorityKeyIdentifier``.
        public static let authorityKeyIdentifier: ASN1ObjectIdentifier = [2, 5, 29, 35]

        /// Identifies the subject key identifier extension, corresponding to
        /// ``SubjectKeyIdentifier``.
        public static let subjectKeyIdentifier: ASN1ObjectIdentifier = [2, 5, 29, 14]

        /// Identifies the key usage extension, corresponding to
        /// ``KeyUsage``.
        public static let keyUsage: ASN1ObjectIdentifier = [2, 5, 29, 15]

        /// Identifies the subject alternative name extension, corresponding to
        /// ``SubjectAlternativeNames``.
        public static let subjectAlternativeName: ASN1ObjectIdentifier = [2, 5, 29, 17]

        /// Identifies the basic constraints extension, corresponding to
        /// ``BasicConstraints``.
        public static let basicConstraints: ASN1ObjectIdentifier = [2, 5, 29, 19]

        /// Identifies the name constraints extension, corresponding to
        /// ``NameConstraints``.
        public static let nameConstraints: ASN1ObjectIdentifier = [2, 5, 29, 30]

        /// Identifies the extended key usage extension, corresponding to
        /// ``ExtendedKeyUsage``.
        public static let extendedKeyUsage: ASN1ObjectIdentifier = [2, 5, 29, 37]

        /// Identifies the authority information access extension, corresponding to
        /// ``AuthorityInformationAccess``.
        public static let authorityInformationAccess: ASN1ObjectIdentifier = [1, 3, 6, 1, 5, 5, 7, 1, 1]
    }
}
