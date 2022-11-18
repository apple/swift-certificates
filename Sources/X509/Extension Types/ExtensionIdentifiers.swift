//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCertificate open source project
//
// Copyright (c) 2022 Apple Inc. and the SwiftCertificate project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.md for the list of SwiftCertificate project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import SwiftASN1

extension ASN1ObjectIdentifier {
    /// OIDs that identify known X509 extensions.
    public enum X509ExtensionID {
        /// Identifies the authority key identifier extension, corresponding to
        /// ``Certificate/Extensions-swift.struct/AuthorityKeyIdentifier-swift.struct``.
        public static let authorityKeyIdentifier: ASN1ObjectIdentifier = [2, 5, 29, 35]

        /// Identifies the subject key identifier extension, corresponding to
        /// ``Certificate/Extensions-swift.struct/SubjectKeyIdentifier-swift.struct``.
        public static let subjectKeyIdentifier: ASN1ObjectIdentifier = [2, 5, 29, 14]

        /// Identifies the key usgae extension, corresponding to
        /// ``Certificate/Extensions-swift.struct/KeyUsage-swift.struct``.
        public static let keyUsage: ASN1ObjectIdentifier = [2, 5, 29, 15]

        /// Identifies the subject alternative name extension, corresponding to
        /// ``Certificate/Extensions-swift.struct/SubjectAlternativeNames-swift.struct``.
        public static let subjectAlternativeName: ASN1ObjectIdentifier = [2, 5, 29, 17]

        /// Identifies the basic constraints extension, corresponding to
        /// ``Certificate/Extensions-swift.struct/BasicConstraints-swift.enum``.
        public static let basicConstraints: ASN1ObjectIdentifier = [2, 5, 29, 19]

        /// Identifies the name constraints extension, corresponding to
        /// ``Certificate/Extensions-swift.struct/NameConstraints-swift.struct``.
        public static let nameConstraints: ASN1ObjectIdentifier = [2, 5, 29, 30]

        /// Identifies the extended key usage extension, corresponding to
        /// ``Certificate/Extensions-swift.struct/ExtendedKeyUsage-swift.struct``.
        public static let extendedKeyUsage: ASN1ObjectIdentifier = [2, 5, 29, 37]

        /// Identifies the authority information access extension, corresponding to
        /// ``Certificate/Extensions-swift.struct/AuthorityInformationAccess-swift.struct``.
        public static let authorityInformationAccess: ASN1ObjectIdentifier = [1, 3, 6, 1, 5, 5, 7, 1, 1]
    }
}
