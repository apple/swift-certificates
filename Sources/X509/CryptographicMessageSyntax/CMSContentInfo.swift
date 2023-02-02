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

/// ``ContentInfo`` is defined in ASN.1 as:
/// ```
/// ContentInfo ::= SEQUENCE {
///   contentType ContentType,
///   content [0] EXPLICIT ANY DEFINED BY contentType }
/// ContentType ::= OBJECT IDENTIFIER
/// ```
struct CMSContentInfo {
    var contentType: ASN1ObjectIdentifier
    var content: ASN1Any
}

extension CMSContentInfo {
    init(_ signedData: CMSSignedData) {
        fatalError("TODO: not implemented")
    }
    
    var signedData: CMSSignedData? {
        get throws {
            fatalError("TODO: not implemented")
        }
    }
}
