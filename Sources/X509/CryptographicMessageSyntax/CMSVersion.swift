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

/// ``CMPVersion`` is defined in ASN1. as:
/// ```
///  CMSVersion ::= INTEGER
///                 { v0(0), v1(1), v2(2), v3(3), v4(4), v5(5) }
/// ```
public struct CMSVersion: RawRepresentable, Hashable, Sendable {
    public var rawValue: Int

    @inlinable
    public init(rawValue: Int) {
        self.rawValue = rawValue
    }

    public static let v0 = Self(rawValue: 0)
    public static let v1 = Self(rawValue: 1)
    public static let v2 = Self(rawValue: 2)
    public static let v3 = Self(rawValue: 3)
    public static let v4 = Self(rawValue: 4)
    public static let v5 = Self(rawValue: 5)
}

extension CMSVersion: CustomStringConvertible {
    @inlinable
    public var description: String {
        "CMSv\(rawValue)"
    }
}
