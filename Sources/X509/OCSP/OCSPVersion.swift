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

struct OCSPVersion {
    var rawValue: Int

    init(rawValue: Int) {
        self.rawValue = rawValue
    }

    static let v1 = Self(rawValue: 0)
}

extension OCSPVersion: Hashable {}

extension OCSPVersion: Sendable {}

extension OCSPVersion: Comparable {
    static func < (lhs: Self, rhs: Self) -> Bool {
        lhs.rawValue < rhs.rawValue
    }
}

extension OCSPVersion: CustomStringConvertible {
    var description: String {
        switch self {
        case .v1:
            return "OCSPv1"
        case let unknown:
            return "OCSPv\(unknown.rawValue + 1)"
        }
    }
}
