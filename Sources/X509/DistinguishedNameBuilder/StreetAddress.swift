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

/// Set the Street Address (STREET) of a ``DistinguishedName``.
///
/// This type is used in ``DistinguishedNameBuilder`` contexts.
public struct StreetAddress: RelativeDistinguishedNameConvertible, Sendable {
    /// The value of the street address field.
    public var name: String

    /// Construct a street address
    ///
    /// - Parameter name: The value of the street address field
    @inlinable
    public init(_ name: String) {
        self.name = name
    }

    @inlinable
    public func makeRDN() throws -> RelativeDistinguishedName {
        return RelativeDistinguishedName(
            .init(type: .RDNAttributeType.streetAddress, utf8String: name)
        )
    }
}
