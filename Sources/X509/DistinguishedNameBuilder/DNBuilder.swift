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

/// Provides a result-builder style DSL for constructing ``DistinguishedName`` values.
///
/// This DSL allows us to construct distinguished names straightforwardly, using their high-level representation instead of
/// the awkward representation provided by sequences of ``RelativeDistinguishedName`` and
/// ``RelativeDistinguishedName/Attribute``. For example, a simple ``DistinguishedName`` can be
/// provided like this:
///
/// ```swift
/// let name = try DistinguishedName {
///     CountryName("US")
///     OrganizationName("Apple Inc.")
///     CommonName("Apple Public EV Server ECC CA 1 - G1")
/// }
/// ```
///
/// Users can extend this syntax for their own extensions by conforming their semantic type to ``RelativeDistinguishedNameConvertible``.
/// This is the only requirement for adding new extensions to this builder syntax.
@resultBuilder
public struct DistinguishedNameBuilder: Sendable {
    @inlinable
    public static func buildExpression<Extension: RelativeDistinguishedNameConvertible>(
        _ expression: Extension
    ) -> Result<DistinguishedName, any Error> {
        Result {
            try DistinguishedName([expression.makeRDN()])
        }
    }

    @inlinable
    public static func buildBlock(
        _ components: Result<DistinguishedName, any Error>...
    ) -> Result<DistinguishedName, any Error> {
        Result {
            DistinguishedName(try components.flatMap { try $0.get() })
        }
    }

    @inlinable
    public static func buildOptional(
        _ component: Result<DistinguishedName, any Error>?
    ) -> Result<DistinguishedName, any Error> {
        component ?? .success(DistinguishedName())
    }

    @inlinable
    public static func buildEither(
        first component: Result<DistinguishedName, any Error>
    ) -> Result<DistinguishedName, any Error> {
        component
    }

    @inlinable
    public static func buildEither(
        second component: Result<DistinguishedName, any Error>
    ) -> Result<DistinguishedName, any Error> {
        component
    }

    @inlinable
    public static func buildArray(
        _ components: [Result<DistinguishedName, any Error>]
    ) -> Result<DistinguishedName, any Error> {
        Result {
            DistinguishedName(try components.flatMap { try $0.get() })
        }
    }

    @inlinable
    public static func buildLimitedAvailability(
        _ component: Result<DistinguishedName, any Error>
    ) -> Result<DistinguishedName, any Error> {
        component
    }
}

public protocol RelativeDistinguishedNameConvertible {
    func makeRDN() throws -> RelativeDistinguishedName
}
