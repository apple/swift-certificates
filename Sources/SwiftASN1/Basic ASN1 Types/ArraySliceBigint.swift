//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftASN1 open source project
//
// Copyright (c) 2019-2020 Apple Inc. and the SwiftASN1 project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftASN1 project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

// For temporary purposes we pretend that ArraySlice is our "bigint" type. We don't really need anything else.
extension ArraySlice: DERSerializable where Element == UInt8 { }

extension ArraySlice: DERParseable where Element == UInt8 { }

extension ArraySlice: DERImplicitlyTaggable where Element == UInt8 { }

extension ArraySlice: ASN1IntegerRepresentable where Element == UInt8 {
    // We only use unsigned "bigint"s
    @inlinable
    public static var isSigned: Bool {
        return false
    }

    @inlinable
    public init(derIntegerBytes: ArraySlice<UInt8>) throws {
        self = derIntegerBytes
    }

    @inlinable
    public func withBigEndianIntegerBytes<ReturnType>(_ body: (ArraySlice<UInt8>) throws -> ReturnType) rethrows -> ReturnType {
        return try body(self)
    }
}
