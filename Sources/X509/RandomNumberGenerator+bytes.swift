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

extension RandomNumberGenerator {
    @inlinable
    internal mutating func bytes(count: Int) -> ArraySlice<UInt8> {
        precondition(count >= 0)
        var bytes = [UInt8]()

        while bytes.count < count {
            bytes.appendLittleEndianBytes(self.next())
        }

        return bytes[..<count]
    }
}

extension Array where Element == UInt8 {
    @inlinable
    mutating func appendLittleEndianBytes(_ number: UInt64) {
        let number = number.littleEndian

        for byte in 0..<(MemoryLayout<UInt64>.size) {
            let shifted = number >> (byte * 8)
            self.append(UInt8(truncatingIfNeeded: shifted))
        }
    }
}
