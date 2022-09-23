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

extension Certificate {
    /// A number that uniquely identifies a certificate issued by a specific
    /// certificate authority.
    ///
    /// Serial numbers are often extremely large (up to 20 bytes), so they cannot typically
    /// be represented using a fixed-width integer type. This type therefore represents the
    /// raw big-endian bytes of the serial number, suitable for loading into a more specific
    /// type.
    public struct SerialNumber {
        /// The raw big-endian bytes of the serial number.
        public var bytes: ArraySlice<UInt8>

        /// Construct a serial number from its raw big-endian bytes.
        /// - Parameter bytes: The raw big-endian bytes of the serial number.
        @inlinable
        public init(bytes: ArraySlice<UInt8>) {
            self.bytes = bytes
        }

        /// Construct a serial number from its raw big-endian bytes.
        /// - Parameter bytes: The raw big-endian bytes of the serial number.
        @inlinable
        public init(bytes: [UInt8]) {
            self.bytes = bytes[...]
        }

        /// Construct a serial number from its raw big-endian bytes.
        /// - Parameter bytes: The raw big-endian bytes of the serial number.
        @inlinable
        public init<Bytes: Collection>(bytes: Bytes) where Bytes.Element == UInt8 {
            self.bytes = ArraySlice(bytes)
        }

        /// Construct a serial number from a fixed width integer.
        ///
        /// In general this API should only be used for testing, as fixed width integers
        /// are not sufficiently large for use in certificates. Using this API for production
        /// use-cases may expose users to hash collision attacks on generated certificates.
        /// 
        /// - Parameter bytes: The raw big-endian bytes of the serial number.
        @inlinable
        public init<Number: FixedWidthInteger>(_ number: Number) {
            fatalError("TODO: Need ASN1 to implement")
        }

        /// Construct a random 20-byte serial number.
        ///
        /// Serial numbers should be generated randomly, and may contain up to 20 bytes. This
        /// initializer generates an appropriate serial number.
        @inlinable
        public init() {
            var rng = SystemRandomNumberGenerator()
            var bytes = [UInt8]()

            while bytes.count < 20 {
                bytes.appendLittleEndianBytes(rng.next())
            }

            self.bytes = bytes[..<20]
        }
    }
}

extension Certificate.SerialNumber: Hashable { }

extension Certificate.SerialNumber: Sendable { }

extension Certificate.SerialNumber: CustomStringConvertible {
    public var description: String {
        return "TODO"
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
