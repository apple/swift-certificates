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

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
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
            self.bytes = ArraySlice(normalisingToASN1IntegerForm: bytes)
        }

        /// Construct a serial number from its raw big-endian bytes.
        /// - Parameter bytes: The raw big-endian bytes of the serial number.
        @inlinable
        public init(bytes: [UInt8]) {
            self.bytes = ArraySlice(normalisingToASN1IntegerForm: bytes[...])
        }

        /// Construct a serial number from its raw big-endian bytes.
        /// - Parameter bytes: The raw big-endian bytes of the serial number.
        @inlinable
        public init<Bytes: Collection>(bytes: Bytes) where Bytes.Element == UInt8 {
            self.bytes = ArraySlice(normalisingToASN1IntegerForm: bytes)
        }

        /// Construct a serial number from a fixed width integer.
        ///
        /// In general this API should only be used for testing, as fixed width integers
        /// are not sufficiently large for use in certificates. Using this API for production
        /// use-cases may expose users to hash collision attacks on generated certificates.
        ///
        /// Prefer using ``Certificate/SerialNumber-swift.struct/init(integerLiteral:)``
        /// with a `StaticBigInt` which enables arbitrary-precision.
        ///
        /// - Parameter number: The raw big-endian bytes of the serial number.
        @inlinable
        public init<Number: FixedWidthInteger>(_ number: Number) {
            // `IntegerBytesCollection` already trims leading zeros
            self.bytes = ArraySlice(IntegerBytesCollection(number))
        }

        /// Construct a random 20-byte serial number.
        ///
        /// Serial numbers should be generated randomly, and may contain up to 20 bytes. This
        /// initializer generates an appropriate serial number.
        @inlinable
        public init() {
            var rng = SystemRandomNumberGenerator()
            self.init(generator: &rng)
        }

        /// Construct a random 20-byte serial number.
        ///
        /// Serial numbers should be generated randomly, and may contain up to 20 bytes. This
        /// initializer generates a serial number with random numbers from the given `generator`.
        /// - Parameter generator: the generator used to generate random number for the serial number
        @inlinable
        internal init(generator: inout some RandomNumberGenerator) {
            // drop leading zeros as required by the ASN.1 spec for INTEGERs
            self.bytes = ArraySlice(normalisingToASN1IntegerForm: generator.bytes(count: 20))
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.SerialNumber: Hashable {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.SerialNumber: Sendable {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.SerialNumber: CustomStringConvertible {
    public var description: String {
        return self.bytes.lazy.map { String($0, radix: 16) }.joined(separator: ":")
    }
}

@available(macOS 13.3, iOS 16.4, watchOS 9.4, tvOS 16.4, macCatalyst 16.4, visionOS 1.0, *)
extension Certificate.SerialNumber: ExpressibleByIntegerLiteral {
    /// Constructs a serial number from an integer.
    ///
    /// - Parameter number: The raw big-endian bytes of the serial number.
    @inlinable
    public init(integerLiteral number: StaticBigInt) {
        var bytes = [UInt8]()
        let wordCount = (number.bitWidth - 1) / (MemoryLayout<UInt>.size * 8) + 1
        bytes.reserveCapacity(wordCount / MemoryLayout<UInt>.size)

        for wordIndex in (0..<wordCount).reversed() {
            bytes.appendBigEndianBytes(number[wordIndex])
        }

        self.bytes = ArraySlice(normalisingToASN1IntegerForm: bytes)
    }
}

extension [UInt8] {
    @inlinable
    mutating func appendBigEndianBytes(_ number: UInt) {
        let number = number.bigEndian

        for byte in 0..<(MemoryLayout<UInt>.size) {
            let shifted = number >> (byte * 8)
            self.append(UInt8(truncatingIfNeeded: shifted))
        }
    }
}
