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
            self.init(generator: &rng)
        }
        
        @inlinable
        internal init(generator: inout some RandomNumberGenerator) {
            // drop leading zeros as required by the ASN.1 spec for INTEGERs
            self.bytes = generator.bytes(count: 20).drop(while: { $0 == 0 })
        }
    }
}

extension Certificate.SerialNumber: Hashable { }

extension Certificate.SerialNumber: Sendable { }

extension Certificate.SerialNumber: CustomStringConvertible {
    public var description: String {
        return self.bytes.lazy.map { String($0, radix: 16) }.joined(separator: ":")
    }
}
