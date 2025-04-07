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

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension CertificateSigningRequest {
    /// The version of the CSR format.
    ///
    /// CSRs are conceptually capable of being evolved using version numbers. In practice,
    /// ``v1`` is the only version in common use.
    public struct Version {
        public var rawValue: Int

        @inlinable
        public init(rawValue: Int) {
            self.rawValue = rawValue
        }

        /// Corresponds to CSR version 1.
        public static let v1 = Self(rawValue: 0)
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension CertificateSigningRequest.Version: Hashable {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension CertificateSigningRequest.Version: Sendable {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension CertificateSigningRequest.Version: Comparable {
    @inlinable
    public static func < (lhs: CertificateSigningRequest.Version, rhs: CertificateSigningRequest.Version) -> Bool {
        lhs.rawValue < rhs.rawValue
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension CertificateSigningRequest.Version: CustomStringConvertible {
    public var description: String {
        switch self {
        case .v1:
            return "CSRv1"
        case let unknown:
            return "CSRv\(unknown.rawValue + 1)"
        }
    }
}
