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

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate {
    /// The X.509 certificate version.
    ///
    /// Almost all certificates in use today use X.509v3, and this should be the default for almost
    /// all use today. In very rare cases X.509v1 certificates can be found, but they should be avoided in
    /// almost all cases.
    public struct Version {
        @usableFromInline
        var rawValue: Int

        @inlinable
        init(rawValue: Int) {
            self.rawValue = rawValue
        }

        /// Corresponds to an X.509 v1 certificate.
        public static let v1 = Self(rawValue: 0)

        /// Corresponds to an X.509 v3 certificate
        public static let v3 = Self(rawValue: 2)
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.Version: Hashable {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.Version: Sendable {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.Version: Comparable {
    @inlinable
    public static func < (lhs: Certificate.Version, rhs: Certificate.Version) -> Bool {
        lhs.rawValue < rhs.rawValue
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate.Version: CustomStringConvertible {
    public var description: String {
        switch self {
        case .v1:
            return "X509v1"
        case .v3:
            return "X509v3"
        case let unknown:
            return "X509v\(unknown.rawValue + 1)"
        }
    }
}
