//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCertificates open source project
//
// Copyright (c) 2024 Apple Inc. and the SwiftCertificates project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCertificates project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

/// Protocol for fetching CRL data from a distribution point URI.
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public protocol CRLFetcher: Sendable {
    func fetch(url: String) async -> CRLFetchResult
}

/// Result of a CRL fetch operation.
public enum CRLFetchResult: Sendable {
    /// Successfully retrieved CRL bytes.
    case success([UInt8])
    /// Network or transport error prevented retrieval.
    case networkError
}
