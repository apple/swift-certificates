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

/// Thread-safe in-memory cache for CRLs, keyed by distribution point URI.
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public final class CRLCache: Sendable {
    private let storage: CRLCacheStorage
    public let gracePeriod: TimeInterval

    /// - Parameter gracePeriod: Extra time after nextUpdate during which a cached CRL
    ///   may still be used if a fresh one cannot be fetched. Default 24 hours.
    public init(gracePeriod: TimeInterval = 86400) {
        self.storage = CRLCacheStorage()
        self.gracePeriod = gracePeriod
    }

    /// Retrieve a valid CRL for the given URL, using cache or fetcher.
    /// Returns nil only if no valid CRL is available (even with grace period).
    public func getCRL(
        url: String,
        fetcher: any CRLFetcher,
        now: Date = Date()
    ) async -> CRLCacheResult {
        // Check cache first
        if let cached = storage.get(url), isValid(cached, now: now) {
            return .success(cached)
        }

        // Attempt fresh fetch
        let fetchResult = await fetcher.fetch(url: url)
        switch fetchResult {
        case .success(let bytes):
            guard let crl = try? CertificateRevocationList(derEncoded: bytes) else {
                return .parseError
            }
            storage.set(url, crl: crl)
            return .success(crl)

        case .networkError:
            // Fall back to grace period cache
            if let cached = storage.get(url), isWithinGracePeriod(cached, now: now) {
                return .success(cached)
            }
            return .networkError
        }
    }

    private func isValid(_ crl: CertificateRevocationList, now: Date) -> Bool {
        crl.thisUpdate <= now && (crl.nextUpdate == nil || now <= crl.nextUpdate!)
    }

    private func isWithinGracePeriod(_ crl: CertificateRevocationList, now: Date) -> Bool {
        guard let nextUpdate = crl.nextUpdate else { return crl.thisUpdate <= now }
        return crl.thisUpdate <= now && now <= nextUpdate.addingTimeInterval(gracePeriod)
    }
}

/// Result of a cache lookup.
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public enum CRLCacheResult: Sendable {
    case success(CertificateRevocationList)
    case parseError
    case networkError
}

/// Internal actor-isolated storage for CRL cache entries.
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
private final class CRLCacheStorage: @unchecked Sendable {
    private var entries: [String: CertificateRevocationList] = [:]
    private let lock = NSLock()

    func get(_ url: String) -> CertificateRevocationList? {
        lock.lock()
        defer { lock.unlock() }
        return entries[url]
    }

    func set(_ url: String, crl: CertificateRevocationList) {
        lock.lock()
        defer { lock.unlock() }
        entries[url] = crl
    }
}
