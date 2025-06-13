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

/// Implement the ``CustomCertificateStore`` if you want to perform dynamic
/// certificate lookup, or if you need custom logic when matching the
/// ``DistinguishedName`` of an Issuer with the Subject of the issuer
/// certificate, then implement a custom certificate store used by the
/// ```Verifier```.
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public protocol CustomCertificateStore: Sendable, Hashable {
    /// Obtain a list of certificates which has a given subject. Note that this
    /// is an async method so that database lookups can be performed
    /// asynchronously.
    subscript(subject: DistinguishedName) -> [Certificate]? {
        get async
    }

    /// Validate if a given certificate is known to exist in this certificate
    /// store. Note that this is an async method so that the existence check
    /// can be performed against a database.
    func contains(_ certificate: Certificate) async -> Bool

    /// Add a certificate to this certificate store.
    mutating func append(contentsOf certificates: some Sequence<Certificate>)
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
@usableFromInline
struct AnyCustomCertificateStore: CustomCertificateStore {
    @usableFromInline
    var value: any DynCustomCertificateStore

    @usableFromInline
    init<T: CustomCertificateStore>(_ value: T) {
        self.value = Backing(value)
    }

    @inlinable
    subscript(subject: DistinguishedName) -> [Certificate]? {
        get async {
            await value[subject]
        }
    }

    @inlinable
    func contains(_ certificate: Certificate) async -> Bool {
        await value.contains(certificate)
    }

    @inlinable
    mutating func append(contentsOf certificates: some Sequence<Certificate>) {
        value.append(contentsOf: certificates)
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension AnyCustomCertificateStore: Hashable {
    public static func == (lhs: AnyCustomCertificateStore, rhs: AnyCustomCertificateStore) -> Bool {
        return lhs.value.isEqual(rhs.value, recurse: true)
    }

    public var hashValue: Int {
        return value.hashValue
    }

    public func hash(into hasher: inout Hasher) {
        value.hash(into: &hasher)
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension AnyCustomCertificateStore {
    @usableFromInline
    protocol DynCustomCertificateStore: CustomCertificateStore {
        func isEqual(_ rhs: any DynCustomCertificateStore, recurse: Bool) -> Bool
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension AnyCustomCertificateStore {
    struct Backing<T: CustomCertificateStore>: DynCustomCertificateStore {
        var value: T

        init(_ value: T) {
            self.value = value
        }

        subscript(subject: DistinguishedName) -> [Certificate]? {
            get async {
                await value[subject]
            }
        }

        func contains(_ certificate: Certificate) async -> Bool {
            await value.contains(certificate)
        }

        @inlinable
        mutating func append(contentsOf certificates: some Sequence<Certificate>) {
            value.append(contentsOf: certificates)
        }

        func isEqual(_ rhs: any DynCustomCertificateStore, recurse: Bool) -> Bool {
            guard let rhs = rhs as? Self else {
                guard recurse else {
                    return false
                }
                return rhs.isEqual(self, recurse: false)
            }
            return self == rhs
        }
    }
}
