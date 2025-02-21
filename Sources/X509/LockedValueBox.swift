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

/// Provides locked access to `Value`.
///
/// - Note: ``LockedValueBox`` has reference semantics and holds the `Value`
///         alongside a lock behind a reference.
///
/// This is no different than creating a ``Lock`` and protecting all
/// accesses to a value using the lock. But it's easy to forget to actually
/// acquire/release the lock in the correct place. ``LockedValueBox`` makes
/// that much easier.
struct LockedValueBox<Value> {

    @usableFromInline
    internal let _storage: LockStorage<Value>

    /// Initialize the `Value`.
    @inlinable
    init(_ value: Value) {
        self._storage = .create(value: value)
    }

    /// Access the `Value`, allowing mutation of it.
    @inlinable
    func withLockedValue<T>(_ mutate: (inout Value) throws -> T) rethrows -> T {
        try self._storage.withLockedValue(mutate)
    }

    /// Provides an unsafe view over the lock and its value.
    ///
    /// This can be beneficial when you require fine grained control over the lock in some
    /// situations but don't want lose the benefits of ``withLockedValue(_:)`` in others by
    /// switching to ``NIOLock``.
    var unsafe: Unsafe {
        Unsafe(_storage: self._storage)
    }

    /// Provides an unsafe view over the lock and its value.
    struct Unsafe {
        @usableFromInline
        let _storage: LockStorage<Value>

        /// Manually acquire the lock.
        @inlinable
        func lock() {
            self._storage.lock()
        }

        /// Manually release the lock.
        @inlinable
        func unlock() {
            self._storage.unlock()
        }

        /// Mutate the value, assuming the lock has been acquired manually.
        ///
        /// - Parameter mutate: A closure with scoped access to the value.
        /// - Returns: The result of the `mutate` closure.
        @inlinable
        func withValueAssumingLockIsAcquired<Result>(
            _ mutate: (_ value: inout Value) throws -> Result
        ) rethrows -> Result {
            try self._storage.withUnsafeMutablePointerToHeader { value in
                try mutate(&value.pointee)
            }
        }
    }
}

extension LockedValueBox: @unchecked Sendable where Value: Sendable {}
