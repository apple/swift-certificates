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

import Foundation

final class LockedValueBox<Value> {
    private let _lock: NSLock = .init()
    private var _value: Value

    var unsafeUnlockedValue: Value {
        get { _value }
        set { _value = newValue }
    }

    func lock() {
        _lock.lock()
    }

    func unlock() {
        _lock.unlock()
    }

    init(_ value: Value) {
        self._value = value
    }

    func withLockedValue<Result>(
        _ body: (inout Value) throws -> Result
    ) rethrows -> Result {
        try _lock.withLock {
            try body(&_value)
        }
    }
}

extension LockedValueBox: @unchecked Sendable where Value: Sendable {}

extension NSLock {
    // this API doesn't exist on Linux and therefore we have a copy of it here
    func withLock<Result>(_ body: () throws -> Result) rethrows -> Result {
        self.lock()
        defer { self.unlock() }
        return try body()
    }
}
