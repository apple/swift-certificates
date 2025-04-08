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

// MARK: - Promise
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, *)
final class Promise<Value: Sendable, Failure: Error> {
    private enum State {
        case unfulfilled(observers: [CheckedContinuation<Result<Value, Failure>, Never>])
        case fulfilled(Result<Value, Failure>)
    }

    private let state = LockedValueBox(State.unfulfilled(observers: []))

    init() {}

    fileprivate var result: Result<Value, Failure> {
        get async {
            self.state.unsafe.lock()

            switch self.state.unsafe.withValueAssumingLockIsAcquired({ $0 }) {
            case .fulfilled(let result):
                defer { self.state.unsafe.unlock() }
                return result
            case .unfulfilled(var observers):
                return await withCheckedContinuation {
                    (continuation: CheckedContinuation<Result<Value, Failure>, Never>) in
                    observers.append(continuation)
                    self.state.unsafe.withValueAssumingLockIsAcquired { value in
                        value = .unfulfilled(observers: observers)
                    }
                    self.state.unsafe.unlock()
                }
            }
        }
    }

    func fulfil(with result: Result<Value, Failure>) {
        self.state.withLockedValue { state in
            switch state {
            case .fulfilled(let oldResult):
                fatalError("tried to fulfil Promise that is already fulfilled to \(oldResult). New result: \(result)")
            case .unfulfilled(let observers):
                for observer in observers {
                    observer.resume(returning: result)
                }
                state = .fulfilled(result)
            }
        }
    }

    deinit {
        self.state.withLockedValue {
            switch $0 {
            case .fulfilled:
                break
            case .unfulfilled:
                fatalError("unfulfilled Promise leaked")
            }
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, *)
extension Promise: Sendable where Value: Sendable {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, *)
extension Promise {
    func succeed(with value: Value) {
        self.fulfil(with: .success(value))
    }

    func fail(with error: Failure) {
        self.fulfil(with: .failure(error))
    }
}

// MARK: - Future

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, *)
struct Future<Value: Sendable, Failure: Error> {
    private let promise: Promise<Value, Failure>

    init(_ promise: Promise<Value, Failure>) {
        self.promise = promise
    }

    var result: Result<Value, Failure> {
        get async {
            await promise.result
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, *)
extension Future: Sendable where Value: Sendable {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, *)
extension Future {
    var value: Value {
        get async throws {
            try await result.get()
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, *)
extension Future where Failure == Never {
    var value: Value {
        get async {
            await result.get()
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, *)
extension Result where Failure == Never {
    func get() -> Success {
        switch self {
        case .success(let success):
            return success
        }
    }
}
