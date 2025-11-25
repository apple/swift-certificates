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
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
final class Promise<Value: Sendable, Failure: Error> {
    private enum State {
        case unfulfilled(observers: [CheckedContinuation<Result<Value, Failure>, Never>])
        case fulfilled(Result<Value, Failure>)

        /// Returns the result, if available.
        ///
        /// - Parameter continuation: A continuation to store if no result is currently available.
        ///   If a result is returned from this function then the continuation will not be stored.
        /// - Returns: The result, if available.
        mutating func result(
            continuation: CheckedContinuation<Result<Value, Failure>, Never>?
        ) -> Result<Value, Failure>? {
            switch self {
            case .fulfilled(let result):
                return result
            case .unfulfilled(var observers):
                if let continuation = continuation {
                    observers.append(continuation)
                    self = .unfulfilled(observers: observers)
                }
                return nil
            }
        }
    }

    private let state = LockedValueBox(State.unfulfilled(observers: []))

    init() {}

    fileprivate var result: Result<Value, Failure> {
        get async {
            let result = self.state.withLockedValue { state in
                state.result(continuation: nil)
            }

            if let result = result {
                return result
            }

            // Holding the lock here *should* be safe but because of a bug in the runtime
            // it isn't, so drop the lock, create the continuation and then try again.
            //
            // See https://github.com/swiftlang/swift/issues/85668
            return await withCheckedContinuation { continuation in
                let result = self.state.withLockedValue { state in
                    state.result(continuation: continuation)
                }

                if let result = result {
                    continuation.resume(returning: result)
                }
            }
        }
    }

    func fulfil(with result: Result<Value, Failure>) {
        let observers = self.state.withLockedValue { state in
            switch state {
            case .fulfilled(let oldResult):
                fatalError("tried to fulfil Promise that is already fulfilled to \(oldResult). New result: \(result)")
            case .unfulfilled(let observers):
                state = .fulfilled(result)
                return observers
            }
        }

        for observer in observers {
            observer.resume(returning: result)
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

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Promise: Sendable where Value: Sendable {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Promise {
    func succeed(with value: Value) {
        self.fulfil(with: .success(value))
    }

    func fail(with error: Failure) {
        self.fulfil(with: .failure(error))
    }
}

// MARK: - Future

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
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

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Future: Sendable where Value: Sendable {}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Future {
    var value: Value {
        get async throws {
            try await result.get()
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Future where Failure == Never {
    var value: Value {
        get async {
            await result.get()
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Result where Failure == Never {
    func get() -> Success {
        switch self {
        case .success(let success):
            return success
        }
    }
}
