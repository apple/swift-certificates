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

// Current recommendation for a black hole function according to:
// https://forums.swift.org/t/compiler-swallows-blackhole/64305/10
// https://github.com/apple/swift/commit/1fceeab71e79dc96f1b6f560bf745b016d7fcdcf
@_optimize(none)
public func blackHole(_: some Any) {}
