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
extension NameConstraintsPolicy {
    /// Validates that a directory name matches a name constraint.
    ///
    /// There's a complex algorithm for doing proper directory name constraints validation.
    /// However, most implementations don't bother, and just directly compare the distinguished
    /// names.
    @inlinable
    static func directoryNameMatchesConstraint(directoryName: DistinguishedName, constraint: DistinguishedName) -> Bool
    {
        return directoryName == constraint
    }
}
