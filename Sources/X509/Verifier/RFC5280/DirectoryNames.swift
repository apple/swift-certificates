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

import SwiftASN1

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension NameConstraintsPolicy {
    /// Validates that a directory name matches a name constraint using RFC 5280 prefix matching.
    ///
    /// The constraint's RDNs must be a prefix of (or equal to) the directory name's RDNs,
    /// compared case-insensitively.
    @inlinable
    static func directoryNameMatchesConstraint(directoryName: DistinguishedName, constraint: DistinguishedName) -> Bool
    {
        guard constraint.count <= directoryName.count else {
            return false
        }
        for i in 0..<constraint.count {
            let constraintRDN = constraint[i]
            let nameRDN = directoryName[i]
            guard constraintRDN.count == nameRDN.count else { return false }
            for attr in constraintRDN {
                guard let nameAttr = nameRDN.first(where: { $0.type == attr.type }) else {
                    return false
                }
                if !attributeValuesEqual(attr.value, nameAttr.value) {
                    return false
                }
            }
        }
        return true
    }

    @inlinable
    static func attributeValuesEqual(
        _ lhs: RelativeDistinguishedName.Attribute.Value,
        _ rhs: RelativeDistinguishedName.Attribute.Value
    ) -> Bool {
        func extractString(_ storage: RelativeDistinguishedName.Attribute.Value.Storage) -> String? {
            switch storage {
            case .printable(let s): return s
            case .utf8(let s): return s
            case .ia5(let s): return s
            case .any: return nil
            }
        }
        if let l = extractString(lhs.storage), let r = extractString(rhs.storage) {
            return l.lowercased() == r.lowercased()
        }
        return lhs == rhs
    }
}
