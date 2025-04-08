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
    /// Validates that an IP address matches a constraint.
    ///
    /// The rules for IP address constraints are fairly simple. The constraint contains both a subnet
    /// and a subnet mask, while the `ipAddress` will contain just the bytes of the address. A constraint
    /// matches if the address is part of the subnet defined by the mask.
    ///
    /// Additionally, RFC 5280 requires that the constraint be equivalent to a subnet defined using CIDR notation.
    /// This implies that we do not tolerate arbitrary masks.
    @inlinable
    static func ipAddressMatchesConstraint(ipAddress: ASN1OctetString, constraint: ASN1OctetString) -> Bool {
        switch (ipAddress.bytes.count, constraint.bytes.count) {
        case (4, 8):
            // IPv4
            return addressIsInSubnet(address: ipAddress.bytes, subnet: constraint.bytes)
        case (16, 32):
            // IPv6
            return addressIsInSubnet(address: ipAddress.bytes, subnet: constraint.bytes)
        default:
            // No match or an invalid format.
            return false
        }
    }
}

extension ArraySlice<UInt8> {
    @inlinable
    var isValidCIDRMask: Bool {
        // Quick check: is the first byte zero? If it is, we can skip the rest: it matches nothing,
        // either by way of being invalid or by being all zeros.
        if self.first == 0 {
            return false
        }

        // A valid CIDR mask is a sequence of leading 1s, followed by a sequence of 0s.
        // Look for the first index that isn't all 1s.
        guard let firstInterestingIndex = self.firstIndex(where: { $0 != 0xff }) else {
            // Huh, the mask is all 1s. Fine.
            return true
        }

        let byte = self[firstInterestingIndex]

        // Count the leading 1s.
        let leadingOneCount = (~byte).leadingZeroBitCount

        // Shift off that many bits. All the bits left must be zero.
        if (byte << leadingOneCount) != 0 {
            return false
        }

        // All remaining bytes must be zero.
        let nextIndex = self.index(after: firstInterestingIndex)
        return self[nextIndex...].allSatisfy { $0 == 0 }
    }

    @inlinable
    subscript(offset offset: Int) -> UInt8 {
        return self[self.startIndex + offset]
    }
}

@inlinable
func addressIsInSubnet(address: ArraySlice<UInt8>, subnet: ArraySlice<UInt8>) -> Bool {
    assert(subnet.count == (address.count * 2))

    let base = subnet.prefix(subnet.count / 2)
    let mask = subnet.suffix(subnet.count / 2)

    guard mask.isValidCIDRMask else {
        return false
    }

    for offset in 0..<address.count {
        let maskByte = mask[offset: offset]
        if (address[offset: offset] & maskByte) != (base[offset: offset] & maskByte) {
            return false
        }
    }

    return true
}
