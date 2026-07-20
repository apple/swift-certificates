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

@usableFromInline
let ASCII_PERIOD = UInt8(ascii: ".")

@usableFromInline
let ASCII_ASTERISK = UInt8(ascii: "*")

@usableFromInline
let ASCII_HYPHEN = UInt8(ascii: "-")

@usableFromInline
let ASCII_LOWERCASE_A = UInt8(ascii: "a")

@usableFromInline
let ASCII_LOWERCASE_Z = UInt8(ascii: "z")

@usableFromInline
let ASCII_UPPERCASE_A = UInt8(ascii: "A")

@usableFromInline
let ASCII_UPPERCASE_Z = UInt8(ascii: "Z")

@usableFromInline
let ASCII_ZERO = UInt8(ascii: "0")

@usableFromInline
let ASCII_NINE = UInt8(ascii: "9")

@usableFromInline
let ASCII_UNDERSCORE = UInt8(ascii: "_")

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension NameConstraintsPolicy {
    /// Validates that a dnsName matches a name constraint.
    ///
    /// The rules on name constraints are simple. Another word would be vague.
    /// From RFC 5280 § 4.2.1.10:
    ///
    ///    DNS name restrictions are expressed as host.example.com.  Any DNS
    ///    name that can be constructed by simply adding zero or more labels to
    ///    the left-hand side of the name satisfies the name constraint.  For
    ///    example, www.host.example.com would satisfy the constraint but
    ///    host1.example.com would not.
    ///
    /// We have a number of other caveats in play, that will be commented within
    /// the body of the function as we go.
    @inlinable
    static func dnsNameMatchesConstraint(dnsName: String.UTF8View, constraint: String.UTF8View) -> Bool {
        // Before any validation: confirm that these are both valid DNS names.
        guard dnsName.isValidDNSName(isConstraint: false) && constraint.isValidDNSName(isConstraint: true) else {
            return false
        }

        // Step 0: Zero-length constraints.
        //
        // The empty constraint matches everything.
        if constraint.count == 0 {
            return true
        }

        // Step 1: Turn these to slices.
        let dnsName = dnsName[...]
        var constraint = constraint[...]

        // Step 2: If the constraint ends in a period, drop it.
        if constraint.last == ASCII_PERIOD {
            constraint = constraint.dropLast()
        }

        // Next, we get the reverse DNS labels.
        var reverseDNSNameLabels = ReverseDNSLabelSequence(dnsName).makeIterator()
        var reverseConstraintLabels = ReverseDNSLabelSequence(constraint).makeIterator()

        // We're going to walk these labels for as long as they match.
        // While we're here, we're going to confirm that none of the labels are
        // empty except, for the constraint, the last one. If they are,
        // that means that _either_ the domain name is absolute
        // _or_ there is an empty DNS label. We support neither.
        while true {
            let nextDNSNameLabel = reverseDNSNameLabels.next()
            let nextConstraintLabel = reverseConstraintLabels.next()

            switch (nextDNSNameLabel, nextConstraintLabel) {
            case (.none, .none):
                // Both sequences are empty, this is a perfect match.
                return true
            case (.some, .none):
                // We've run out of constraint labels to match. This is a match!
                return true
            case (.none, .some):
                // We've run out of DNS name labels, but there is still
                // a constraint label! Even if the constraint label is empty
                // (that is, there was a leading period), we don't match.
                return false
            case (.some(let dnsLabel), _) where dnsLabel.count == 0:
                // Empty DNS label. This is always forbidden.
                return false
            case (.some, .some(let constraintLabel)) where constraintLabel.count == 0:
                // We have an empty constraint label. This must be last, so confirm that.
                guard reverseConstraintLabels.hasMoreLabels else {
                    // The period matches everything else, so we're good to go.
                    return true
                }
                // This label is empty, and not last, which is unacceptable.
                return false
            case (.some(let dnsLabel), .some(let constraintLabel))
            where dnsLabel.caseInsensitiveASCIIMatch(constraintLabel):
                // The two labels match, continue.
                continue
            case (.some, .some):
                // Two labels don't match!
                return false
            }
        }
    }
}

extension String.UTF8View {
    // The maximum label length is 63 bytes.
    @usableFromInline
    static let maximumLabelLength = 63

    @inlinable
    func isValidDNSName(isConstraint: Bool) -> Bool {
        var bytes = self[...]
        var labelCount = 0
        var isWildcard = false

        // First check: reject long domains. Anything more than 253 bytes is no good.
        if bytes.count > 253 {
            return false
        }

        // We're going to allow a wildcard, but it must be first, and must be the whole
        // label.
        if bytes.first == ASCII_ASTERISK {
            bytes = bytes.dropFirst()
            guard let next = bytes.popFirst(), next == ASCII_PERIOD else {
                // Either there was no next byte, or it wasn't a period. Not a valid name.
                return false
            }

            labelCount += 1
            isWildcard = true
        }

        // This is not the most efficient construction, but it's a bit easier to understand than a
        // purely iterative approach. If we need to squeeze more perf out of there, we can
        // rewrite it.
        while bytes.count > 0 {
            let label: String.UTF8View.SubSequence
            if let nextPeriod = bytes.firstIndex(of: ASCII_PERIOD) {
                label = bytes[..<nextPeriod]

                let indexAfterPeriod = bytes.index(after: nextPeriod)
                bytes = bytes[indexAfterPeriod...]
            } else {
                // No periods left, the label is whatever is left.
                label = bytes
                bytes = bytes[bytes.endIndex...]
            }

            labelCount += 1

            // We forbid empty labels, unless that label is first in a name constraint.
            if label.count == 0 && !(labelCount == 1 && isConstraint) {
                return false
            }

            // We don't allow labels to start or end with a hyphen.
            if label.first == ASCII_HYPHEN || label.last == ASCII_HYPHEN {
                return false
            }

            // Labels must not exceed the max label length.
            if label.count > Self.maximumLabelLength {
                return false
            }

            // Now we want to scan for valid bytes. The scan here is doing two
            // things: counting numerics and non-numerics, and detecting non ASCII bytes.
            //
            // We are counting numerics because the most significant label must not be entirely
            // numeric. We can detect whether this is the last label because, if it is,
            // there are no more bytes left in the name.
            switch label.labelContents {
            case .allASCII(nonNumerics: let nonNumerics) where nonNumerics > 0:
                // All ASCII, and at least one non-numeric, we're good. On to the next label.
                continue
            case .allASCII where bytes.count > 0:
                // Label is all numeric, but this isn't the last label. Allowed.
                continue
            case .allASCII:
                // Last label is all numeric. Not allowed.
                assert(bytes.count == 0)
                return false
            case .nonASCII:
                // Either non-ASCII, or all numeric. Not allowed.
                return false
            }
        }

        // For wildcards, we follow NSS and require at least two labels after the wildcard.
        if isWildcard && labelCount < 3 {
            return false
        }

        // We're good!
        return true

    }
}

@usableFromInline
struct ReverseDNSLabelSequence: Sequence, Sendable {
    @usableFromInline
    var base: String.UTF8View.SubSequence

    @inlinable
    init(_ base: String.UTF8View.SubSequence) {
        self.base = base
    }

    @inlinable
    func makeIterator() -> Iterator {
        return Iterator(self.base)
    }

    @usableFromInline
    struct Iterator: IteratorProtocol, Sendable {
        @usableFromInline
        var base: String.UTF8View.SubSequence?

        @inlinable
        init(_ base: String.UTF8View.SubSequence) {
            self.base = base
        }

        @inlinable mutating func next() -> String.UTF8View.SubSequence? {
            // If we've sliced everything out, this is the end of the sequence.
            guard let base = self.base else {
                return nil
            }

            // We walk backwards from the end until we find a period, then
            // we slice out that section and return it.
            guard let periodIndex = base.lastIndex(of: ASCII_PERIOD) else {
                // No period left! Return the entirety of what is left as the label,
                // and then store nil.
                let label = base
                self.base = nil
                return label
            }
            // Ok, we found a period. Slice out that section, then drop the
            // period and save the updated base.
            let labelStartIndex = base.index(after: periodIndex)
            let label = base[labelStartIndex...]
            self.base = base[..<periodIndex]
            return label
        }

        @inlinable var hasMoreLabels: Bool {
            return self.base != nil
        }
    }
}

extension String.UTF8View.SubSequence {
    @usableFromInline
    static let asciiCaseInsensitiveMask: UInt8 = ~(1 << 5)

    @inlinable
    func caseInsensitiveASCIIMatch(_ other: Self) -> Bool {
        guard self.count == other.count else {
            return false
        }

        return self.elementsEqual(
            other,
            by: { selfByte, otherByte in
                (selfByte & Self.asciiCaseInsensitiveMask) == (otherByte & Self.asciiCaseInsensitiveMask)
            }
        )
    }

    @usableFromInline
    enum LabelContents: Sendable {
        case allASCII(nonNumerics: Int)
        case nonASCII
    }

    @inlinable
    var labelContents: LabelContents {
        var nonNumerics = 0

        for byte in self {
            switch byte {
            case ASCII_ZERO...ASCII_NINE:
                ()
            case ASCII_LOWERCASE_A...ASCII_LOWERCASE_Z,
                ASCII_UPPERCASE_A...ASCII_UPPERCASE_Z,
                ASCII_HYPHEN, ASCII_UNDERSCORE:
                nonNumerics += 1
            default:
                return .nonASCII
            }
        }

        return .allASCII(nonNumerics: nonNumerics)
    }
}
