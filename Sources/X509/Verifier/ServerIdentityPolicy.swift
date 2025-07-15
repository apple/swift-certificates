//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCertificates open source project
//
// Copyright (c) 2024 Apple Inc. and the SwiftCertificates project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCertificates project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import SwiftASN1
#if os(Windows)
import WinSDK
#elseif canImport(Android)
import Android
#elseif canImport(Glibc)
import Glibc
#elseif canImport(Musl)
import Musl
#endif

/// A ``VerifierPolicy`` that validates that the leaf certificate is authoritative
/// for a given hostname or IP address.
///
/// This policy is most commonly used to validate the leaf certificate presented by a server
/// during a TLS handshake.
///
/// This policy implements the logic for service validation as specified by
/// RFC 6125 (https://tools.ietf.org/search/rfc6125), which loosely speaking
/// defines the common algorithm used for validating that an X.509 certificate
/// is valid for a given service
public struct ServerIdentityPolicy: Sendable {
    @usableFromInline
    var serverHostname: LazyServerHostname?

    // This field is `var` becuase we lazily convert from String to something more useful, if needed.
    @usableFromInline
    var serverIP: LazyIPAddress?

    /// Constructs a new ``ServerIdentityPolicy``.
    ///
    /// - parameters:
    ///     - serverHostname: The hostname used to connect to the server.
    ///     - serverIP: The IP address of the server, if known.
    @inlinable
    public init(
        serverHostname: String?,
        serverIP: String?
    ) {
        self.serverHostname = serverHostname.map { .string($0) }
        self.serverIP = serverIP.map { .string($0) }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension ServerIdentityPolicy: VerifierPolicy {
    @inlinable
    public var verifyingCriticalExtensions: [ASN1ObjectIdentifier] {
        [.X509ExtensionID.subjectAlternativeName]
    }

    @inlinable
    public mutating func chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain) -> PolicyEvaluationResult {
        let targetIP = self.serverIP.convert()
        let targetHostname = self.serverHostname.convert()

        // We only validate the leaf node in this policy.
        //
        // Note that we also deliberately call a non-inlinable method here. That's to avoid
        // littering the repo with things that shouldn't be at internal visibility. As a practical
        // matter the worst possible outcome here is some excess retain/releases, none of the
        // code is generic, so this is basically acceptable.
        return chain.leaf.hasValidIdentityForService(
            serverHostname: targetHostname,
            serverIP: targetIP
        )
    }
}

extension ServerIdentityPolicy {
    @usableFromInline
    enum IPAddress: Sendable {
        case v4(in_addr)
        case v6(in6_addr)
    }

    @usableFromInline
    enum LazyIPAddress: Sendable {
        case ipAddress(IPAddress)
        case string(String)
    }

    @usableFromInline
    enum LazyServerHostname: Sendable {
        case string(String)
        case prepared(PreparedServerHostname)
    }

    @usableFromInline
    struct PreparedServerHostname: Sendable {
        var bytes: ArraySlice<UInt8>
        var firstPeriodIndex: ArraySlice<UInt8>.Index?

        /// Creates an `PreparedServerHostname`
        ///
        /// This consists of a non-NULL-terminated sequence of ASCII bytes and the index of the
        /// first period in that hostname.
        ///
        /// If the string this method is called on contains non-ACSII code points, this constructor fails.
        ///
        /// This constructor exists to avoid doing repeated loops over the string buffer.
        /// In a naive implementation we'd loop at least four times: once to lowercase
        /// the string, once to get a buffer pointer to a contiguous buffer, once
        /// to confirm the string is ASCII, and once to find the first period for matching wildcards.
        /// Here we can do that all in one loop.
        @usableFromInline
        init?(lowercaseASCIIBytes string: String) {
            let utf8View = string.utf8
            self.firstPeriodIndex = nil

            var value: [UInt8] = []
            value.reserveCapacity(utf8View.count)

            for codeUnit in utf8View {
                guard codeUnit.isValidDNSCharacter else {
                    return nil
                }

                if self.firstPeriodIndex == nil && codeUnit == asciiPeriod {
                    // This is tricky and not generically correct, but it's safe for Array.
                    self.firstPeriodIndex = value.endIndex
                }

                // We know we have only ASCII printables, we can safely unconditionally set the 6 bit to 1 to lowercase.
                value.append(codeUnit | (0x20))
            }

            self.bytes = value[...]

            // Strip trailing period.
            if self.bytes.last == asciiPeriod {
                self.bytes = self.bytes.dropLast()
            }
        }
    }

    // This should really be an init, but weird compiler issues have prevented it from being one.
    @_spi(Testing)
    public static func parsingIPv4Address(_ string: String) -> in_addr? {
        var value = in_addr()

        let rc = string.withCString {
            inet_pton(AF_INET, $0, &value)
        }

        if rc != 1 { return nil }
        return value
    }

    // This should really be an init, but weird compiler issues have prevented it from being one.
    @_spi(Testing)
    public static func parsingIPv6Address(_ string: String) -> in6_addr? {
        var value = in6_addr()

        let rc = string.withCString {
            inet_pton(AF_INET6, $0, &value)
        }

        if rc != 1 { return nil }
        return value
    }
}

extension Optional where Wrapped == ServerIdentityPolicy.LazyIPAddress {
    /// Converts the value from string to one of the IP address cases and
    /// returns it.
    ///
    /// Does nothing if the value is nil.
    @usableFromInline
    mutating func convert() -> ServerIdentityPolicy.IPAddress? {
        switch self {
        case .some(.ipAddress(let address)):
            return address
        case .some(.string(let value)):
            if let v4 = ServerIdentityPolicy.parsingIPv4Address(value) {
                self = .some(.ipAddress(.v4(v4)))
                return .v4(v4)
            } else if let v6 = ServerIdentityPolicy.parsingIPv6Address(value) {
                self = .some(.ipAddress(.v6(v6)))
                return .v6(v6)
            } else {
                // This is fine, if we can't convert the IP address
                // it's just not eligible to match anything.
                self = .none
                return nil
            }
        case .none:
            return nil
        }
    }
}

extension Optional where Wrapped == ServerIdentityPolicy.LazyServerHostname {
    /// Converts the value from string to the prepared case and
    /// returns it.
    ///
    /// Does nothing if the value is nil. Nils the value if the conversion fails.
    @usableFromInline
    mutating func convert() -> ServerIdentityPolicy.PreparedServerHostname? {
        switch self {
        case .none:
            return nil
        case .some(.string(let string)):
            guard let prepared = ServerIdentityPolicy.PreparedServerHostname(lowercaseASCIIBytes: string) else {
                // failed to convert, don't try.
                self = .none
                return nil
            }

            self = .some(.prepared(prepared))
            return prepared
        case .some(.prepared(let prepared)):
            return prepared
        }
    }
}

extension ServerIdentityPolicy.IPAddress {
    init?(sanField: ASN1OctetString) {
        switch sanField.bytes.count {
        case 4:
            let addr = sanField.bytes.withUnsafeBufferPointer {
                UnsafeRawPointer($0.baseAddress!).loadUnaligned(as: in_addr.self)
            }
            self = .v4(addr)
        case 16:
            let addr = sanField.bytes.withUnsafeBufferPointer {
                UnsafeRawPointer($0.baseAddress!).loadUnaligned(as: in6_addr.self)
            }
            self = .v6(addr)
        default:
            return nil
        }
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate {
    /// Validates that a given leaf certificate is valid for a service.
    ///
    /// This function implements the logic for service validation as specified by
    /// RFC 6125 (https://tools.ietf.org/search/rfc6125), which loosely speaking
    /// defines the common algorithm used for validating that an X.509 certificate
    /// is valid for a given service
    ///
    /// The algorithm we're implementing is specified in RFC 6125 Section 6 if you want to
    /// follow along at home.
    @usableFromInline
    internal func hasValidIdentityForService(
        serverHostname: ServerIdentityPolicy.PreparedServerHostname?,
        serverIP: ServerIdentityPolicy.IPAddress?
    ) -> PolicyEvaluationResult {
        // We want to begin by checking the subjectAlternativeName fields. If there are any fields
        // in there that we could validate against (either IP or hostname) we will validate against
        // them, and then refuse to check the commonName field. If there are no SAN fields to
        // validate against, we'll check commonName.
        //
        // If the SAN field is invalid and we can't parse it, we fail.
        let subjectAlternativeNames: SubjectAlternativeNames
        do {
            subjectAlternativeNames = try self.extensions.subjectAlternativeNames ?? SubjectAlternativeNames()
        } catch {
            return .failsToMeetPolicy(reason: "Error parsing SAN field, cert cannot be trusted: \(error)")
        }

        var checkedMatch = false
        for name in subjectAlternativeNames {
            checkedMatch = true

            switch name {
            case .dnsName(let dnsName):
                if Self.matchHostname(serverHostname: serverHostname, dnsName: dnsName) {
                    return .meetsPolicy
                }
            case .ipAddress(let ipAddressBytes):
                if let serverIP = serverIP,
                    let certificateIP = ServerIdentityPolicy.IPAddress(sanField: ipAddressBytes),
                    Self.matchIpAddress(serverIP: serverIP, certificateIP: certificateIP)
                {
                    return .meetsPolicy
                }
            default:
                continue
            }
        }

        guard !checkedMatch else {
            // We had some subject alternative names, but none matched. We failed here.
            return .failsToMeetPolicy(reason: "None of the names in SAN extension matched: \(subjectAlternativeNames)")
        }

        // In the absence of any matchable subjectAlternativeNames, we can fall back to checking
        // the common name. This is a deprecated practice, and in a future release we should
        // stop doing this.
        //
        // As distinguished names move from least significant to most significant, we actually
        // want the _last_ CN value.
        guard let commonName = self.subject.lastCommonName else {
            // No CN, no match.
            return .failsToMeetPolicy(reason: "No SAN extension and no common name")
        }

        // We have a common name. Let's check it against the provided hostname. We never check
        // the common name against the IP address.
        guard let cn = String(commonName), Self.matchHostname(serverHostname: serverHostname, dnsName: cn) else {
            return .failsToMeetPolicy(reason: "Common name \(commonName) does not match expected hostname")
        }

        return .meetsPolicy
    }

    private static func matchHostname(
        serverHostname: ServerIdentityPolicy.PreparedServerHostname?,
        dnsName: String
    ) -> Bool {
        guard let serverHostname else {
            // No server hostname was provided, so we cannot match.
            return false
        }

        // Now we validate the cert hostname.
        guard let validatedHostname = AnalysedCertificateHostname(baseName: dnsName.utf8) else {
            // This is a hostname we can't match, return false.
            return false
        }
        return validatedHostname.validMatchForName(serverHostname)
    }

    private static func matchIpAddress(
        serverIP: ServerIdentityPolicy.IPAddress,
        certificateIP: ServerIdentityPolicy.IPAddress
    ) -> Bool {
        // These match if the two underlying IP address structures match.
        switch (serverIP, certificateIP) {
        case (.v4(var addr1), .v4(var addr2)):
            return memcmp(&addr1, &addr2, MemoryLayout<in_addr>.size) == 0
        case (.v6(var addr1), .v6(var addr2)):
            return memcmp(&addr1, &addr2, MemoryLayout<in6_addr>.size) == 0
        default:
            // Different protocol families, no match.
            return false
        }
    }
}

extension DistinguishedName {
    // TODO: We should have a bunch of these as API.
    var lastCommonName: RelativeDistinguishedName.Attribute.Value? {
        for rdn in self.reversed() {
            for ava in rdn.reversed() {
                if ava.type == .RDNAttributeType.commonName {
                    return ava.value
                }
            }
        }

        return nil
    }
}

private let asciiIDNAIdentifier: ArraySlice<UInt8> = Array("xn--".utf8)[...]
private let asciiCapitals: ClosedRange<UInt8> = (UInt8(ascii: "A")...UInt8(ascii: "Z"))
private let asciiLowercase: ClosedRange<UInt8> = (UInt8(ascii: "a")...UInt8(ascii: "z"))
private let asciiNumbers: ClosedRange<UInt8> = (UInt8(ascii: "0")...UInt8(ascii: "9"))
private let asciiHyphen: UInt8 = UInt8(ascii: "-")
private let asciiPeriod: UInt8 = UInt8(ascii: ".")
private let asciiAsterisk: UInt8 = UInt8(ascii: "*")

extension Collection {
    /// Splits a collection in two around a given index. This index may be nil, in which case the split
    /// will occur around the end.
    fileprivate func splitAroundIndex(_ index: Index?) -> (SubSequence, SubSequence) {
        guard let index = index else {
            return (self[...], self[self.endIndex...])
        }

        let subsequentIndex = self.index(after: index)
        return (self[..<index], self[subsequentIndex...])
    }
}

extension Sequence<UInt8> {
    fileprivate func caseInsensitiveElementsEqual(_ other: some Sequence<UInt8>) -> Bool {
        self.elementsEqual(other) { $0.lowercased() == $1.lowercased() }
    }
}

extension UInt8 {
    /// Whether this character is a valid DNS character, which is the ASCII
    /// letters, digits, the hypen, and the period.
    fileprivate var isValidDNSCharacter: Bool {
        switch self {
        case asciiCapitals, asciiLowercase, asciiNumbers, asciiHyphen, asciiPeriod:
            return true
        default:
            return false
        }
    }

    fileprivate func lowercased() -> UInt8 {
        asciiCapitals.contains(self) ? self | 0x20 : self
    }
}

/// This structure contains a certificate hostname that has been analysed and prepared for matching.
///
/// A certificate hostname that is valid for matching meets the following criteria:
///
/// 1. Contains only valid DNS characters, plus the ASCII asterisk.
/// 2. Contains zero or one ASCII asterisks.
/// 3. Any ASCII asterisk present must be in the first DNS label (i.e. before the first period).
/// 4. If the first label contains an ASCII asterisk, it must not also be an IDN A label.
///
/// Answering these questions potentially relies on multiple searches through the hostname. That's not
/// ideal: it'd be better to do a single search that both validates the domain name meets the criteria
/// and that also records information needed to validate that the name matches the one we're searching for.
/// That's what this structure does.
private struct AnalysedCertificateHostname<
    BaseNameType: BidirectionalCollection
> where BaseNameType.Element == UInt8 {
    private var name: NameType

    fileprivate init?(baseName: BaseNameType) {
        var baseName = baseName[...]

        // First, strip a trailing period from this name.
        if baseName.last == .some(asciiPeriod) {
            baseName = baseName.dropLast()
        }

        // Ok, start looping.
        var index = baseName.startIndex
        var firstPeriodIndex: BaseNameType.Index?
        var asteriskIndex: BaseNameType.Index?

        while index < baseName.endIndex {
            switch baseName[index] {
            case asciiPeriod where firstPeriodIndex == nil:
                // This is the first period we've seen, great. Future
                // periods will be ignored.
                firstPeriodIndex = index

            case asciiCapitals, asciiLowercase, asciiNumbers, asciiHyphen, asciiPeriod:
                // Valid character, no notes.
                break

            case asciiAsterisk where asteriskIndex == nil && firstPeriodIndex == nil:
                // Found an asterisk, it's the first one, and it precedes any periods.
                asteriskIndex = index

            case asciiAsterisk:
                // An extra asterisk, or an asterisk after a period, is unacceptable.
                return nil

            default:
                // Unacceptable character in the name.
                return nil
            }

            baseName.formIndex(after: &index)
        }

        // Now we can finally initialize ourself.
        if let asteriskIndex = asteriskIndex {
            // One final check: if we found a wildcard, we need to confirm that the first label isn't an IDNA A label.
            if baseName.prefix(4).caseInsensitiveElementsEqual(asciiIDNAIdentifier) {
                return nil
            }

            self.name = .wildcard(baseName, asteriskIndex: asteriskIndex, firstPeriodIndex: firstPeriodIndex)
        } else {
            self.name = .singleName(baseName)
        }
    }

    /// Whether this parsed name is a valid match for the one passed in.
    fileprivate func validMatchForName(
        _ target: ServerIdentityPolicy.PreparedServerHostname
    ) -> Bool {
        switch self.name {
        case .singleName(let baseName):
            // For non-wildcard names, we just do a straightforward comparison.
            return baseName.caseInsensitiveElementsEqual(target.bytes)

        case .wildcard(let baseName, asteriskIndex: let asteriskIndex, firstPeriodIndex: let firstPeriodIndex):
            // The wildcard can appear more-or-less anywhere in the first label. The wildcard
            // character itself can match any number of characters, though it must match at least
            // one.
            // The algorithm for this is simple: first, we split the two names on their first period to get their
            // first label and their subsequent components. Second, we check that the subcomponents match a straightforward
            // bytewise comparison: if that fails, we can avoid the expensive wildcard checking operation.
            // Third, we split the wildcard label on the wildcard character, and and confirm that
            // the characters *before* the wildcard are the prefix of the target first label, and that the
            // characters *after* the wildcard are the suffix of the target first label. This works well because
            // the empty string is a prefix and suffix of all strings.
            let (wildcardLabel, remainingComponents) = baseName.splitAroundIndex(firstPeriodIndex)
            let (targetFirstLabel, targetRemainingComponents) = target.bytes.splitAroundIndex(target.firstPeriodIndex)

            guard remainingComponents.caseInsensitiveElementsEqual(targetRemainingComponents) else {
                // Wildcard is irrelevant, the remaining components don't match.
                return false
            }

            guard targetFirstLabel.count >= wildcardLabel.count else {
                // The target label cannot possibly match the wildcard.
                return false
            }

            let (wildcardLabelPrefix, wildcardLabelSuffix) = wildcardLabel.splitAroundIndex(asteriskIndex)
            let targetBeforeWildcard = targetFirstLabel.prefix(wildcardLabelPrefix.count)
            let targetAfterWildcard = targetFirstLabel.suffix(wildcardLabelSuffix.count)

            let leadingBytesMatch = targetBeforeWildcard.caseInsensitiveElementsEqual(wildcardLabelPrefix)
            let trailingBytesMatch = targetAfterWildcard.caseInsensitiveElementsEqual(wildcardLabelSuffix)

            return leadingBytesMatch && trailingBytesMatch
        }
    }
}

extension AnalysedCertificateHostname {
    private enum NameType {
        case wildcard(
            BaseNameType.SubSequence,
            asteriskIndex: BaseNameType.Index,
            firstPeriodIndex: BaseNameType.Index?
        )
        case singleName(BaseNameType.SubSequence)
    }
}
