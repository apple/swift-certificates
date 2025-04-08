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

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
#if os(Windows)
import WinSDK
#elseif canImport(Glibc)
import Glibc
import CoreFoundation
#elseif canImport(Musl)
import Musl
import CoreFoundation
#elseif canImport(Darwin)
import Darwin
#elseif canImport(Android)
import Android
import CoreFoundation
#endif

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension NameConstraintsPolicy {
    /// Validates that a URI name matches a name constraint.
    ///
    /// From RFC 5280:
    ///
    ///    For URIs, the constraint applies to the host part of the name.  The
    ///    constraint MUST be specified as a fully qualified domain name and MAY
    ///    specify a host or a domain.  Examples would be "host.example.com" and
    ///    ".example.com".  When the constraint begins with a period, it MAY be
    ///    expanded with one or more labels.  That is, the constraint
    ///    ".example.com" is satisfied by both host.example.com and
    ///    my.host.example.com.  However, the constraint ".example.com" is not
    ///    satisfied by "example.com".  When the constraint does not begin with
    ///    a period, it specifies a host.  If a constraint is applied to the
    ///    uniformResourceIdentifier name form and a subsequent certificate
    ///    includes a subjectAltName extension with a uniformResourceIdentifier
    ///    that does not include an authority component with a host name
    ///    specified as a fully qualified domain name (e.g., if the URI either
    ///    does not include an authority component or includes an authority
    ///    component in which the host name is specified as an IP address), then
    ///    the application MUST reject the certificate.
    @inlinable
    static func uriNameMatchesConstraint(uriName: String, constraint: String) -> Bool {
        // If we can't parse the URL, the constraint is definitely not satisfied.
        // If there is no authority component then the last rule above applies.
        guard let parsed = URL(string: uriName), let host = parsed.host else {
            return false
        }

        if host.isIPAddress {
            // IP addresses are forbidden if there is a constraint.
            return false
        }

        // From this point, we can do regular domain matching.
        return Self.dnsNameMatchesConstraint(dnsName: host.utf8, constraint: constraint.utf8)

    }
}

extension String {
    @inlinable
    var isIPAddress: Bool {
        #if os(Windows)
        var v4: IN_ADDR = IN_ADDR()
        var v6: IN6_ADDR = IN6_ADDR()
        return self.withCString(encodedAs: UTF16.self) {
            return InetPtonW(AF_INET, $0, &v4) == 1 || InetPtonW(AF_INET6, $0, &v6) == 1
        }
        #else
        // We need some scratch space to let inet_pton write into.
        var ipv4Addr = in_addr()
        var ipv6Addr = in6_addr()
        return self.withCString { ptr in
            return inet_pton(AF_INET, ptr, &ipv4Addr) == 1 || inet_pton(AF_INET6, ptr, &ipv6Addr) == 1
        }
        #endif
    }
}
