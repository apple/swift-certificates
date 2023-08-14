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

import XCTest
import SwiftASN1
@testable import X509

final class DNSNamesTests: XCTestCase {
    // This test data has been borrowed from the Rust webpki project.
    static let fixtures: [(String, String, Bool)] = [
        ("", "a", false),
        ("a", "a", true),
        ("b", "a", false),
        ("*.b.a", "c.b.a", false),
        ("*.b.a", "b.a", true),
        ("*.b.a", "b.a.", true),
        // Wildcard not in leftmost label
        ("d.c.b.a", "d.c.b.a", true),
        ("d.*.b.a", "d.c.b.a", false),
        ("d.c*.b.a", "d.c.b.a", false),
        ("d.c*.b.a", "d.cc.b.a", false),
        // case sensitivity
        (
            "abcdefghijklmnopqrstuvwxyz",
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            true
        ),
        (
            "ABCDEFGHIJKLMNOPQRSTUVWXYZ",
            "abcdefghijklmnopqrstuvwxyz",
            true
        ),
        ("aBc", "Abc", true),
        // digits
        ("a1", "a1", true),
        // A trailing dot indicates an absolute name, and absolute names can match
        // relative names, and vice-versa.
        ("example", "example", true),
        ("example.", "example.", false),
        ("example", "example.", true),
        ("example.", "example", false),
        ("example.com", "example.com", true),
        ("example.com.", "example.com.", false),
        ("example.com", "example.com.", true),
        ("example.com.", "example.com", false),
        ("example.com..", "example.com.", false),
        ("example.com..", "example.com", false),
        ("example.com...", "example.com.", false),
        // xn-- IDN prefix
        ("x*.b.a", "xa.b.a", false),
        ("x*.b.a", "xna.b.a", false),
        ("x*.b.a", "xn-a.b.a", false),
        ("x*.b.a", "xn--a.b.a", false),
        ("xn*.b.a", "xn--a.b.a", false),
        ("xn-*.b.a", "xn--a.b.a", false),
        ("xn--*.b.a", "xn--a.b.a", false),
        ("xn*.b.a", "xn--a.b.a", false),
        ("xn-*.b.a", "xn--a.b.a", false),
        ("xn--*.b.a", "xn--a.b.a", false),
        ("xn---*.b.a", "xn--a.b.a", false),
        // "*" cannot expand to nothing.
        ("c*.b.a", "c.b.a", false),
        // --------------------------------------------------------------------------
        // The rest of these are test cases adapted from Chromium's
        // x509_certificate_unittest.cc. The parameter order is the opposite in
        // Chromium's tests. Also, they some tests were modified to fit into this
        // framework or due to intentional differences between mozilla::pkix and
        // Chromium.
        ("foo.com", "foo.com", true),
        ("f", "f", true),
        ("i", "h", false),
        ("*.foo.com", "bar.foo.com", false),
        ("*.test.fr", "www.test.fr", false),
        ("*.test.FR", "wwW.tESt.fr", false),
        (".uk", "f.uk", false),
        ("?.bar.foo.com", "w.bar.foo.com", false),
        ("(www|ftp).foo.com", "www.foo.com", false),  // regex!
        ("www.foo.com\0", "www.foo.com", false),
        ("www.foo.com\0*.foo.com", "www.foo.com", false),
        ("ww.house.example", "www.house.example", false),
        ("www.test.org", "test.org", true),
        ("*.test.org", "test.org", true),
        ("*.org", "test.org", false),
        // '*' must be the only character in the wildcard label
        ("w*.bar.foo.com", ".bar.foo.com", false),
        ("ww*ww.bar.foo.com", ".bar.foo.com", false),
        ("ww*ww.bar.foo.com", ".bar.foo.com", false),
        ("w*w.bar.foo.com", ".bar.foo.com", false),
        ("w*w.bar.foo.c0m", ".bar.foo.com", false),
        ("wa*.bar.foo.com", ".bar.foo.com", false),
        ("*Ly.bar.foo.com", ".bar.foo.com", false),
        ("*.test.de", "www.test.co.jp", false),
        ("*.jp", "www.test.co.jp", false),
        ("www.test.co.uk", "www.test.co.jp", false),
        ("www.*.co.jp", "www.test.co.jp", false),
        ("www.bar.foo.com", "www.bar.foo.com", true),
        ("*.foo.com", "www.bar.foo.com", false),
        ("*.*.foo.com", "www.bar.foo.com", false),
        ("www.bath.org", "www.bath.org", true),

        // IDN tests
        (
            "xn--poema-9qae5a.com.br",
            "xn--poema-9qae5a.com.br",
            true
        ),
        (
            "*.xn--poema-9qae5a.com.br",
            "www.xn--poema-9qae5a.com.br",
            false
        ),
        (
            "*.xn--poema-9qae5a.com.br",
            "xn--poema-9qae5a.com.br",
            true
        ),
        ("xn--poema-*.com.br", "xn--poema-9qae5a.com.br", false),
        ("xn--*-9qae5a.com.br", "xn--poema-9qae5a.com.br", false),
        ("*--poema-9qae5a.com.br", "xn--poema-9qae5a.com.br", false),
        // The following are adapted from the examples quoted from
        //   http://tools.ietf.org/html/rfc6125#section-6.4.3
        // (e.g., *.example.com would match foo.example.com but
        // not bar.foo.example.com or example.com).
        ("*.example.com", "foo.example.com", false),
        ("*.example.com", "bar.foo.example.com", false),
        ("*.example.com", "example.com", true),
        ("baz*.example.net", "baz1.example.net", false),
        ("*baz.example.net", "foobaz.example.net", false),
        ("b*z.example.net", "buzz.example.net", false),
        // Wildcards should not be valid for public registry controlled domains,
        // and unknown/unrecognized domains, at least three domain components must
        // be present. For mozilla::pkix and NSS, there must always be at least two
        // labels after the wildcard label.
        ("*.test.example", ".test.example", true),
        ("*.example.co.uk", ".example.co.uk", true),
        ("*.example", ".example", false),
        // The result is different than Chromium, because Chromium takes into account
        // the additional knowledge it has that "co.uk" is a TLD. mozilla::pkix does
        // not know that.
        ("*.co.uk", ".co.uk", true),
        ("*.com", ".com", false),
        ("*.us", ".us", false),
        ("*", "foo", false),
        // IDN variants of wildcards and registry controlled domains.
        (
            "*.xn--poema-9qae5a.com.br",
            ".xn--poema-9qae5a.com.br",
            true
        ),
        (
            "*.example.xn--mgbaam7a8h",
            ".example.xn--mgbaam7a8h",
            true
        ),
        ("*.xn--mgbaam7a8h", ".xn--mgbaam7a8h", false),
        // Wildcards should be permissible for 'private' registry-controlled
        // domains. (In mozilla::pkix, we do not know if it is a private registry-
        // controlled domain or not.)
        ("*.appspot.com", ".appspot.com", true),
        ("*.s3.amazonaws.com", ".s3.amazonaws.com", true),
        // Multiple wildcards are not valid.
        ("*.*.com", ".com", false),
        ("*.bar.*.com", ".com", false),
        // Absolute vs relative DNS name tests. Although not explicitly specified
        // in RFC 6125, absolute reference names (those ending in a .) should
        // match either absolute or relative presented names.
        // TODO: File errata against RFC 6125 about this.
        ("foo.com.", "foo.com", false),
        ("foo.com", "foo.com.", true),
        ("foo.com.", "foo.com.", false),
        ("f.", "f", false),
        ("f", "f.", true),
        ("f.", "f.", false),
        ("*.bar.foo.com.", ".bar.foo.com", false),
        ("*.bar.foo.com", ".bar.foo.com.", true),
        ("*.bar.foo.com.", ".bar.foo.com.", false),
        ("*.com.", "example.com", false),
        ("*.com", "example.com.", false),
        ("*.com.", "example.com.", false),
        ("*.", "foo.", false),
        ("*.", "foo", false),
        // The result is different than Chromium because we don't know that co.uk is
        // a TLD.
        ("*.co.uk.", "foo.co.uk", false),
        ("*.co.uk.", "foo.co.uk.", false),

        // Empty constraint matches everything
        ("example.com", "", true),
        ("*.foo.example.com", "", true),

        // Longer constraint doesn't match.
        ("example.com", "foo.example.com", false),

        // Long domains
        //
        // Formula here: (string length * count) + (count - 1) + 7 (".com.au") == total number of bytes.
        //
        // We want to hit 254 bytes, so when "example" is the string (7 bytes) we end up at 31 repetitions, for:
        // (7 * 31) + 30 + 7 == 254.
        (Array(repeating: "example", count: 31).joined(separator: ".") + ".com.au", ".example.com.au", false),
        ("example.com.au", Array(repeating: "example", count: 31).joined(separator: ".") + ".com.au", false),

        // No hyphens beginning or ending labels
        ("-.example.com", "example.com", false),
        ("foo.-bar.example.com", "example.com", false),
        ("foo-.example.com", "example.com", false),
        ("foo-bar.example.com", "example.com", true),
        ("foo.-example.com", "-example.com", false),
        ("foo.-bar.example.com", "foo.-bar.example.com", false),
        ("foo.bar-.example.com", "foo.bar-.example.com", false),
        ("foo-bar.example.com", "foo-bar.example.com", true),

        // Long labels
        ("\(String(repeating: "a", count: 63)).example.com", "example.com", true),
        ("\(String(repeating: "a", count: 64)).example.com", "example.com", false),
        ("\(String(repeating: "a", count: 63)).example.com", "\(String(repeating: "a", count: 63)).example.com", true),
        ("\(String(repeating: "a", count: 64)).example.com", "\(String(repeating: "a", count: 64)).example.com", false),

        // All numeric labels
        ("1234567.example.com", "example.com", true),
        ("foo.1234567.example.com", "foo.1234567.example.com", true),
        ("foo.example.123", "foo.example.123", false),

        // Trailing period doesn't always match
        ("foo.com", "example.bar.", false),
        ("foo.com", "foo.www.", false),
    ]

    func testNameMatchesReference() throws {
        for (dnsName, constraint, match) in DNSNamesTests.fixtures {
            XCTAssertEqual(
                match,
                NameConstraintsPolicy.dnsNameMatchesConstraint(dnsName: dnsName.utf8, constraint: constraint.utf8),
                "Expected \(dnsName) matching \(constraint) to be \(match)"
            )
        }
    }

    func testReverseDNSLabels() throws {
        func reverse(_ string: String) -> [Substring] {
            return Array(ReverseDNSLabelSequence(string.utf8[...])).map { Substring($0) }
        }

        XCTAssertEqual(reverse("f."), ["", "f"])
        XCTAssertEqual(reverse("www-3.example.com"), ["com", "example", "www-3"])
        XCTAssertEqual(reverse("f....y."), ["", "y", "", "", "", "f"])
        XCTAssertEqual(reverse(".example.com"), ["com", "example", ""])
    }

    static func urisThatMatch(_ dnsName: String) -> [String] {
        return [
            "http://\(dnsName)/",
            "https://\(dnsName)",
            "http://user:password@\(dnsName)",
            "http://\(dnsName)/index.html",
            "https://\(dnsName)/foo/bar/baz?x=y",
            "ftp://user:password@\(dnsName):4343/cat.txt",
        ]
    }

    static func urisThatDontMatch(_ dnsName: String) -> [String] {
        return [
            // User and password parts don't match.
            "http://\(dnsName):\(dnsName)@sir.not.appearing.in.this.movie",

            // Scheme doesn't match
            "\(dnsName)://sir.not.appearing.in.this.movie/",

            // Path doesn't match
            "http://sir.not.appearing.in.this.movie/\(dnsName)/baz",

            // IP addresses never match
            "http://127.0.0.1",
            "http://[fe80::1]",

            // Neither do URIs without host components at all
            "/foo/bar",
            "\(dnsName)",
        ]
    }

    func testURINamesMatchReferenceHostname() throws {
        // This adapts the basic checks from the DNS name case, as they apply to the host part of the constraint. However,
        // to each case we add a little URI special sauce to confirm that they all still work (or don't!).
        for (dnsName, constraint, match) in DNSNamesTests.fixtures {
            for uri in DNSNamesTests.urisThatMatch(dnsName) {
                XCTAssertEqual(
                    match,
                    NameConstraintsPolicy.uriNameMatchesConstraint(uriName: uri, constraint: constraint),
                    "Expected \(uri) matching \(constraint) to be \(match)"
                )

                // Never works inverted
                XCTAssertFalse(
                    NameConstraintsPolicy.uriNameMatchesConstraint(uriName: constraint, constraint: uri),
                    "\(uri) incorrectly matched \(constraint)"
                )
            }

            if constraint == "" {
                // We don't test the "don't match" case on the empty constraint, because everything matches the empty constraint
                continue
            }

            for uri in DNSNamesTests.urisThatDontMatch(dnsName) {
                XCTAssertFalse(
                    NameConstraintsPolicy.uriNameMatchesConstraint(uriName: uri, constraint: constraint),
                    "\(uri) incorrectly matched \(constraint)"
                )
            }
        }
    }
}
