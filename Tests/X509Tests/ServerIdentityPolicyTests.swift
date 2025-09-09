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
import XCTest
import Crypto
import SwiftASN1
@_spi(Testing) import X509

private let key = Certificate.PrivateKey(P256.Signing.PrivateKey())
private let certName = try! DistinguishedName {
    CommonName("httpbin.org")
}
private let localhostName = try! DistinguishedName {
    CommonName("localhost")
}
private let multiCNName = try! DistinguishedName {
    CountryName("US")
    CommonName("Ignore me")
    StateOrProvinceName("Nebraska")
    CommonName("localhost")
}
private let noCNName = try! DistinguishedName {
    CountryName("US")
    StateOrProvinceName("Nebraska")
}
private let unicodeCNName = try! DistinguishedName {
    CommonName("straße.org")
}

/// This cert contains the following SAN fields:
/// DNS:*.WILDCARD.EXAMPLE.com - A straightforward wildcard, should be accepted
/// DNS:FO*.EXAMPLE.com - A suffix wildcard, should be accepted
/// DNS:*AR.EXAMPLE.com - A prefix wildcard, should be accepted
/// DNS:B*Z.EXAMPLE.com - An infix wildcard
/// DNS:TRAILING.PERIOD.EXAMPLE.com. - A domain with a trailing period, should match
/// DNS:XN--STRAE-OQA.UNICODE.EXAMPLE.com. - An IDN A-label, should match.
/// DNS:XN--X*-GIA.UNICODE.EXAMPLE.com. - An IDN A-label with a wildcard, invalid.
/// DNS:WEIRDWILDCARD.*.EXAMPLE.com. - A wildcard not in the leftmost label, invalid.
/// DNS:*.*.DOUBLE.EXAMPLE.com. - Two wildcards, invalid.
/// DNS:*.XN--STRAE-OQA.EXAMPLE.com. - A wildcard followed by a new IDN A-label, this is fine.
/// A SAN with a null in it, should be ignored.
///
/// This also contains a commonName of httpbin.org.
private let weirdoSANCert = try! Certificate(
    version: .v3,
    serialNumber: Certificate.SerialNumber(),
    publicKey: key.publicKey,
    notValidBefore: Date() - .days(1),
    notValidAfter: Date() + .days(354),
    issuer: certName,
    subject: certName,
    signatureAlgorithm: .ecdsaWithSHA256,
    extensions: Certificate.Extensions {
        BasicConstraints.notCertificateAuthority

        SubjectAlternativeNames([
            // A straightforward wildcard, should be accepted
            .dnsName("*.WILDCARD.EXAMPLE.com"),

            // A suffix wildcard, should be accepted
            .dnsName("FO*.EXAMPLE.com"),

            /// A prefix wildcard, should be accepted
            .dnsName("*AR.EXAMPLE.com"),

            /// An infix wildcard
            .dnsName("B*Z.EXAMPLE.com"),

            /// A domain with a trailing period, should match
            .dnsName("TRAILING.PERIOD.EXAMPLE.com."),

            /// An IDN A-label, should match.
            .dnsName("XN--STRAE-OQA.UNICODE.EXAMPLE.com."),

            /// An IDN A-label with a wildcard, invalid.
            .dnsName("XN--X*-GIA.UNICODE.EXAMPLE.com."),

            /// A wildcard not in the leftmost label, invalid.
            .dnsName("WEIRDWILDCARD.*.EXAMPLE.com."),

            /// Two wildcards, invalid.
            .dnsName("*.*.DOUBLE.EXAMPLE.com."),

            /// A wildcard followed by a new IDN A-label, this is fine.
            .dnsName("*.XN--STRAE-OQA.EXAMPLE.com."),

            /// A SAN with a null in it, should be ignored.
            .dnsName("\u{0000}"),
        ])

    },
    issuerPrivateKey: key
)

private let multiSANCert = try! Certificate(
    version: .v3,
    serialNumber: Certificate.SerialNumber(),
    publicKey: key.publicKey,
    notValidBefore: Date() - .days(1),
    notValidAfter: Date() + .days(354),
    issuer: localhostName,
    subject: localhostName,
    signatureAlgorithm: .ecdsaWithSHA256,
    extensions: Certificate.Extensions {
        BasicConstraints.notCertificateAuthority

        SubjectAlternativeNames([
            .dnsName("localhost"),
            .dnsName("example.com"),
            .rfc822Name("user@example.com"),
            .ipAddress(ASN1OctetString(ipv4Address: "192.168.0.1")),
            .ipAddress(ASN1OctetString(ipv6Address: "2001:DB8:0:0:0:0:0:1")),
        ])

    },
    issuerPrivateKey: key
)
private let multiCNCert = try! Certificate(
    version: .v3,
    serialNumber: Certificate.SerialNumber(),
    publicKey: key.publicKey,
    notValidBefore: Date() - .days(1),
    notValidAfter: Date() + .days(354),
    issuer: multiCNName,
    subject: multiCNName,
    signatureAlgorithm: .ecdsaWithSHA256,
    extensions: Certificate.Extensions {
        BasicConstraints.notCertificateAuthority
    },
    issuerPrivateKey: key
)
private let noCNCert = try! Certificate(
    version: .v3,
    serialNumber: Certificate.SerialNumber(),
    publicKey: key.publicKey,
    notValidBefore: Date() - .days(1),
    notValidAfter: Date() + .days(354),
    issuer: noCNName,
    subject: noCNName,
    signatureAlgorithm: .ecdsaWithSHA256,
    extensions: Certificate.Extensions {
        BasicConstraints.notCertificateAuthority
    },
    issuerPrivateKey: key
)
private let unicodeCNCert = try! Certificate(
    version: .v3,
    serialNumber: Certificate.SerialNumber(),
    publicKey: key.publicKey,
    notValidBefore: Date() - .days(1),
    notValidAfter: Date() + .days(354),
    issuer: unicodeCNName,
    subject: unicodeCNName,
    signatureAlgorithm: .ecdsaWithSHA256,
    extensions: Certificate.Extensions {
        BasicConstraints.notCertificateAuthority
    },
    issuerPrivateKey: key
)

// All tests in this class are deprecated.
final class ServerIdentityPolicyTestsDeprecated: XCTestCase {
    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    func testCanValidateHostnameInFirstSan() async throws {
        let roots = CertificateStore([multiSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "localhost", serverIP: nil)
            }
        )
        await XCTAssertValidCertificateDeprecated(
            await verifier.validate(
                leafCertificate: multiSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    func testCanValidateHostnameInSecondSan() async throws {
        let roots = CertificateStore([multiSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "example.com", serverIP: nil)
            }
        )
        await XCTAssertValidCertificateDeprecated(
            await verifier.validate(
                leafCertificate: multiSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    func testIgnoresTrailingPeriod() async throws {
        let roots = CertificateStore([multiSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "example.com.", serverIP: nil)
            }
        )
        await XCTAssertValidCertificateDeprecated(
            await verifier.validate(
                leafCertificate: multiSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    func testLowercasesHostnameForSan() async throws {
        let roots = CertificateStore([multiSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "LoCaLhOsT", serverIP: nil)
            }
        )
        await XCTAssertValidCertificateDeprecated(
            await verifier.validate(
                leafCertificate: multiSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    func testRejectsIncorrectHostname() async throws {
        let roots = CertificateStore([multiSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "httpbin.org", serverIP: nil)
            }
        )
        await XCTAssertInvalidCertificateDeprecated(
            await verifier.validate(
                leafCertificate: multiSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    func testAcceptsIpv4Address() async throws {
        let roots = CertificateStore([multiSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: nil, serverIP: "192.168.0.1")
            }
        )
        await XCTAssertValidCertificateDeprecated(
            await verifier.validate(
                leafCertificate: multiSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    func testAcceptsIpv6Address() async throws {
        let roots = CertificateStore([multiSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: nil, serverIP: "2001:db8::1")
            }
        )
        await XCTAssertValidCertificateDeprecated(
            await verifier.validate(
                leafCertificate: multiSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    func testRejectsIncorrectIpv4Address() async throws {
        let roots = CertificateStore([multiSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: nil, serverIP: "192.168.0.2")
            }
        )
        await XCTAssertInvalidCertificateDeprecated(
            await verifier.validate(
                leafCertificate: multiSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    func testRejectsIncorrectIpv6Address() async throws {
        let roots = CertificateStore([multiSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: nil, serverIP: "2001:db8::2")
            }
        )
        await XCTAssertInvalidCertificateDeprecated(
            await verifier.validate(
                leafCertificate: multiSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    func testAcceptsWildcards() async throws {
        let roots = CertificateStore([weirdoSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "this.wildcard.example.com", serverIP: nil)
            }
        )
        await XCTAssertValidCertificateDeprecated(
            await verifier.validate(
                leafCertificate: weirdoSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    func testAcceptsSuffixWildcard() async throws {
        let roots = CertificateStore([weirdoSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "foo.example.com", serverIP: nil)
            }
        )
        await XCTAssertValidCertificateDeprecated(
            await verifier.validate(
                leafCertificate: weirdoSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    func testAcceptsPrefixWildcard() async throws {
        let roots = CertificateStore([weirdoSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "bar.example.com", serverIP: nil)
            }
        )
        await XCTAssertValidCertificateDeprecated(
            await verifier.validate(
                leafCertificate: weirdoSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    func testAcceptsInfixWildcard() async throws {
        let roots = CertificateStore([weirdoSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "baz.example.com", serverIP: nil)
            }
        )
        await XCTAssertValidCertificateDeprecated(
            await verifier.validate(
                leafCertificate: weirdoSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    func testIgnoresTrailingPeriodInCert() async throws {
        let roots = CertificateStore([weirdoSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "trailing.period.example.com", serverIP: nil)
            }
        )
        await XCTAssertValidCertificateDeprecated(
            await verifier.validate(
                leafCertificate: weirdoSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    func testRejectsEncodedIDNALabel() async throws {
        let roots = CertificateStore([weirdoSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "straße.unicode.example.com", serverIP: nil)
            }
        )
        await XCTAssertInvalidCertificateDeprecated(
            await verifier.validate(
                leafCertificate: weirdoSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    func testMatchesUnencodedIDNALabel() async throws {
        let roots = CertificateStore([weirdoSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "xn--strae-oqa.unicode.example.com", serverIP: nil)
            }
        )
        await XCTAssertValidCertificateDeprecated(
            await verifier.validate(
                leafCertificate: weirdoSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    func testDoesNotMatchIDNALabelWithWildcard() async throws {
        let roots = CertificateStore([weirdoSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "xn--xx-gia.unicode.example.com", serverIP: nil)
            }
        )
        await XCTAssertInvalidCertificateDeprecated(
            await verifier.validate(
                leafCertificate: weirdoSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    func testDoesNotMatchNonLeftmostWildcards() async throws {
        let roots = CertificateStore([weirdoSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "weirdwildcard.nomatch.example.com", serverIP: nil)
            }
        )
        await XCTAssertInvalidCertificateDeprecated(
            await verifier.validate(
                leafCertificate: weirdoSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    func testDoesNotMatchMultipleWildcards() async throws {
        let roots = CertificateStore([weirdoSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "one.two.double.example.com", serverIP: nil)
            }
        )
        await XCTAssertInvalidCertificateDeprecated(
            await verifier.validate(
                leafCertificate: weirdoSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    func testRejectsWildcardBeforeUnencodedIDNALabel() async throws {
        let roots = CertificateStore([weirdoSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "foo.straße.example.com", serverIP: nil)
            }
        )
        await XCTAssertInvalidCertificateDeprecated(
            await verifier.validate(
                leafCertificate: weirdoSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    func testMatchesWildcardBeforeEncodedIDNALabel() async throws {
        let roots = CertificateStore([weirdoSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "foo.xn--strae-oqa.example.com", serverIP: nil)
            }
        )
        await XCTAssertValidCertificateDeprecated(
            await verifier.validate(
                leafCertificate: weirdoSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    func testDoesNotMatchSANWithEmbeddedNULL() async throws {
        let roots = CertificateStore([weirdoSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "nul\u{0000}l.example.com", serverIP: nil)
            }
        )
        await XCTAssertInvalidCertificateDeprecated(
            await verifier.validate(
                leafCertificate: weirdoSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    func testFallsBackToCommonName() async throws {
        let roots = CertificateStore([multiCNCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "localhost", serverIP: nil)
            }
        )
        await XCTAssertValidCertificateDeprecated(
            await verifier.validate(
                leafCertificate: multiCNCert,
                intermediates: CertificateStore()
            )
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    func testLowercasesForCommonName() async throws {
        let roots = CertificateStore([multiCNCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "LoCaLhOsT", serverIP: nil)
            }
        )
        await XCTAssertValidCertificateDeprecated(
            await verifier.validate(
                leafCertificate: multiCNCert,
                intermediates: CertificateStore()
            )
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    func testRejectsUnicodeCommonNameWithUnencodedIDNALabel() async throws {
        let roots = CertificateStore([unicodeCNCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "straße.org", serverIP: nil)
            }
        )
        await XCTAssertInvalidCertificateDeprecated(
            await verifier.validate(
                leafCertificate: unicodeCNCert,
                intermediates: CertificateStore()
            )
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    func testRejectsUnicodeCommonNameWithEncodedIDNALabel() async throws {
        let roots = CertificateStore([unicodeCNCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "xn--strae-oqa.org", serverIP: nil)
            }
        )
        await XCTAssertInvalidCertificateDeprecated(
            await verifier.validate(
                leafCertificate: unicodeCNCert,
                intermediates: CertificateStore()
            )
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    func testHandlesMissingCommonName() async throws {
        let roots = CertificateStore([noCNCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "localhost", serverIP: nil)
            }
        )
        await XCTAssertInvalidCertificateDeprecated(
            await verifier.validate(
                leafCertificate: noCNCert,
                intermediates: CertificateStore()
            )
        )
    }

    @available(*, deprecated, message: "deprecated because it uses deprecated API")
    func testDoesNotFallBackToCNWithSans() async throws {
        let roots = CertificateStore([weirdoSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "httpbin.org", serverIP: nil)
            }
        )
        await XCTAssertInvalidCertificateDeprecated(
            await verifier.validate(
                leafCertificate: weirdoSANCert,
                intermediates: CertificateStore()
            )
        )
    }
}

extension ASN1OctetString {
    fileprivate init(ipv4Address: String) {
        let bytes = ServerIdentityPolicy.parsingIPv4Address(ipv4Address)!
        let byteArray = Swift.withUnsafeBytes(of: bytes) { Array($0) }
        self.init(contentBytes: byteArray[...])
    }

    fileprivate init(ipv6Address: String) {
        let bytes = ServerIdentityPolicy.parsingIPv6Address(ipv6Address)!
        let byteArray = Swift.withUnsafeBytes(of: bytes) { Array($0) }
        self.init(contentBytes: byteArray[...])
    }
}

@available(*, deprecated, message: "deprecated because it uses deprecated API")
private func XCTAssertValidCertificateDeprecated(
    _ verifier: @autoclosure () async throws -> VerificationResult,
    file: StaticString = #filePath,
    line: UInt = #line
) async rethrows {
    let result = try await verifier()
    if case .couldNotValidate(let reason) = result {
        XCTFail("Could not validate certificate, reason: \(reason)", file: file, line: line)
    }
}

@available(*, deprecated, message: "deprecated because it uses deprecated API")
private func XCTAssertInvalidCertificateDeprecated(
    _ verifier: @autoclosure () async throws -> VerificationResult,
    file: StaticString = #filePath,
    line: UInt = #line
) async rethrows {
    let result = try await verifier()
    if case .validCertificate = result {
        XCTFail("Incorrectly validated certificate", file: file, line: line)
    }
}

final class ServerIdentityPolicyTests: XCTestCase {
    func testCanValidateHostnameInFirstSan() async throws {
        let roots = CertificateStore([multiSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "localhost", serverIP: nil)
            }
        )
        await XCTAssertValidCertificate(
            await verifier.validate(
                leaf: multiSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    func testCanValidateHostnameInSecondSan() async throws {
        let roots = CertificateStore([multiSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "example.com", serverIP: nil)
            }
        )
        await XCTAssertValidCertificate(
            await verifier.validate(
                leaf: multiSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    func testIgnoresTrailingPeriod() async throws {
        let roots = CertificateStore([multiSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "example.com.", serverIP: nil)
            }
        )
        await XCTAssertValidCertificate(
            await verifier.validate(
                leaf: multiSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    func testLowercasesHostnameForSan() async throws {
        let roots = CertificateStore([multiSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "LoCaLhOsT", serverIP: nil)
            }
        )
        await XCTAssertValidCertificate(
            await verifier.validate(
                leaf: multiSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    func testRejectsIncorrectHostname() async throws {
        let roots = CertificateStore([multiSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "httpbin.org", serverIP: nil)
            }
        )
        await XCTAssertInvalidCertificate(
            await verifier.validate(
                leaf: multiSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    func testAcceptsIpv4Address() async throws {
        let roots = CertificateStore([multiSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: nil, serverIP: "192.168.0.1")
            }
        )
        await XCTAssertValidCertificate(
            await verifier.validate(
                leaf: multiSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    func testAcceptsIpv6Address() async throws {
        let roots = CertificateStore([multiSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: nil, serverIP: "2001:db8::1")
            }
        )
        await XCTAssertValidCertificate(
            await verifier.validate(
                leaf: multiSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    func testRejectsIncorrectIpv4Address() async throws {
        let roots = CertificateStore([multiSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: nil, serverIP: "192.168.0.2")
            }
        )
        await XCTAssertInvalidCertificate(
            await verifier.validate(
                leaf: multiSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    func testRejectsIncorrectIpv6Address() async throws {
        let roots = CertificateStore([multiSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: nil, serverIP: "2001:db8::2")
            }
        )
        await XCTAssertInvalidCertificate(
            await verifier.validate(
                leaf: multiSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    func testAcceptsWildcards() async throws {
        let roots = CertificateStore([weirdoSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "this.wildcard.example.com", serverIP: nil)
            }
        )
        await XCTAssertValidCertificate(
            await verifier.validate(
                leaf: weirdoSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    func testAcceptsSuffixWildcard() async throws {
        let roots = CertificateStore([weirdoSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "foo.example.com", serverIP: nil)
            }
        )
        await XCTAssertValidCertificate(
            await verifier.validate(
                leaf: weirdoSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    func testAcceptsPrefixWildcard() async throws {
        let roots = CertificateStore([weirdoSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "bar.example.com", serverIP: nil)
            }
        )
        await XCTAssertValidCertificate(
            await verifier.validate(
                leaf: weirdoSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    func testAcceptsInfixWildcard() async throws {
        let roots = CertificateStore([weirdoSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "baz.example.com", serverIP: nil)
            }
        )
        await XCTAssertValidCertificate(
            await verifier.validate(
                leaf: weirdoSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    func testIgnoresTrailingPeriodInCert() async throws {
        let roots = CertificateStore([weirdoSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "trailing.period.example.com", serverIP: nil)
            }
        )
        await XCTAssertValidCertificate(
            await verifier.validate(
                leaf: weirdoSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    func testRejectsEncodedIDNALabel() async throws {
        let roots = CertificateStore([weirdoSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "straße.unicode.example.com", serverIP: nil)
            }
        )
        await XCTAssertInvalidCertificate(
            await verifier.validate(
                leaf: weirdoSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    func testMatchesUnencodedIDNALabel() async throws {
        let roots = CertificateStore([weirdoSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "xn--strae-oqa.unicode.example.com", serverIP: nil)
            }
        )
        await XCTAssertValidCertificate(
            await verifier.validate(
                leaf: weirdoSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    func testDoesNotMatchIDNALabelWithWildcard() async throws {
        let roots = CertificateStore([weirdoSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "xn--xx-gia.unicode.example.com", serverIP: nil)
            }
        )
        await XCTAssertInvalidCertificate(
            await verifier.validate(
                leaf: weirdoSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    func testDoesNotMatchNonLeftmostWildcards() async throws {
        let roots = CertificateStore([weirdoSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "weirdwildcard.nomatch.example.com", serverIP: nil)
            }
        )
        await XCTAssertInvalidCertificate(
            await verifier.validate(
                leaf: weirdoSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    func testDoesNotMatchMultipleWildcards() async throws {
        let roots = CertificateStore([weirdoSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "one.two.double.example.com", serverIP: nil)
            }
        )
        await XCTAssertInvalidCertificate(
            await verifier.validate(
                leaf: weirdoSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    func testRejectsWildcardBeforeUnencodedIDNALabel() async throws {
        let roots = CertificateStore([weirdoSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "foo.straße.example.com", serverIP: nil)
            }
        )
        await XCTAssertInvalidCertificate(
            await verifier.validate(
                leaf: weirdoSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    func testMatchesWildcardBeforeEncodedIDNALabel() async throws {
        let roots = CertificateStore([weirdoSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "foo.xn--strae-oqa.example.com", serverIP: nil)
            }
        )
        await XCTAssertValidCertificate(
            await verifier.validate(
                leaf: weirdoSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    func testDoesNotMatchSANWithEmbeddedNULL() async throws {
        let roots = CertificateStore([weirdoSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "nul\u{0000}l.example.com", serverIP: nil)
            }
        )
        await XCTAssertInvalidCertificate(
            await verifier.validate(
                leaf: weirdoSANCert,
                intermediates: CertificateStore()
            )
        )
    }

    func testFallsBackToCommonName() async throws {
        let roots = CertificateStore([multiCNCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "localhost", serverIP: nil)
            }
        )
        await XCTAssertValidCertificate(
            await verifier.validate(
                leaf: multiCNCert,
                intermediates: CertificateStore()
            )
        )
    }

    func testLowercasesForCommonName() async throws {
        let roots = CertificateStore([multiCNCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "LoCaLhOsT", serverIP: nil)
            }
        )
        await XCTAssertValidCertificate(
            await verifier.validate(
                leaf: multiCNCert,
                intermediates: CertificateStore()
            )
        )
    }

    func testRejectsUnicodeCommonNameWithUnencodedIDNALabel() async throws {
        let roots = CertificateStore([unicodeCNCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "straße.org", serverIP: nil)
            }
        )
        await XCTAssertInvalidCertificate(
            await verifier.validate(
                leaf: unicodeCNCert,
                intermediates: CertificateStore()
            )
        )
    }

    func testRejectsUnicodeCommonNameWithEncodedIDNALabel() async throws {
        let roots = CertificateStore([unicodeCNCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "xn--strae-oqa.org", serverIP: nil)
            }
        )
        await XCTAssertInvalidCertificate(
            await verifier.validate(
                leaf: unicodeCNCert,
                intermediates: CertificateStore()
            )
        )
    }

    func testHandlesMissingCommonName() async throws {
        let roots = CertificateStore([noCNCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "localhost", serverIP: nil)
            }
        )
        await XCTAssertInvalidCertificate(
            await verifier.validate(
                leaf: noCNCert,
                intermediates: CertificateStore()
            )
        )
    }

    func testDoesNotFallBackToCNWithSans() async throws {
        let roots = CertificateStore([weirdoSANCert])
        var verifier = Verifier(
            rootCertificates: roots,
            policy: {
                ServerIdentityPolicy(serverHostname: "httpbin.org", serverIP: nil)
            }
        )
        await XCTAssertInvalidCertificate(
            await verifier.validate(
                leaf: weirdoSANCert,
                intermediates: CertificateStore()
            )
        )
    }
}

private func XCTAssertValidCertificate(
    _ verifier: @autoclosure () async throws -> CertificateValidationResult,
    file: StaticString = #filePath,
    line: UInt = #line
) async rethrows {
    let result = try await verifier()
    if case .couldNotValidate(let reason) = result {
        XCTFail("Could not validate certificate, reason: \(reason)", file: file, line: line)
    }
}

private func XCTAssertInvalidCertificate(
    _ verifier: @autoclosure () async throws -> CertificateValidationResult,
    file: StaticString = #filePath,
    line: UInt = #line
) async rethrows {
    let result = try await verifier()
    if case .validCertificate = result {
        XCTFail("Incorrectly validated certificate", file: file, line: line)
    }
}
