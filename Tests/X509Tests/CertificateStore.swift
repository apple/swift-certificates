//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCertificates open source project
//
// Copyright (c) 2025 Apple Inc. and the SwiftCertificates project authors
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
@_spi(Testing) @testable import X509
@preconcurrency import Crypto

final class CertificateStoreTests: XCTestCase {
    #if os(Linux)
    func testLoadingDefaultTrustRoots() async throws {
        let log = DiagnosticsLog()
        let store = await CertificateStore.systemTrustRoots.resolve(diagnosticsCallback: log.append(_:))
        XCTAssertGreaterThanOrEqual(store.totalCertificateCount, 100, "expected to find at least 100 certificates")
        XCTAssertEqual(log, [])
    }
    #else
    func testLoadingDefaultTrustRoots() async throws {
        let log = DiagnosticsLog()

        let store = await CertificateStore.systemTrustRoots.resolve(diagnosticsCallback: log.append(_:))
        XCTAssertEqual(store.totalCertificateCount, 0)

        XCTAssertEqual(log.count, 1)
    }

    #endif

    func testLoadingFailsGracefullyIfFilesDoNotExist() {
        let searchPaths = [
            "/some/path/that/does/not/exist/1",
            "/some/path/that/does/not/exist/2",
        ]
        XCTAssertThrowsError(try CertificateStore.loadTrustRoots(at: searchPaths)) { error in
            guard let error = error as? CertificateError else {
                return XCTFail("could not cast \(error) to \(CertificateError.self)")
            }
            XCTAssertEqual(error.code, .failedToLoadSystemTrustStore)
        }
    }

    func testLoadingFailsGracefullyIfFirstFileDoesNotExist() throws {
        let caCertificatesURL = try XCTUnwrap(Bundle.module.url(forResource: "ca-certificates", withExtension: "crt"))
        let searchPaths = [
            "/some/path/that/does/not/exist/1",
            caCertificatesURL.path,
        ]
        let log = DiagnosticsLog()
        let store = try CertificateStore.loadTrustRoots(at: searchPaths)
        XCTAssertEqual(log, [])
        XCTAssertEqual(store.values.lazy.map(\.count).reduce(0, +), 137)
    }

    static func normalizeDistinguishedName(_ dn: DistinguishedName) -> DistinguishedName {
        DistinguishedName(
            dn.map {
                RelativeDistinguishedName(
                    $0.map {
                        guard let str = String($0.value) else {
                            return $0
                        }
                        return RelativeDistinguishedName.Attribute(
                            type: $0.type,
                            value: RelativeDistinguishedName.Attribute.Value(utf8String: str)
                        )
                    }
                )
            }
        )
    }

    struct CertStore: CustomCertificateStore {
        subscript(subject: X509.DistinguishedName) -> [X509.Certificate]? {
            get async {
                self.trustRoots[normalizeDistinguishedName(subject)]
            }
        }

        func contains(_ certificate: X509.Certificate) async -> Bool {
            self.trustRoots[normalizeDistinguishedName(certificate.subject)]?.contains(certificate) == true
        }

        mutating func append(contentsOf certificates: some Sequence<X509.Certificate>) {
            for certificate in certificates {
                self.trustRoots[normalizeDistinguishedName(certificate.subject), default: []].append(certificate)
            }
        }

        @usableFromInline
        var trustRoots: [DistinguishedName: [Certificate]]

        @inlinable
        public init(_ certificates: some Sequence<Certificate>) {
            self.trustRoots = Dictionary(grouping: certificates) {
                normalizeDistinguishedName($0.subject)
            }
        }
    }

    private static let referenceTime = Date()

    private static let ca1PrivateKey = P384.Signing.PrivateKey()
    private static let ca1: Certificate = {
        // Force CA to encode using printableString:
        let ca1Name = try! DistinguishedName([
            RelativeDistinguishedName([
                RelativeDistinguishedName.Attribute(
                    type: .RDNAttributeType.countryName,
                    value: RelativeDistinguishedName.Attribute.Value(printableString: "US")
                )
            ]),
            RelativeDistinguishedName([
                RelativeDistinguishedName.Attribute(
                    type: .RDNAttributeType.organizationName,
                    value: RelativeDistinguishedName.Attribute.Value(printableString: "Apple")
                )
            ]),
            RelativeDistinguishedName([
                RelativeDistinguishedName.Attribute(
                    type: .RDNAttributeType.commonName,
                    value: RelativeDistinguishedName.Attribute.Value(printableString: "Swift Certificate Test CA 1")
                )
            ]),
        ])
        return try! Certificate(
            version: .v3,
            serialNumber: .init(),
            publicKey: .init(ca1PrivateKey.publicKey),
            notValidBefore: referenceTime - .days(365),
            notValidAfter: referenceTime + .days(3650),
            issuer: ca1Name,
            subject: ca1Name,
            signatureAlgorithm: .ecdsaWithSHA384,
            extensions: Certificate.Extensions {
                Critical(
                    BasicConstraints.isCertificateAuthority(maxPathLength: nil)
                )
                KeyUsage(keyCertSign: true)
                SubjectKeyIdentifier(
                    keyIdentifier: ArraySlice(Insecure.SHA1.hash(data: ca1PrivateKey.publicKey.derRepresentation))
                )
            },
            issuerPrivateKey: .init(ca1PrivateKey)
        )
    }()

    private static let leafPrivateKey = P256.Signing.PrivateKey()
    private static let leafCert: Certificate = {
        try! Certificate(
            version: .v3,
            serialNumber: .init(),
            publicKey: .init(leafPrivateKey.publicKey),
            notValidBefore: referenceTime - .days(365),
            notValidAfter: referenceTime + .days(365),
            // Force leaf to encode using utf8String:
            issuer: DistinguishedName([
                RelativeDistinguishedName([
                    RelativeDistinguishedName.Attribute(
                        type: .RDNAttributeType.countryName,
                        value: RelativeDistinguishedName.Attribute.Value(utf8String: "US")
                    )
                ]),
                RelativeDistinguishedName([
                    RelativeDistinguishedName.Attribute(
                        type: .RDNAttributeType.organizationName,
                        value: RelativeDistinguishedName.Attribute.Value(utf8String: "Apple")
                    )
                ]),
                RelativeDistinguishedName([
                    RelativeDistinguishedName.Attribute(
                        type: .RDNAttributeType.commonName,
                        value: RelativeDistinguishedName.Attribute.Value(utf8String: "Swift Certificate Test CA 1")
                    )
                ]),
            ]),
            subject: try! DistinguishedName {
                CountryName("US")
                OrganizationName("Apple")
                CommonName("localhost")
            },
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: Certificate.Extensions {
                Critical(
                    BasicConstraints.notCertificateAuthority
                )
                KeyUsage(keyCertSign: true)
                AuthorityKeyIdentifier(keyIdentifier: try! ca1.extensions.subjectKeyIdentifier!.keyIdentifier)
            },
            issuerPrivateKey: .init(ca1PrivateKey)
        )
    }()

    @available(*, deprecated, message: "test for replacement in testCustomCertificateStore")
    func testCustomCertificateStoreDeprecated() async throws {
        // MUST fail due to encoding of DN mismatch:
        var concreteStore = CertificateStore()
        concreteStore.append(Self.ca1)

        var concreteVerifier = Verifier(rootCertificates: concreteStore) {
            RFC5280Policy()
        }
        let concreteResult = await concreteVerifier.validate(
            leafCertificate: Self.leafCert,
            intermediates: CertificateStore()
        )

        guard case .couldNotValidate = concreteResult else {
            XCTFail("Incorrectly validated: \(concreteResult)")
            return
        }

        // The custom CertStore should normalize the DN so it no longer fails:
        var customStore = CertificateStore(custom: CertStore([]))
        customStore.append(Self.ca1)

        var customVerifier = Verifier(rootCertificates: customStore) {
            RFC5280Policy()
        }
        let customResult = await customVerifier.validate(
            leafCertificate: Self.leafCert,
            intermediates: CertificateStore()
        )

        guard case .validCertificate(_) = customResult else {
            XCTFail("Failed to validate: \(customResult)")
            return
        }
    }

    func testCustomCertificateStore() async throws {
        // MUST fail due to encoding of DN mismatch:
        var concreteStore = CertificateStore()
        concreteStore.append(Self.ca1)

        var concreteVerifier = Verifier(rootCertificates: concreteStore) {
            RFC5280Policy()
        }
        let concreteResult = await concreteVerifier.validate(
            leaf: Self.leafCert,
            intermediates: CertificateStore()
        )

        guard case .couldNotValidate = concreteResult else {
            XCTFail("Incorrectly validated: \(concreteResult)")
            return
        }

        // The custom CertStore should normalize the DN so it no longer fails:
        var customStore = CertificateStore(custom: CertStore([]))
        customStore.append(Self.ca1)

        var customVerifier = Verifier(rootCertificates: customStore) {
            RFC5280Policy()
        }
        let customResult = await customVerifier.validate(
            leaf: Self.leafCert,
            intermediates: CertificateStore()
        )

        guard case .validCertificate(_) = customResult else {
            XCTFail("Failed to validate: \(customResult)")
            return
        }
    }
}

extension CertificateStore.Resolved {
    var totalCertificateCount: Int {
        if case .concrete(let inner) = self {
            inner.systemTrustRoots.values.lazy.map(\.count).reduce(0, +)
                + inner.additionalTrustRoots.values.lazy.map(\.count).reduce(0, +)
        } else {
            fatalError("Expected concrete certificate store!")
        }
    }
}
