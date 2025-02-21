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
import XCTest
import Crypto
import _CryptoExtras
import SwiftASN1
@testable import X509

final class CSRTests: XCTestCase {
    func testSimpleRoundTrip() throws {
        let key = P256.Signing.PrivateKey()
        let name = try DistinguishedName {
            CommonName("Hello")
        }
        let extensions = try Certificate.Extensions {
            SubjectAlternativeNames([.dnsName("example.com")])
        }
        let extensionRequest = ExtensionRequest(extensions: extensions)
        let attributes = try CertificateSigningRequest.Attributes(
            [.init(extensionRequest)]
        )
        let csr = try CertificateSigningRequest(
            version: .v1,
            subject: name,
            privateKey: .init(key),
            attributes: attributes,
            signatureAlgorithm: .ecdsaWithSHA256
        )

        let bytes = try DER.Serializer.serialized(element: csr)
        let parsed = try CertificateSigningRequest(derEncoded: bytes)

        XCTAssertEqual(parsed, csr)
    }

    func testRSASHA1CSR() throws {
        let url = Bundle.module.url(
            forResource: "rsa_sha1",
            withExtension: "der",
            subdirectory: "CSR Vectors/cryptography"
        )!
        let bytes = try Data(contentsOf: url)
        let csr = try CertificateSigningRequest(derEncoded: Array(bytes))

        XCTAssertEqual(csr.signatureAlgorithm, .sha1WithRSAEncryption)
        XCTAssertEqual(
            csr.subject,
            try! DistinguishedName([
                .init(type: .NameAttributes.countryName, printableString: "US"),
                .init(type: .NameAttributes.stateOrProvinceName, printableString: "Texas"),
                .init(type: .NameAttributes.localityName, printableString: "Austin"),
                .init(type: .NameAttributes.organizationName, printableString: "PyCA"),
                .init(type: .NameAttributes.commonName, printableString: "cryptography.io"),
            ])
        )
        XCTAssertNotNil(_RSA.Signing.PublicKey(csr.publicKey))
        XCTAssertNil(csr.attributes[oid: .CSRAttributes.extensionRequest])

        XCTAssertTrue(csr.publicKey.isValidSignature(csr.signature, for: csr))

        var serializer = DER.Serializer()
        try serializer.serialize(csr)
        XCTAssertEqual(Array(bytes), serializer.serializedBytes)
    }

    func testRSASHA1CSRPEM() throws {
        let url = Bundle.module.url(
            forResource: "rsa_sha1",
            withExtension: "pem",
            subdirectory: "CSR Vectors/cryptography"
        )!
        let pemDocument = try String(decoding: Data(contentsOf: url), as: UTF8.self)
        let csr = try CertificateSigningRequest(pemEncoded: pemDocument)

        XCTAssertEqual(csr.signatureAlgorithm, .sha1WithRSAEncryption)
        XCTAssertEqual(
            csr.subject,
            try! DistinguishedName([
                .init(type: .NameAttributes.countryName, printableString: "US"),
                .init(type: .NameAttributes.stateOrProvinceName, printableString: "Texas"),
                .init(type: .NameAttributes.localityName, printableString: "Austin"),
                .init(type: .NameAttributes.organizationName, printableString: "PyCA"),
                .init(type: .NameAttributes.commonName, printableString: "cryptography.io"),
            ])
        )
        XCTAssertNotNil(_RSA.Signing.PublicKey(csr.publicKey))
        XCTAssertNil(csr.attributes[oid: .CSRAttributes.extensionRequest])

        XCTAssertTrue(csr.publicKey.isValidSignature(csr.signature, for: csr))

        let reEncoded = try csr.serializeAsPEM()
        XCTAssertEqual(
            pemDocument.trimmingCharacters(in: .whitespacesAndNewlines),
            reEncoded.pemString.trimmingCharacters(in: .whitespacesAndNewlines)
        )
    }

    func testUnsupportedSignatureAlgorithmDER() throws {
        let url = Bundle.module.url(
            forResource: "rsa_md4",
            withExtension: "der",
            subdirectory: "CSR Vectors/cryptography"
        )!
        let bytes = try Data(contentsOf: url)
        XCTAssertThrowsError(try CertificateSigningRequest(derEncoded: Array(bytes)))
    }

    func testUnsupportedSignatureAlgorithmPEM() throws {
        let url = Bundle.module.url(
            forResource: "rsa_md4",
            withExtension: "pem",
            subdirectory: "CSR Vectors/cryptography"
        )!
        let bytes = try String(decoding: Data(contentsOf: url), as: UTF8.self)
        XCTAssertThrowsError(try CertificateSigningRequest(pemEncoded: bytes))
    }

    func testBadVersion() throws {
        let url = Bundle.module.url(
            forResource: "bad-version",
            withExtension: "pem",
            subdirectory: "CSR Vectors/cryptography"
        )!
        let bytes = try String(decoding: Data(contentsOf: url), as: UTF8.self)
        let csr = try CertificateSigningRequest(pemEncoded: bytes)
        XCTAssertEqual(csr.version, .init(rawValue: 1))
    }

    func testDuplicateExtension() throws {
        let url = Bundle.module.url(
            forResource: "two_basic_constraints",
            withExtension: "pem",
            subdirectory: "CSR Vectors/cryptography"
        )!
        let bytes = try String(decoding: Data(contentsOf: url), as: UTF8.self)
        #if canImport(Darwin)
        XCTExpectFailure("Currently don't police extension uniqueness")
        XCTAssertThrowsError(try CertificateSigningRequest(pemEncoded: bytes))
        #else
        // This is temporary: when we fix this, we'll want to invert the conditional!
        // Sadly, XCTExpectFailure is not available on Linux.
        XCTAssertNoThrow(try CertificateSigningRequest(pemEncoded: bytes))
        #endif
    }

    func testUnknownCriticalExtension() throws {
        let url = Bundle.module.url(
            forResource: "unsupported_extension_critical",
            withExtension: "pem",
            subdirectory: "CSR Vectors/cryptography"
        )!
        let bytes = try String(decoding: Data(contentsOf: url), as: UTF8.self)
        let csr = try CertificateSigningRequest(pemEncoded: bytes)

        guard let extensionRequest = try csr.attributes.extensionRequest else {
            XCTFail("No extension request")
            return
        }

        XCTAssertEqual(
            extensionRequest.extensions,
            try! Certificate.Extensions {
                Certificate.Extension(oid: [1, 2, 3, 4], critical: true, value: ArraySlice("value".utf8))
            }
        )
    }

    func testUnknownExtension() throws {
        let url = Bundle.module.url(
            forResource: "unsupported_extension",
            withExtension: "pem",
            subdirectory: "CSR Vectors/cryptography"
        )!
        let bytes = try String(decoding: Data(contentsOf: url), as: UTF8.self)
        let csr = try CertificateSigningRequest(pemEncoded: bytes)

        guard let extensionRequest = try csr.attributes.extensionRequest else {
            XCTFail("No extension request")
            return
        }

        XCTAssertEqual(
            extensionRequest.extensions,
            try! Certificate.Extensions {
                Certificate.Extension(oid: [1, 2, 3, 4], critical: false, value: ArraySlice("value".utf8))
            }
        )
    }

    func testNoExtensions() throws {
        let url = Bundle.module.url(
            forResource: "challenge-unstructured",
            withExtension: "pem",
            subdirectory: "CSR Vectors/cryptography"
        )!
        let bytes = try String(decoding: Data(contentsOf: url), as: UTF8.self)
        let csr = try CertificateSigningRequest(pemEncoded: bytes)

        XCTAssertNil(try csr.attributes.extensionRequest)
    }

    func testBasicConstraints() throws {
        let url = Bundle.module.url(
            forResource: "basic_constraints",
            withExtension: "pem",
            subdirectory: "CSR Vectors/cryptography"
        )!
        let bytes = try String(decoding: Data(contentsOf: url), as: UTF8.self)
        let csr = try CertificateSigningRequest(pemEncoded: bytes)

        guard let extensionRequest = try csr.attributes.extensionRequest else {
            XCTFail("No extension request")
            return
        }

        XCTAssertEqual(
            extensionRequest.extensions,
            try! Certificate.Extensions {
                Critical(
                    BasicConstraints.isCertificateAuthority(maxPathLength: 1)
                )
            }
        )
    }

    func testSubjectAlternativeName() throws {
        let url = Bundle.module.url(
            forResource: "san_rsa_sha1",
            withExtension: "der",
            subdirectory: "CSR Vectors/cryptography"
        )!
        let bytes = try Data(contentsOf: url)
        let csr = try CertificateSigningRequest(derEncoded: Array(bytes))

        guard let extensionRequest = try csr.attributes.extensionRequest else {
            XCTFail("No extension request")
            return
        }

        XCTAssertEqual(
            extensionRequest.extensions,
            try! Certificate.Extensions {
                SubjectAlternativeNames([
                    .dnsName("cryptography.io"),
                    .dnsName("sub.cryptography.io"),
                ])
            }
        )
    }

    func testSubjectAlternativeNamePEM() throws {
        let url = Bundle.module.url(
            forResource: "san_rsa_sha1",
            withExtension: "pem",
            subdirectory: "CSR Vectors/cryptography"
        )!
        let bytes = try String(decoding: Data(contentsOf: url), as: UTF8.self)
        let csr = try CertificateSigningRequest(pemEncoded: bytes)

        guard let extensionRequest = try csr.attributes.extensionRequest else {
            XCTFail("No extension request")
            return
        }

        XCTAssertEqual(
            extensionRequest.extensions,
            try! Certificate.Extensions {
                SubjectAlternativeNames([
                    .dnsName("cryptography.io"),
                    .dnsName("sub.cryptography.io"),
                ])
            }
        )
    }

    func testFreeIPABadCritical() throws {
        let url = Bundle.module.url(
            forResource: "freeipa-bad-critical",
            withExtension: "pem",
            subdirectory: "CSR Vectors/cryptography"
        )!
        let bytes = try String(decoding: Data(contentsOf: url), as: UTF8.self)
        let csr = try CertificateSigningRequest(pemEncoded: bytes)

        XCTAssertThrowsError(try csr.attributes.extensionRequest)
    }

    func testRSASHA256Signature() throws {
        let url = Bundle.module.url(
            forResource: "rsa_sha256",
            withExtension: "der",
            subdirectory: "CSR Vectors/cryptography"
        )!
        let bytes = try Data(contentsOf: url)
        let csr = try CertificateSigningRequest(derEncoded: Array(bytes))

        XCTAssertTrue(csr.publicKey.isValidSignature(csr.signature, for: csr))
    }

    func testRSASHA256SignaturePEM() throws {
        let url = Bundle.module.url(
            forResource: "rsa_sha256",
            withExtension: "pem",
            subdirectory: "CSR Vectors/cryptography"
        )!
        let bytes = try String(decoding: Data(contentsOf: url), as: UTF8.self)
        let csr = try CertificateSigningRequest(pemEncoded: bytes)

        XCTAssertTrue(csr.publicKey.isValidSignature(csr.signature, for: csr))
    }

    func testECDSACSR() throws {
        let url = Bundle.module.url(
            forResource: "ec_sha256",
            withExtension: "der",
            subdirectory: "CSR Vectors/cryptography"
        )!
        let bytes = try Data(contentsOf: url)
        let csr = try CertificateSigningRequest(derEncoded: Array(bytes))

        XCTAssertEqual(csr.signatureAlgorithm, .ecdsaWithSHA256)
        XCTAssertEqual(
            csr.subject,
            try! DistinguishedName([
                .init(type: .NameAttributes.commonName, utf8String: "cryptography.io"),
                .init(type: .NameAttributes.organizationName, utf8String: "PyCA"),
                .init(type: .NameAttributes.countryName, printableString: "US"),
                .init(type: .NameAttributes.stateOrProvinceName, utf8String: "Texas"),
                .init(type: .NameAttributes.localityName, utf8String: "Austin"),
            ])
        )
        XCTAssertNotNil(P384.Signing.PublicKey(csr.publicKey))
        XCTAssertNil(csr.attributes[oid: .CSRAttributes.extensionRequest])

        XCTAssertTrue(csr.publicKey.isValidSignature(csr.signature, for: csr))

        var serializer = DER.Serializer()
        try serializer.serialize(csr)
        XCTAssertEqual(Array(bytes), serializer.serializedBytes)
    }

    func testECDSACSRPEM() throws {
        let url = Bundle.module.url(
            forResource: "ec_sha256",
            withExtension: "pem",
            subdirectory: "CSR Vectors/cryptography"
        )!
        let pemDocument = try String(decoding: Data(contentsOf: url), as: UTF8.self)
        let csr = try CertificateSigningRequest(pemEncoded: pemDocument)

        XCTAssertEqual(csr.signatureAlgorithm, .ecdsaWithSHA256)
        XCTAssertEqual(
            csr.subject,
            try! DistinguishedName([
                .init(type: .NameAttributes.commonName, utf8String: "cryptography.io"),
                .init(type: .NameAttributes.organizationName, utf8String: "PyCA"),
                .init(type: .NameAttributes.countryName, printableString: "US"),
                .init(type: .NameAttributes.stateOrProvinceName, utf8String: "Texas"),
                .init(type: .NameAttributes.localityName, utf8String: "Austin"),
            ])
        )
        XCTAssertNotNil(P384.Signing.PublicKey(csr.publicKey))
        XCTAssertNil(csr.attributes[oid: .CSRAttributes.extensionRequest])

        XCTAssertTrue(csr.publicKey.isValidSignature(csr.signature, for: csr))

        let reEncoded = try csr.serializeAsPEM()
        XCTAssertEqual(
            pemDocument.trimmingCharacters(in: .whitespacesAndNewlines),
            reEncoded.pemString.trimmingCharacters(in: .whitespacesAndNewlines)
        )
    }

    func testDuplicateAttributesAreRemovedOnInsertion() throws {
        var elements = Array(repeating: CertificateSigningRequest.Attribute(oid: [1, 2, 3, 4], values: []), count: 5)
        elements.append(CertificateSigningRequest.Attribute(oid: [1, 2, 3, 4, 5], values: [try ASN1Any(erasing: 5)]))
        elements.append(CertificateSigningRequest.Attribute(oid: [1, 2, 3, 4], values: [try ASN1Any(erasing: 6)]))
        elements.append(CertificateSigningRequest.Attribute(oid: [1, 2, 3, 4], values: [try ASN1Any(erasing: 7)]))

        let attributes = CertificateSigningRequest.Attributes(elements)
        XCTAssertEqual(attributes.count, 2)
        XCTAssertEqual(
            attributes[oid: [1, 2, 3, 4]],
            CertificateSigningRequest.Attribute(oid: [1, 2, 3, 4], values: [try ASN1Any(erasing: 7)])
        )
        XCTAssertEqual(
            attributes[oid: [1, 2, 3, 4, 5]],
            CertificateSigningRequest.Attribute(oid: [1, 2, 3, 4, 5], values: [try ASN1Any(erasing: 5)])
        )
    }

    func testCanReplaceElementInAttributes() throws {
        var attributes = CertificateSigningRequest.Attributes([
            CertificateSigningRequest.Attribute(oid: [1, 2, 3, 4], values: [try ASN1Any(erasing: 1)]),
            CertificateSigningRequest.Attribute(oid: [1, 2, 3, 4, 5], values: [try ASN1Any(erasing: 2)]),
        ])

        attributes[oid: [1, 2, 3, 4]] = CertificateSigningRequest.Attribute(
            oid: [1, 2, 3, 4],
            values: [try ASN1Any(erasing: 3)]
        )
        attributes[oid: [1, 2, 3, 4, 5]] = nil
        attributes[oid: [4, 3, 2, 1]] = CertificateSigningRequest.Attribute(
            oid: [4, 3, 2, 1],
            values: [try ASN1Any(erasing: 4)]
        )

        XCTAssertEqual(attributes.count, 2)
        XCTAssertEqual(
            attributes[oid: [1, 2, 3, 4]],
            CertificateSigningRequest.Attribute(oid: [1, 2, 3, 4], values: [try ASN1Any(erasing: 3)])
        )
        XCTAssertEqual(
            attributes[oid: [4, 3, 2, 1]],
            CertificateSigningRequest.Attribute(oid: [4, 3, 2, 1], values: [try ASN1Any(erasing: 4)])
        )
    }

    func testInsertHasTheEffectOfTheSubscript() throws {
        var attributes = CertificateSigningRequest.Attributes()

        attributes.insert(contentsOf: [
            CertificateSigningRequest.Attribute(oid: [1, 2, 3, 4], values: [try ASN1Any(erasing: 1)]),
            CertificateSigningRequest.Attribute(oid: [1, 2, 3, 4, 5], values: [try ASN1Any(erasing: 2)]),
            CertificateSigningRequest.Attribute(oid: [1, 2, 3, 4], values: [try ASN1Any(erasing: 3)]),
            CertificateSigningRequest.Attribute(oid: [1, 2, 3, 4, 5], values: [try ASN1Any(erasing: 4)]),
        ])

        XCTAssertEqual(attributes.count, 2)
        XCTAssertEqual(
            attributes[oid: [1, 2, 3, 4]],
            CertificateSigningRequest.Attribute(oid: [1, 2, 3, 4], values: [try ASN1Any(erasing: 3)])
        )
        XCTAssertEqual(
            attributes[oid: [1, 2, 3, 4, 5]],
            CertificateSigningRequest.Attribute(oid: [1, 2, 3, 4, 5], values: [try ASN1Any(erasing: 4)])
        )

        attributes.insert(CertificateSigningRequest.Attribute(oid: [1, 2, 3, 4], values: [try ASN1Any(erasing: 5)]))
        XCTAssertEqual(attributes.count, 2)
        XCTAssertEqual(
            attributes[oid: [1, 2, 3, 4]],
            CertificateSigningRequest.Attribute(oid: [1, 2, 3, 4], values: [try ASN1Any(erasing: 5)])
        )
        XCTAssertEqual(
            attributes[oid: [1, 2, 3, 4, 5]],
            CertificateSigningRequest.Attribute(oid: [1, 2, 3, 4, 5], values: [try ASN1Any(erasing: 4)])
        )

        attributes.insert(CertificateSigningRequest.Attribute(oid: [4, 3, 2, 1], values: [try ASN1Any(erasing: 6)]))
        XCTAssertEqual(attributes.count, 3)
        XCTAssertEqual(
            attributes[oid: [1, 2, 3, 4]],
            CertificateSigningRequest.Attribute(oid: [1, 2, 3, 4], values: [try ASN1Any(erasing: 5)])
        )
        XCTAssertEqual(
            attributes[oid: [1, 2, 3, 4, 5]],
            CertificateSigningRequest.Attribute(oid: [1, 2, 3, 4, 5], values: [try ASN1Any(erasing: 4)])
        )
        XCTAssertEqual(
            attributes[oid: [4, 3, 2, 1]],
            CertificateSigningRequest.Attribute(oid: [4, 3, 2, 1], values: [try ASN1Any(erasing: 6)])
        )
    }

    func testCSRAttributeValuesAreOrderIndependentForEqualityAndHashing() throws {
        let values: [ASN1Any] = [
            try ASN1Any(erasing: 5),
            try ASN1Any(erasing: 10),
            try ASN1Any(erasing: 15),
        ]

        let options = values.permutations.map { CertificateSigningRequest.Attribute(oid: [1, 2, 3, 4], values: $0) }

        for option in options {
            // Everything is equal.
            XCTAssertTrue(options.allSatisfy({ $0 == option }))
        }

        let setified = Set(options)
        XCTAssertEqual(setified.count, 1)

        XCTAssertNotEqual(
            CertificateSigningRequest.Attribute(oid: [1, 2, 3, 4], values: [try ASN1Any(erasing: 5)]),
            CertificateSigningRequest.Attribute(
                oid: [1, 2, 3, 4],
                values: [try ASN1Any(erasing: 5), try ASN1Any(erasing: 10)]
            )
        )
    }

    func testCSRAttributesAreOrderIndependentForEqualityAndHashing() throws {
        let attributes: [CertificateSigningRequest.Attribute] = [
            CertificateSigningRequest.Attribute(oid: [1, 2, 3, 4], values: [try ASN1Any(erasing: 5)]),
            CertificateSigningRequest.Attribute(oid: [4, 3, 2, 1], values: [try ASN1Any(erasing: 10)]),
            CertificateSigningRequest.Attribute(oid: [1, 1, 1, 1], values: [try ASN1Any(erasing: 5)]),
        ]

        let options = attributes.permutations.map { CertificateSigningRequest.Attributes($0) }

        for option in options {
            // Everything is equal.
            XCTAssertTrue(options.allSatisfy({ $0 == option }))
        }

        let setified = Set(options)
        XCTAssertEqual(setified.count, 1)

        XCTAssertNotEqual(
            CertificateSigningRequest.Attributes(attributes.prefix(1)),
            CertificateSigningRequest.Attributes(attributes.prefix(2))
        )
    }

    func testDefaultRSASignatureAlgorithm() throws {
        let privateKey = try Certificate.PrivateKey(_RSA.Signing.PrivateKey(keySize: .bits2048))
        let csr = try self.generateCertificateSigningRequest(privateKey: privateKey)
        XCTAssertEqual(csr.signatureAlgorithm.description, "SignatureAlgorithm.sha256WithRSAEncryption")
    }

    func testDefaultP256SignatureAlgorithm() throws {
        let privateKey = Certificate.PrivateKey(P256.Signing.PrivateKey())
        let csr = try self.generateCertificateSigningRequest(privateKey: privateKey)
        XCTAssertEqual(csr.signatureAlgorithm.description, "SignatureAlgorithm.ecdsaWithSHA256")
    }

    func testDefaultP384SignatureAlgorithm() throws {
        let privateKey = Certificate.PrivateKey(P384.Signing.PrivateKey())
        let csr = try self.generateCertificateSigningRequest(privateKey: privateKey)
        XCTAssertEqual(csr.signatureAlgorithm.description, "SignatureAlgorithm.ecdsaWithSHA384")
    }

    func testDefaultP521SignatureAlgorithm() throws {
        let privateKey = Certificate.PrivateKey(P521.Signing.PrivateKey())
        let csr = try self.generateCertificateSigningRequest(privateKey: privateKey)
        XCTAssertEqual(csr.signatureAlgorithm.description, "SignatureAlgorithm.ecdsaWithSHA512")
    }

    func testDefaultEd25519SignatureAlgorithm() throws {
        let privateKey = Certificate.PrivateKey(Curve25519.Signing.PrivateKey())
        let csr = try self.generateCertificateSigningRequest(privateKey: privateKey)
        XCTAssertEqual(csr.signatureAlgorithm.description, "SignatureAlgorithm.ed25519")
    }

    private func generateCertificateSigningRequest(
        privateKey: Certificate.PrivateKey
    ) throws -> CertificateSigningRequest {
        try CertificateSigningRequest(
            version: .v1,
            subject: DistinguishedName { CommonName("test") },
            privateKey: privateKey,
            attributes: CertificateSigningRequest.Attributes()
        )
    }
}

extension RandomAccessCollection {
    var permutations: [[Element]] {
        // A more efficient implementation would be implemented as a Sequence, but for tests this isn't important
        // enough.
        //
        // For the curious, this is an implementation of QuickPerm in Swift.
        var permutations: [[Element]] = []
        var working = Array(self)

        // Trivial first permutation is the current one.
        permutations.append(working)

        let n = working.count
        var p = Array(0...n)
        var i = 1

        while i < n {
            p[i] -= 1

            let j: Int
            if i % 2 == 1 {
                j = p[i]
            } else {
                j = 0
            }

            working.swapAt(i, j)
            permutations.append(working)

            i = 1

            while p[i] == 0 {
                p[i] = i
                i += 1
            }
        }

        return permutations
    }
}
