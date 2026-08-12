//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCertificates open source project
//
// Copyright (c) 2026 Apple Inc. and the SwiftCertificates project authors
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
@preconcurrency import Crypto
@testable import X509

final class MLDSATests: XCTestCase {
    // MARK: - No ML-DSA key material involved: parsing and re-serializing the ASN.1 identity layer

    func testParsesCertificateSignedByMLDSA65CA() throws {
        let cert = try fixtureCertificate(mldsaIssuedLeafDERBase64)
        XCTAssertEqual(cert.signatureAlgorithm, .mldsa65)
        XCTAssertEqual(String(describing: cert.signatureAlgorithm), "SignatureAlgorithm.mldsa65")
        XCTAssertEqual(String(describing: cert.signature), "MLDSA65")
        // The leaf's own key is P-256; only the issuer's signature is post-quantum.
        XCTAssertNotNil(P256.Signing.PublicKey(cert.publicKey))
    }

    func testMLDSASignedCertificateRoundTripsToIdenticalDER() throws {
        let der = try XCTUnwrap(Data(base64Encoded: mldsaIssuedLeafDERBase64))
        let cert = try Certificate(derEncoded: Array(der))
        var serializer = DER.Serializer()
        try serializer.serialize(cert)
        XCTAssertEqual(Array(der), serializer.serializedBytes)
    }

    // ML-DSA-44 exists in RFC 9881 (2.16.840.1.101.3.4.3.17) but not in swift-crypto,
    // so we deliberately do not support it.
    func testMLDSA44IsRejected() throws {
        XCTAssertThrowsError(try fixtureCertificate(mldsa44RootDERBase64)) { error in
            XCTAssertEqual((error as? CertificateError)?.code, .unsupportedPublicKeyAlgorithm)
        }
    }

    // MARK: - Requires macOS 26+ on Darwin: names MLDSA65/MLDSA87 and touches key material

    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
    func testParsesSelfSignedMLDSA65Root() throws {
        let cert = try fixtureCertificate(mldsa65RootDERBase64)
        XCTAssertEqual(cert.signatureAlgorithm, .mldsa65)
        // RFC 9881: raw FIPS 204 bytes in the BIT STRING — 1952 octets for ML-DSA-65.
        XCTAssertEqual(cert.publicKey.subjectPublicKeyInfoBytes.count, 1952)
        XCTAssertEqual(String(describing: cert.publicKey), "MLDSA65.PublicKey")
        XCTAssertNotNil(MLDSA65.PublicKey(cert.publicKey))
        XCTAssertNil(MLDSA87.PublicKey(cert.publicKey))
    }

    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
    func testParsesSelfSignedMLDSA87Root() throws {
        let cert = try fixtureCertificate(mldsa87RootDERBase64)
        XCTAssertEqual(cert.signatureAlgorithm, .mldsa87)
        XCTAssertEqual(cert.publicKey.subjectPublicKeyInfoBytes.count, 2592)
        XCTAssertNotNil(MLDSA87.PublicKey(cert.publicKey))
    }

    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
    func testMLDSARootRoundTripsToIdenticalDER() throws {
        for fixture in [mldsa65RootDERBase64, mldsa87RootDERBase64] {
            let der = try XCTUnwrap(Data(base64Encoded: fixture))
            let cert = try Certificate(derEncoded: Array(der))
            var serializer = DER.Serializer()
            try serializer.serialize(cert)
            XCTAssertEqual(Array(der), serializer.serializedBytes)
        }
    }

    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
    func testPublicKeyWrapUnwrapRoundTrip() throws {
        let cert = try fixtureCertificate(mldsa65RootDERBase64)
        let unwrapped = try XCTUnwrap(MLDSA65.PublicKey(cert.publicKey))
        XCTAssertEqual(Certificate.PublicKey(unwrapped), cert.publicKey)
        let pemRoundTripped = try Certificate.PublicKey(pemEncoded: cert.publicKey.serializeAsPEM().pemString)
        XCTAssertEqual(pemRoundTripped, cert.publicKey)
    }

    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
    func testVerifiesOpenSSLSelfSignature() throws {
        // Known-answer interop test: signatures produced by OpenSSL 3.6.3, not by this library.
        for fixture in [mldsa65RootDERBase64, mldsa87RootDERBase64] {
            let root = try fixtureCertificate(fixture)
            XCTAssertTrue(root.publicKey.isValidSignature(root.signature, for: root))
        }
    }

    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
    func testRejectsTamperedSignature() throws {
        let root = try fixtureCertificate(mldsa65RootDERBase64)
        var tamperedBytes = root.signature.rawRepresentation
        tamperedBytes[0] ^= 0x01
        let tampered = try Certificate.Signature(
            signatureAlgorithm: .mldsa65,
            signatureBytes: ASN1BitString(bytes: tamperedBytes[...])
        )
        XCTAssertFalse(root.publicKey.isValidSignature(tampered, for: root))
    }

    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
    func testRejectsMLDSASignatureWithPaddingBits() throws {
        // RFC 9881 / FIPS 204 signatures are octet-aligned: a BIT STRING wrapping an
        // ML-DSA signature must never carry padding bits. Certificate.Signature's
        // initializer must reject one that does, rather than silently truncating it.
        //
        // ASN1BitString itself validates, at construction time, that any bits a nonzero
        // paddingBits count claims to mask off are actually zero in the trailing byte,
        // so the trailing byte is cleared here to produce a well-formed ASN1BitString
        // that nonetheless has a nonzero paddingBits count for Certificate.Signature to reject.
        let root = try fixtureCertificate(mldsa65RootDERBase64)
        var bytes = root.signature.rawRepresentation
        bytes[bytes.count - 1] &= 0b1111_0000
        XCTAssertThrowsError(
            try Certificate.Signature(
                signatureAlgorithm: .mldsa65,
                signatureBytes: ASN1BitString(bytes: bytes[...], paddingBits: 4)
            )
        ) { error in
            XCTAssertEqual((error as? CertificateError)?.code, .invalidSignatureForCertificate)
        }
    }

    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
    func testRejectsSignatureOverDifferentTBS() throws {
        let root = try fixtureCertificate(mldsa65RootDERBase64)
        let other = try fixtureCertificate(mldsa65LeafSignedByMLDSA65RootDERBase64)
        // The root's signature is not a signature over the leaf's TBSCertificate.
        XCTAssertFalse(root.publicKey.isValidSignature(root.signature, for: other))
    }

    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
    func testRejectsWrongParameterSet() throws {
        let root65 = try fixtureCertificate(mldsa65RootDERBase64)
        let root87 = try fixtureCertificate(mldsa87RootDERBase64)
        // An ML-DSA-87 signature must not verify under an ML-DSA-65 key, and vice versa.
        XCTAssertFalse(root65.publicKey.isValidSignature(root87.signature, for: root87))
        XCTAssertFalse(root87.publicKey.isValidSignature(root65.signature, for: root65))
        // Raw-bytes overload with a mismatched algorithm claim must also refuse.
        XCTAssertFalse(
            root65.publicKey.isValidSignature(
                root65.signature.rawRepresentation,
                for: root65.tbsCertificateBytes,
                signatureAlgorithm: .mldsa87
            )
        )
    }

    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
    func testRejectsNonMLDSASignatureAgainstMLDSAKey() throws {
        let root = try fixtureCertificate(mldsa65RootDERBase64)
        let ed25519Key = Curve25519.Signing.PrivateKey()
        let ed25519Signature = try Certificate.Signature(
            signatureAlgorithm: .ed25519,
            signatureBytes: ASN1BitString(
                bytes: ArraySlice(try ed25519Key.signature(for: root.tbsCertificateBytes))
            )
        )
        XCTAssertFalse(root.publicKey.isValidSignature(ed25519Signature, for: root))
    }

    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
    func testVerifiesP256LeafChainedToMLDSA65Root() async throws {
        let root = try fixtureCertificate(mldsa65RootDERBase64)
        let leaf = try fixtureCertificate(p256LeafSignedByMLDSA65RootDERBase64)
        var verifier = Verifier(rootCertificates: CertificateStore([root])) { RFC5280Policy() }
        let result = await verifier.validate(leaf: leaf, intermediates: CertificateStore([]))
        guard case .validCertificate(let chain) = result else {
            XCTFail("Failed to validate: \(result)")
            return
        }
        XCTAssertEqual(Array(chain), [leaf, root])
    }

    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
    func testVerifiesMLDSA65LeafChainedToMLDSA65Root() async throws {
        let root = try fixtureCertificate(mldsa65RootDERBase64)
        let leaf = try fixtureCertificate(mldsa65LeafSignedByMLDSA65RootDERBase64)
        var verifier = Verifier(rootCertificates: CertificateStore([root])) { RFC5280Policy() }
        let result = await verifier.validate(leaf: leaf, intermediates: CertificateStore([]))
        guard case .validCertificate(let chain) = result else {
            XCTFail("Failed to validate: \(result)")
            return
        }
        XCTAssertEqual(Array(chain), [leaf, root])
    }

    @available(macOS 26.0, iOS 26.0, watchOS 26.0, tvOS 26.0, macCatalyst 26.0, visionOS 26.0, *)
    func testRejectsChainToWrongRoot() async throws {
        // An "evil twin" root: same subject DN as the real ML-DSA-65 root, but a different
        // key.
        let evilRoot = try fixtureCertificate(mldsa65EvilTwinRootDERBase64)
        let leaf = try fixtureCertificate(mldsa65LeafSignedByMLDSA65RootDERBase64)
        var verifier = Verifier(rootCertificates: CertificateStore([evilRoot])) { RFC5280Policy() }
        let result = await verifier.validate(leaf: leaf, intermediates: CertificateStore([]))
        guard case .couldNotValidate = result else {
            XCTFail("Unexpectedly validated: \(result)")
            return
        }
        // Direct crypto negative, independent of chain-building: the evil twin's key must
        // not validate a signature produced by the real root's key, even though both claim
        // the same algorithm and the same tbsCertificate bytes are checked.
        XCTAssertFalse(evilRoot.publicKey.isValidSignature(leaf.signature, for: leaf))
    }
}

private func fixtureCertificate(_ base64: String) throws -> Certificate {
    let der = try XCTUnwrap(Data(base64Encoded: base64))
    return try Certificate(derEncoded: Array(der))
}

// A P-256 leaf signed by an ML-DSA-65 CA. Generated with OpenSSL 3.6.3
// (`openssl genpkey -algorithm ML-DSA-65` for the CA, then a P-256 CSR signed
// by that CA).
private let mldsaIssuedLeafDERBase64 = """
    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
    """

// A self-signed ML-DSA-65 root CA, 10-year validity. Generated with OpenSSL 3.6.3:
//   openssl req -x509 -new -newkey ML-DSA-65 -nodes -keyout ML-DSA-65-root.key \
//     -out ML-DSA-65-root.pem -days 3650 -subj "/CN=swift-certificates ML-DSA-65 Test Root"
//   openssl x509 -in ML-DSA-65-root.pem -outform DER -out ML-DSA-65-root.der
private let mldsa65RootDERBase64 = """
    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\
    AAAAAAAAAAAAAAAAAAAAAAAABQwPGB4k
    """

// A self-signed ML-DSA-87 root CA, 10-year validity. Generated with OpenSSL 3.6.3:
//   openssl req -x509 -new -newkey ML-DSA-87 -nodes -keyout ML-DSA-87-root.key \
//     -out ML-DSA-87-root.pem -days 3650 -subj "/CN=swift-certificates ML-DSA-87 Test Root"
//   openssl x509 -in ML-DSA-87-root.pem -outform DER -out ML-DSA-87-root.der
private let mldsa87RootDERBase64 = """
    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\
    AAAAAAAAAAAAAAAAAAAAAAAAAAAAChAXGiAmKzI=
    """

// A self-signed ML-DSA-44 root CA, 10-year validity. ML-DSA-44 exists in RFC 9881 but is
// not implemented by swift-crypto, so swift-certificates deliberately rejects it. Generated
// with OpenSSL 3.6.3:
//   openssl req -x509 -new -newkey ML-DSA-44 -nodes -keyout ML-DSA-44-root.key \
//     -out ML-DSA-44-root.pem -days 3650 -subj "/CN=swift-certificates ML-DSA-44 Test Root"
//   openssl x509 -in ML-DSA-44-root.pem -outform DER -out ML-DSA-44-root.der
private let mldsa44RootDERBase64 = """
    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\
    AAAAECA1QQ==
    """

// A P-256 leaf certificate (CA:FALSE, with SKI/AKI extensions) signed by the ML-DSA-65 root
// above. Generated with OpenSSL 3.6.3:
//   openssl req -new -newkey ec -pkeyopt ec_paramgen_curve:P-256 -nodes \
//     -keyout p256-leaf.key -out p256-leaf.csr -subj "/CN=p256.leaf.example.com"
//   printf 'basicConstraints=CA:FALSE\nsubjectKeyIdentifier=hash\nauthorityKeyIdentifier=keyid\n' > leaf.ext
//   openssl x509 -req -in p256-leaf.csr -CA ML-DSA-65-root.pem -CAkey ML-DSA-65-root.key \
//     -CAcreateserial -days 3650 -extfile leaf.ext -out p256-leaf.pem
//   openssl x509 -in p256-leaf.pem -outform DER -out p256-leaf.der
private let p256LeafSignedByMLDSA65RootDERBase64 = """
    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\
    AAAGCRYZIyg=
    """

// An ML-DSA-65 leaf certificate (CA:FALSE, with SKI/AKI extensions) signed by the ML-DSA-65
// root above. Generated with OpenSSL 3.6.3:
//   openssl req -new -newkey ML-DSA-65 -nodes -keyout mldsa65-leaf.key \
//     -out mldsa65-leaf.csr -subj "/CN=mldsa65.leaf.example.com"
//   openssl x509 -req -in mldsa65-leaf.csr -CA ML-DSA-65-root.pem -CAkey ML-DSA-65-root.key \
//     -CAcreateserial -days 3650 -extfile leaf.ext -out mldsa65-leaf.pem
//   openssl x509 -in mldsa65-leaf.pem -outform DER -out mldsa65-leaf.der
private let mldsa65LeafSignedByMLDSA65RootDERBase64 = """
    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\
    EhggJA==
    """

// An "evil twin" of the ML-DSA-65 root above: same subject DN, a brand-new ML-DSA-65 key,
// self-signed. Generated with OpenSSL 3.6.3:
//   openssl req -x509 -new -newkey ML-DSA-65 -nodes -keyout evil-twin.key \
//     -out evil-twin.pem -days 3650 -subj "/CN=swift-certificates ML-DSA-65 Test Root"
//   openssl x509 -in evil-twin.pem -outform DER -out evil-twin.der
private let mldsa65EvilTwinRootDERBase64 = """
    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\
    AAAAAAAAAAAAAAAAAAAAAAAAAwgKDxQa
    """
