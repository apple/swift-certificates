//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCertificates open source project
//
// Copyright (c) 2022 Apple Inc. and the SwiftCertificates project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCertificates project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import SwiftASN1

@usableFromInline
struct AlgorithmIdentifier: DERImplicitlyTaggable, BERImplicitlyTaggable, Hashable, Sendable {
    @inlinable
    static var defaultIdentifier: ASN1Identifier {
        .sequence
    }

    @usableFromInline
    var algorithm: ASN1ObjectIdentifier

    @usableFromInline
    var parameters: ASN1Any?

    @inlinable
    init(algorithm: ASN1ObjectIdentifier, parameters: ASN1Any?) {
        self.algorithm = algorithm
        self.parameters = parameters
    }

    @inlinable
    init(derEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        // The AlgorithmIdentifier block looks like this.
        //
        // AlgorithmIdentifier  ::=  SEQUENCE  {
        //   algorithm   OBJECT IDENTIFIER,
        //   parameters  ANY DEFINED BY algorithm OPTIONAL
        // }
        self = try DER.sequence(rootNode, identifier: identifier) { nodes in
            let algorithmOID = try ASN1ObjectIdentifier(derEncoded: &nodes)

            let parameters = nodes.next().map { ASN1Any(derEncoded: $0) }

            return .init(algorithm: algorithmOID, parameters: parameters)
        }
    }

    @inlinable
    init(berEncoded rootNode: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        self = try .init(derEncoded: rootNode, withIdentifier: identifier)
    }

    @inlinable
    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        try coder.appendConstructedNode(identifier: identifier) { coder in
            try coder.serialize(self.algorithm)
            if let parameters = self.parameters {
                try coder.serialize(parameters)
            }
        }
    }
}

// MARK: Algorithm Identifier Statics
extension AlgorithmIdentifier {
    @usableFromInline
    static let p256PublicKey = AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.idEcPublicKey,
        parameters: try! .init(erasing: ASN1ObjectIdentifier.NamedCurves.secp256r1)
    )

    @usableFromInline
    static let p384PublicKey = AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.idEcPublicKey,
        parameters: try! .init(erasing: ASN1ObjectIdentifier.NamedCurves.secp384r1)
    )

    @usableFromInline
    static let p521PublicKey = AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.idEcPublicKey,
        parameters: try! .init(erasing: ASN1ObjectIdentifier.NamedCurves.secp521r1)
    )

    @usableFromInline
    static let ecdsaWithSHA256 = AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.ecdsaWithSHA256,
        parameters: nil
    )

    @usableFromInline
    static let ecdsaWithSHA384 = AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.ecdsaWithSHA384,
        parameters: nil
    )

    @usableFromInline
    static let ecdsaWithSHA512 = AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.ecdsaWithSHA512,
        parameters: nil
    )

    // MARK: For the RSA signature types, explicit ASN.1 NULL is equivalent to a missing parameters field.
    // We include both here, and the usage sites need to handle the equivalent.
    @usableFromInline
    static let sha1WithRSAEncryption = AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.sha1WithRSAEncryption,
        parameters: try! ASN1Any(erasing: ASN1Null())
    )

    @usableFromInline
    static let sha1WithRSAEncryptionUsingNil = AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.sha1WithRSAEncryption,
        parameters: nil
    )

    @usableFromInline
    static let sha256WithRSAEncryption = AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.sha256WithRSAEncryption,
        parameters: try! ASN1Any(erasing: ASN1Null())
    )

    @usableFromInline
    static let sha256WithRSAEncryptionUsingNil = AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.sha256WithRSAEncryption,
        parameters: nil
    )

    @usableFromInline
    static let sha384WithRSAEncryption = AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.sha384WithRSAEncryption,
        parameters: try! ASN1Any(erasing: ASN1Null())
    )

    @usableFromInline
    static let sha384WithRSAEncryptionUsingNil = AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.sha384WithRSAEncryption,
        parameters: nil
    )

    @usableFromInline
    static let sha512WithRSAEncryption = AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.sha512WithRSAEncryption,
        parameters: try! ASN1Any(erasing: ASN1Null())
    )

    @usableFromInline
    static let sha512WithRSAEncryptionUsingNil = AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.sha512WithRSAEncryption,
        parameters: nil
    )

    @usableFromInline
    static let rsaKey = AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.rsaEncryption,
        parameters: try! ASN1Any(erasing: ASN1Null())
    )

    @usableFromInline
    static let sha1UsingNil = AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.sha1,
        parameters: nil
    )

    @usableFromInline
    static let sha1 = AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.sha1,
        parameters: try! ASN1Any(erasing: ASN1Null())
    )

    @usableFromInline
    static let sha256UsingNil = AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.sha256,
        parameters: nil
    )

    @usableFromInline
    static let sha256 = AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.sha256,
        parameters: try! ASN1Any(erasing: ASN1Null())
    )

    @usableFromInline
    static let sha384UsingNil = AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.sha384,
        parameters: nil
    )

    @usableFromInline
    static let sha384 = AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.sha384,
        parameters: try! ASN1Any(erasing: ASN1Null())
    )

    @usableFromInline
    static let sha512UsingNil = AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.sha512,
        parameters: nil
    )

    @usableFromInline
    static let sha512 = AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.sha512,
        parameters: try! ASN1Any(erasing: ASN1Null())
    )

    @usableFromInline
    static let ed25519 = AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.ed25519,
        parameters: nil
    )
}

extension AlgorithmIdentifier: CustomStringConvertible {
    @usableFromInline
    var description: String {
        switch self {
        case .p256PublicKey:
            return "p256PublicKey"
        case .p384PublicKey:
            return "p384PublicKey"
        case .p521PublicKey:
            return "p521PublicKey"
        case .ecdsaWithSHA256:
            return "ecdsaWithSHA256"
        case .ecdsaWithSHA384:
            return "ecdsaWithSHA384"
        case .ecdsaWithSHA512:
            return "ecdsaWithSHA512"
        case .sha1WithRSAEncryption, .sha1WithRSAEncryptionUsingNil:
            return "sha1WithRSAEncryption"
        case .sha256WithRSAEncryption, .sha256WithRSAEncryptionUsingNil:
            return "sha256WithRSAEncryption"
        case .sha384WithRSAEncryption, .sha384WithRSAEncryptionUsingNil:
            return "sha384WithRSAEncryption"
        case .sha512WithRSAEncryption, .sha512WithRSAEncryptionUsingNil:
            return "sha512WithRSAEncryption"
        case .sha1, .sha1UsingNil:
            return "sha1"
        case .sha256, .sha256UsingNil:
            return "sha256"
        case .sha384, .sha384UsingNil:
            return "sha384"
        case .sha512, .sha512UsingNil:
            return "sha512"
        case .ed25519:
            return "ed25519"
        default:
            return "AlgorithmIdentifier(\(self.algorithm) - \(String(reflecting: self.parameters)))"
        }
    }
}

// Relevant note: the PKCS1v1.5 versions need to treat having no parameters and a NULL parameters as identical. This is probably general,
// so we may need a custom equatable implementation there.

extension ASN1ObjectIdentifier.AlgorithmIdentifier {
    static let ecdsaWithSHA256: ASN1ObjectIdentifier = [1, 2, 840, 10045, 4, 3, 2]

    static let ecdsaWithSHA384: ASN1ObjectIdentifier = [1, 2, 840, 10045, 4, 3, 3]

    static let ecdsaWithSHA512: ASN1ObjectIdentifier = [1, 2, 840, 10045, 4, 3, 4]

    static let sha1WithRSAEncryption: ASN1ObjectIdentifier = [1, 2, 840, 113549, 1, 1, 5]

    static let sha1: ASN1ObjectIdentifier = [1, 3, 14, 3, 2, 26]

    static let sha256: ASN1ObjectIdentifier = [2, 16, 840, 1, 101, 3, 4, 2, 1]

    static let sha384: ASN1ObjectIdentifier = [2, 16, 840, 1, 101, 3, 4, 2, 2]

    static let sha512: ASN1ObjectIdentifier = [2, 16, 840, 1, 101, 3, 4, 2, 3]

    static let ed25519: ASN1ObjectIdentifier = [1, 3, 101, 112]
}

extension AlgorithmIdentifier {
    @usableFromInline
    static let ecdsaP256 = AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.idEcPublicKey,
        parameters: try! .init(erasing: ASN1ObjectIdentifier.NamedCurves.secp256r1)
    )
    @usableFromInline
    static let ecdsaP384 = AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.idEcPublicKey,
        parameters: try! .init(erasing: ASN1ObjectIdentifier.NamedCurves.secp384r1)
    )
    @usableFromInline
    static let ecdsaP521 = AlgorithmIdentifier(
        algorithm: .AlgorithmIdentifier.idEcPublicKey,
        parameters: try! .init(erasing: ASN1ObjectIdentifier.NamedCurves.secp521r1)
    )
}
