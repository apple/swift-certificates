//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCertificates open source project
//
// Copyright (c) 2022 Apple Inc. and the SwiftCertificates project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.md for the list of SwiftCertificates project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import SwiftASN1

/// ``OCSPRequest`` is defined in ASN.1 as:
/// ```
/// OCSPRequest ::= SEQUENCE {
///    tbsRequest              TBSRequest,
///    optionalSignature   [0] EXPLICIT Signature OPTIONAL }
/// ```
struct OCSPRequest: DERImplicitlyTaggable, Hashable {
    static var defaultIdentifier: ASN1Identifier {
        .sequence
    }
    
    var tbsRequest: OCSPTBSRequest
    
    var signature: OCSPSignature?
    
    init(derEncoded: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        fatalError()
    }
    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        fatalError()
    }
}

/// ``OCSPTBSRequest`` is defined in ASN.1 as:
/// ```
/// TBSRequest ::= SEQUENCE {
///    version             [0] EXPLICIT Version DEFAULT v1,
///    requestorName       [1] EXPLICIT GeneralName OPTIONAL,
///    requestList             SEQUENCE OF Request,
///    requestExtensions   [2] EXPLICIT Extensions OPTIONAL }
///
/// Version ::= INTEGER { v1(0) }
/// ```
struct OCSPTBSRequest: DERImplicitlyTaggable, Hashable {
    static var defaultIdentifier: ASN1Identifier {
        .sequence
    }
    
    var version: Int
    
    var requestorName: GeneralName?
    
    var requestList: [OCSPSingleRequest]
    
    var requestExtensions: Certificate.Extensions?
    
    init(derEncoded: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        fatalError()
    }
    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        fatalError()
    }
}

/// ``OCSPSingleRequest`` is defined in ASN.1 as:
/// ```
/// SingleRequest ::= SEQUENCE {
///    reqCert                     CertID,
///    singleRequestExtensions [0] EXPLICIT Extensions OPTIONAL }
/// ```
/// - note: originally named just `Request` in RFC 6960 but prefix `Single` added to avoid naming conflicts with ``OCSPRequest``
struct OCSPSingleRequest: DERImplicitlyTaggable, Hashable {
    static var defaultIdentifier: ASN1Identifier {
        .sequence
    }
    
    var certID: OCSPCertID
    
    var singleRequestExtensions: Certificate.Extensions?
    
    init(derEncoded: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        fatalError()
    }
    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        fatalError()
    }
}


/// ``OCSPSignature`` is defined in ASN.1 as:
/// ```
/// Signature ::= SEQUENCE {
///    signatureAlgorithm      AlgorithmIdentifier,
///    signature               BIT STRING,
///    certs               [0] EXPLICIT SEQUENCE OF Certificate OPTIONAL }
/// ```
struct OCSPSignature: DERImplicitlyTaggable, Hashable {
    static var defaultIdentifier: ASN1Identifier {
        .sequence
    }
    
    var algortihmIdentifier: AlgorithmIdentifier
    
    var signature: ASN1BitString
    
    var certs: [Certificate]?
    
    init(derEncoded: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        fatalError()
    }
    func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        fatalError()
    }
}
