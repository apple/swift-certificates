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
import Crypto
import protocol Foundation.DataProtocol

public protocol OCSPRequester: Sendable {
    /// Called with a OCSP Request
    /// - Parameters:
    ///   - request: DER-encoded request bytes
    ///   - uri: uri of the
    /// - Returns: DER-encoded response bytes
    func query(request: [UInt8], uri: String) async throws -> [UInt8]
    // TODO: Do we need to handle a request timeout gracefully?
    // TODO: If yes, how should this method signal a timeout? throw an error or return an enum with a success and timeout case?
}

extension ASN1ObjectIdentifier {
    static let sha256NoSign: Self = [2, 16, 840, 1, 101, 3, 4, 2, 1]
    static let sha1NoSign: Self = [1, 3, 14, 3, 2, 26]
}

public struct OCSPVerifierPolicy<Requester: OCSPRequester>: VerifierPolicy {
    enum RequestHashAlgorithm {
        case insecureSha1
        // TODO: can we somehow automatically figure out that a responder will support sha256?
        case sha256
        
        var oid: ASN1ObjectIdentifier {
            switch self {
            case .insecureSha1: return .sha1NoSign
            case .sha256: return .sha256NoSign
            }
        }
        private func hashed(_ value: some DataProtocol) -> ArraySlice<UInt8> {
            switch self {
            case .insecureSha1:
                var hashAlgorithm = Insecure.SHA1()
                hashAlgorithm.update(data: value)
                return Array(hashAlgorithm.finalize())[...]
            case .sha256:
                var hashAlgorithm = SHA256()
                hashAlgorithm.update(data: value)
                return Array(hashAlgorithm.finalize())[...]
            }
        }
        
        fileprivate func issuerNameHashed(_ certificate: Certificate) throws -> ArraySlice<UInt8> {
            /// issuerNameHash is the hash of the issuer's distinguished name
            /// (DN).  The hash shall be calculated over the DER encoding of the
            /// issuer's name field in the certificate being checked.
            var serializer = DER.Serializer()
            try serializer.serialize(certificate.subject)
            return hashed(serializer.serializedBytes)
        }
        
        fileprivate func issuerPublicKeyHashed(_ certificate: Certificate) -> ArraySlice<UInt8> {
            /// issuerKeyHash is the hash of the issuer's public key.  The hash
            /// shall be calculated over the value (excluding tag and length) of
            /// the subject public key field in the issuer's certificate.
            hashed(SubjectPublicKeyInfo(certificate.publicKey).key.bytes)
        }
    }
    var requester: Requester
    var requestHashAlgorithm: RequestHashAlgorithm
    
    public init(requester: Requester) {
        self.requester = requester
        self.requestHashAlgorithm = .insecureSha1
    }
    
    public mutating func chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain) async -> PolicyEvaluationResult {
        for index in chain.dropLast().indices {
            let certificate = chain[index]
            let issuer = chain[chain.index(after: index)]
            switch await certificateMeetsPolicyRequirements(certificate, issuer: issuer) {
            case .meetsPolicy:
                continue
            case .failsToMeetPolicy(let reason):
                return .failsToMeetPolicy(reason: reason)
            }
        }
        return .meetsPolicy
        // TODO: should we verify that the last certificate doesn't have an OCSP extension set?
    }
    
    public mutating func certificateMeetsPolicyRequirements(_ certificate: Certificate, issuer: Certificate) async -> PolicyEvaluationResult {
        guard let description = certificate.extensions[oid: .X509ExtensionID.authorityInformationAccess] else {
            // OCSP not necessary for certificate
            return .meetsPolicy
        }
        do {
            let authorityInformationAccess = try Certificate.Extensions.AuthorityInformationAccess(description)
            
            guard let ocspAccessDescription = authorityInformationAccess.first(where: { $0.method == .ocspServer }) else {
                return .meetsPolicy
            }
 
            guard case .uniformResourceIdentifier(let uri) = ocspAccessDescription.location else {
                return .failsToMeetPolicy(reason: "expected OCSP location to be a URI but got \(ocspAccessDescription.location)")
            }
            
            let requestNonce = OCSPNonce()
            let request = try request(certificate: certificate, issuer: issuer, nonce: requestNonce)
            
            var serializer = DER.Serializer()
            try serializer.serialize(request)
            
            let responseDer = try await requester.query(request: serializer.serializedBytes, uri: uri)
            
            let response = try OCSPResponse(derEncoded: responseDer[...])
            switch response {
            case .successful(let basicResponse):
                guard basicResponse.responseData.version == .v1 else {
                    return .failsToMeetPolicy(reason: "OCSP response version unsupported \(basicResponse.responseData.version)")
                }
                // OCSP responders are allowed to not include the nonce, but if they do it needs to match
                if let responseNonce = try basicResponse.responseData.responseExtensions?.ocspNonce {
                    guard requestNonce == responseNonce else {
                        return .failsToMeetPolicy(reason: "OCSP response nonce does not match request nonce")
                    }
                }
                guard let response = basicResponse.responseData.responses.first else {
                    return .failsToMeetPolicy(reason: "empty OCSP response")
                }
                switch response.certStatus {
                case .good:
                    // TODO: verify signature
                    // TODO: verify time
                    return .meetsPolicy
                case .revoked(let info):
                    return .failsToMeetPolicy(reason: "revoked through OCSP, reason: \(info.revocationReason?.description ?? "nil")")
                case .unknown:
                    return .failsToMeetPolicy(reason: "OCSP response returned as status unknown")
                }
            case .unauthorized, .tryLater, .sigRequired, .malformedRequest, .internalError:
                return .failsToMeetPolicy(reason: "OCSP request failed \(response)")
            }
            
        } catch {
            return .failsToMeetPolicy(reason: "OCSP failed: \(error)")
        }
    }
    
    func request(certificate: Certificate, issuer: Certificate, nonce: OCSPNonce) throws -> OCSPRequest {
        OCSPRequest(tbsRequest: OCSPTBSRequest(
            version: .v1,
            requestList: [
                OCSPSingleRequest(certID: OCSPCertID(
                    hashAlgorithm: .init(algorithm: requestHashAlgorithm.oid, parameters: nil),
                    issuerNameHash: .init(contentBytes: try requestHashAlgorithm.issuerNameHashed(issuer)),
                    issuerKeyHash: .init(contentBytes: requestHashAlgorithm.issuerPublicKeyHashed(issuer)),
                    serialNumber: certificate.serialNumber
                ))
            ],
            requestExtensions: try .init(builder: {
                nonce
            })
        ))
    }
}
