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
import struct Foundation.Date
import typealias Foundation.TimeInterval

public protocol OCSPRequester: Sendable {
    /// Called with a OCSP Request.
    ///
    /// The ``OCSPVerifierPolicy`` will call this method for each certificate witch contains a OCSP URI and will cancel the call if it reaches a deadline.
    /// Therefore the implementation of this method should **not** set a deadline on the HTTP request.
    /// - Parameters:
    ///   - request: DER-encoded request bytes
    ///   - uri: uri of the OCSP responder
    /// - Returns: DER-encoded response bytes
    func query(request: [UInt8], uri: String) async throws -> [UInt8]
}


extension ASN1ObjectIdentifier {
    static let sha256NoSign: Self = [2, 16, 840, 1, 101, 3, 4, 2, 1]
    static let sha1NoSign: Self = [1, 3, 14, 3, 2, 26]
}

public struct OCSPVerifierPolicy<Requester: OCSPRequester>: VerifierPolicy {
    enum RequestHashAlgorithm {
        case insecureSha1
        // we can't yet enable sha256 by default but we want in the future
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
    
    /// max duration the policy verification is allowed in total
    ///
    /// This is not the duration for a single OCSP request but the total duration of all OCSP requests.
    var maxDuration: TimeInterval
    
    public init(requester: Requester) {
        self.requester = requester
        self.requestHashAlgorithm = .insecureSha1
        self.maxDuration = 10
    }
    
    public func chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain) async -> PolicyEvaluationResult {
        await withDeadline(maxDuration) {
            await chainMeetsPolicyRequirementsWithoutDeadline(chain: chain)
        }
    }
    
    private func chainMeetsPolicyRequirementsWithoutDeadline(chain: UnverifiedCertificateChain) async -> PolicyEvaluationResult {
        for index in chain.dropLast().indices {
            let certificate = chain[index]
            let issuer = chain[chain.index(after: index)]
            switch await self.certificateMeetsPolicyRequirements(certificate, issuer: issuer) {
            case .meetsPolicy:
                continue
            case .failsToMeetPolicy(let reason):
                return .failsToMeetPolicy(reason: reason)
            }
        }
        
        do {
            let hasRootCertificateOCSPURI = try chain.last?.extensions.authorityInformationAccess?.contains { $0.method == .ocspServer } ?? false
            guard !hasRootCertificateOCSPURI else {
                return .failsToMeetPolicy(reason: "root certificate is not allowed to have an OCSP URI")
            }
        } catch {
            return .failsToMeetPolicy(reason: "failed to parse AuthorityInformationAccess extension")
        }
        return .meetsPolicy
    }
    
    
    
    private func certificateMeetsPolicyRequirements(_ certificate: Certificate, issuer: Certificate) async -> PolicyEvaluationResult {
        guard let description = certificate.extensions[oid: .X509ExtensionID.authorityInformationAccess] else {
            // OCSP not necessary for certificate
            return .meetsPolicy
        }
        let authorityInformationAccess: Certificate.Extensions.AuthorityInformationAccess
        do {
            authorityInformationAccess = try .init(description)
        } catch {
            return .failsToMeetPolicy(reason: "failed to decode AuthorityInformationAccess \(error)")
        }
        guard let ocspAccessDescription = authorityInformationAccess.first(where: { $0.method == .ocspServer }) else {
            // OCSP not necessary for certificate
            return .meetsPolicy
        }

        guard case .uniformResourceIdentifier(let responderURI) = ocspAccessDescription.location else {
            return .failsToMeetPolicy(reason: "expected OCSP location to be a URI but got \(ocspAccessDescription.location)")
        }
        
        let certID: OCSPCertID
        do {
            certID = try self.certID(certificate: certificate, issuer: issuer)
        } catch {
            return .failsToMeetPolicy(reason: "failed to create OCSPCertID \(error)")
        }
        
        return await queryAndVerifyCertificateStatus(for: certID, responderURI: responderURI)
    }
    
    private func queryAndVerifyCertificateStatus(for certID: OCSPCertID, responderURI: String) async -> PolicyEvaluationResult {
        let requestNonce = OCSPNonce()
        let requestBytes: [UInt8]
        do {
            let request = try request(certID: certID, nonce: requestNonce)
            var serializer = DER.Serializer()
            try serializer.serialize(request)
            requestBytes = serializer.serializedBytes
        } catch {
            return .failsToMeetPolicy(reason: "failed to create OCSPRequest \(error)")
        }
        
        let responseDerEncoded: [UInt8]
        do {
            responseDerEncoded = try await requester.query(request: requestBytes, uri: responderURI)
        } catch {
            // the request can fail for various reasons and we need to tolerate this
            return .meetsPolicy
        }
        let response: OCSPResponse
        do {
            response = try OCSPResponse(derEncoded: responseDerEncoded[...])
        } catch {
            return .failsToMeetPolicy(reason: "OCSP deserialisation failed \(error)")
        }
        
        return verifyResponse(response, requestedCertID: certID, requestNonce: requestNonce)
    }
    
    private func verifyResponse(_ response: OCSPResponse, requestedCertID: OCSPCertID, requestNonce: OCSPNonce) -> PolicyEvaluationResult {
        switch response {
        case .unauthorized, .tryLater, .sigRequired, .malformedRequest, .internalError:
            return .failsToMeetPolicy(reason: "OCSP request failed \(OCSPResponseStatus(response))")
        case .successful(let basicResponse):
            guard basicResponse.responseData.version == .v1 else {
                return .failsToMeetPolicy(reason: "OCSP response version unsupported \(basicResponse.responseData.version)")
            }
            do {
                // OCSP responders are allowed to not include the nonce, but if they do it needs to match
                if let responseNonce = try basicResponse.responseData.responseExtensions?.ocspNonce {
                    guard requestNonce == responseNonce else {
                        return .failsToMeetPolicy(reason: "OCSP response nonce does not match request nonce")
                    }
                }
            } catch {
                return .failsToMeetPolicy(reason: "failed to decode nonce response \(error)")
            }
            guard let response = basicResponse.responseData.responses.first(where: { $0.certID == requestedCertID }) else {
                return .failsToMeetPolicy(reason: "OCSP response does not include a response for the queried certificate")
            }
            
            switch response.certStatus {
            case .good:
                switch response.verifyTime() {
                case .meetsPolicy:
                    break
                case .failsToMeetPolicy(let reason):
                    return .failsToMeetPolicy(reason: reason)
                }
                
                // TODO: verify signature
                return .meetsPolicy
            case .revoked(let info):
                return .failsToMeetPolicy(reason: "revoked through OCSP, reason: \(info.revocationReason?.description ?? "nil")")
            case .unknown:
                return .failsToMeetPolicy(reason: "OCSP response returned as status unknown")
            }
        }
    }
    
    func certID(certificate: Certificate, issuer: Certificate) throws -> OCSPCertID {
        OCSPCertID(
            hashAlgorithm: .init(algorithm: requestHashAlgorithm.oid, parameters: nil),
            issuerNameHash: .init(contentBytes: try requestHashAlgorithm.issuerNameHashed(issuer)),
            issuerKeyHash: .init(contentBytes: requestHashAlgorithm.issuerPublicKeyHashed(issuer)),
            serialNumber: certificate.serialNumber
        )
    }
    
    func request(certID: OCSPCertID, nonce: OCSPNonce) throws -> OCSPRequest {
        OCSPRequest(tbsRequest: OCSPTBSRequest(
            version: .v1,
            requestList: [
                OCSPSingleRequest(certID: certID)
            ],
            requestExtensions: try .init(builder: {
                nonce
            })
        ))
    }
}

extension OCSPSingleResponse {
    func verifyTime(now: Date = Date()) -> PolicyEvaluationResult {
        guard let nextUpdateGeneralizedTime = self.nextUpdate else {
            return .failsToMeetPolicy(reason: "OCSP response `nextUpdate` is nil")
        }
        
        guard
            let thisUpdate = Date(self.thisUpdate),
            let nextUpdate = Date(nextUpdateGeneralizedTime)
        else {
            return .failsToMeetPolicy(reason: "could not convert time specified in certificate to a `Date`")
        }
        guard thisUpdate <= now else {
            return .failsToMeetPolicy(reason: "OCSP response `thisUpdate` (\(self.thisUpdate) is in the future but should be in the past")
        }
        
        guard nextUpdate >= now else {
            return .failsToMeetPolicy(reason: "OCSP response `nextUpdate` (\(nextUpdateGeneralizedTime) is in the past but should be in the future")
        }
        
        return .meetsPolicy
    }
}


/// Executes the given `task` up to `maxDuration` seconds and cancel it it exceeds this deadline.
/// - Parameters:
///   - maxDuration: max execution duration of
///   - task: the async task to execute and cancel after `maxDuration` seconds
/// - Returns: the result of `task`
private func withDeadline<Result>(
    _ maxDuration: TimeInterval,
    task: @escaping () async -> Result
) async -> Result {
    let resultTask = Task<Result, Never> {
        await task()
    }
    
    let cancelationTask = Task {
        // seconds -> milliseconds -> microseconds -> nanoseconds
        try await Task.sleep(nanoseconds: UInt64(maxDuration * 1000 * 1000 * 1000))
        resultTask.cancel()
    }
    defer { cancelationTask.cancel() }
    
    return await withTaskCancellationHandler {
        await resultTask.value
    } onCancel: {
        resultTask.cancel()
    }
}
