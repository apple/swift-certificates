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
    /// Called with an OCSP Request.
    ///
    /// The ``OCSPVerifierPolicy`` will call this method for each certificate that contains an OCSP URI and will cancel the call if it reaches a deadline.
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

enum OCSPRequestHashAlgorithm {
    case insecureSha1
    // we can't yet enable sha256 by default but we want in the future
    case sha256
    
    var oid: ASN1ObjectIdentifier {
        switch self {
        case .insecureSha1: return .sha1NoSign
        case .sha256: return .sha256NoSign
        }
    }
    private func hashed(_ value: ArraySlice<UInt8>) -> ArraySlice<UInt8> {
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
        return self.hashed(serializer.serializedBytes[...])
    }
    
    fileprivate func issuerPublicKeyHashed(_ certificate: Certificate) -> ArraySlice<UInt8> {
        /// issuerKeyHash is the hash of the issuer's public key.  The hash
        /// shall be calculated over the value (excluding tag and length) of
        /// the subject public key field in the issuer's certificate.
        self.hashed(SubjectPublicKeyInfo(certificate.publicKey).key.bytes)
    }
}

public struct OCSPVerifierPolicy<Requester: OCSPRequester>: VerifierPolicy {
    
    private var requester: Requester
    private var requestHashAlgorithm: OCSPRequestHashAlgorithm
    
    /// max duration the policy verification is allowed in total
    ///
    /// This is not the duration for a single OCSP request but the total duration of all OCSP requests.
    private var maxDuration: TimeInterval
    
    /// the time used to decide if the request is relatively recent
    /// if nil, the current system time is used
    /// note that this is only used for testing purposes
    private var now: Date?
    
    public init(requester: Requester) {
        self.init(requester: requester, now: nil)
    }
    
    internal init(requester: Requester, now: Date?) {
        self.requester = requester
        self.requestHashAlgorithm = .insecureSha1
        self.maxDuration = 10
        self.now = now
    }
    
    public func chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain) async -> PolicyEvaluationResult {
        await withTimeout(maxDuration) {
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
            if hasRootCertificateOCSPURI {
                return .failsToMeetPolicy(reason: "root certificate is not allowed to have an OCSP URI")
            }
        } catch {
            return .failsToMeetPolicy(reason: "failed to parse AuthorityInformationAccess extension")
        }
        return .meetsPolicy
    }
    
    
    
    private func certificateMeetsPolicyRequirements(_ certificate: Certificate, issuer: Certificate) async -> PolicyEvaluationResult {
        
        let authorityInformationAccess: AuthorityInformationAccess?
        do {
            authorityInformationAccess = try certificate.extensions.authorityInformationAccess
        } catch {
            return .failsToMeetPolicy(reason: "failed to decode AuthorityInformationAccess \(error)")
        }
        guard let authorityInformationAccess else {
            // OCSP not necessary for certificate
            return .meetsPolicy
        }
        
        let ocspAccessDescriptions = authorityInformationAccess.lazy.filter { $0.method == .ocspServer }
        if ocspAccessDescriptions.isEmpty {
            // OCSP not necessary for certificate
            return .meetsPolicy
        }
        
        // We could find more than one ocsp server, where only one has a uri. We want to find the first one with a uri.
        let responderURI = ocspAccessDescriptions.lazy.compactMap { description -> String? in
            guard case .uniformResourceIdentifier(let responderURI) = description.location else {
                return nil
            }
            return responderURI
        }.first
        guard let responderURI else {
            return .failsToMeetPolicy(reason: "expected OCSP location to be a URI but got \(ocspAccessDescriptions)")
        }
        
        let certID: OCSPCertID
        do {
            certID = try OCSPCertID(hashAlgorithm: requestHashAlgorithm, certificate: certificate, issuer: issuer)
        } catch {
            return .failsToMeetPolicy(reason: "failed to create OCSPCertID \(error)")
        }
        
        return await self.queryAndVerifyCertificateStatus(for: certID, responderURI: responderURI)
    }
    
    private func queryAndVerifyCertificateStatus(for certID: OCSPCertID, responderURI: String) async -> PolicyEvaluationResult {
        let requestNonce = OCSPNonce()
        let requestBytes: [UInt8]
        do {
            let request = try OCSPRequest(certID: certID, nonce: requestNonce)
            var serializer = DER.Serializer()
            try serializer.serialize(request)
            requestBytes = serializer.serializedBytes
        } catch {
            return .failsToMeetPolicy(reason: "failed to create OCSPRequest \(error)")
        }
        
        let responseDerEncoded: [UInt8]
        do {
            responseDerEncoded = try await self.requester.query(request: requestBytes, uri: responderURI)
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
        
        return self.verifyResponse(response, requestedCertID: certID, requestNonce: requestNonce)
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
                if let responseNonce = try basicResponse.responseData.responseExtensions?.ocspNonce,
                   requestNonce != responseNonce {
                    return .failsToMeetPolicy(reason: "OCSP response nonce does not match request nonce")
                }
            } catch {
                return .failsToMeetPolicy(reason: "failed to decode nonce response \(error)")
            }
            guard let response = basicResponse.responseData.responses.first(where: { $0.certID == requestedCertID }) else {
                return .failsToMeetPolicy(reason: "OCSP response does not include a response for the queried certificate")
            }
            
            switch response.certStatus {
            case .good:
                switch response.verifyTime(now: self.now ?? Date()) {
                case .meetsPolicy:
                    break
                case .failsToMeetPolicy(let reason):
                    return .failsToMeetPolicy(reason: reason)
                }
                
                // TODO: verify signature: rdar://104687979
                return .meetsPolicy
            case .revoked(let info):
                return .failsToMeetPolicy(reason: "revoked through OCSP, reason: \(info.revocationReason?.description ?? "nil")")
            case .unknown:
                return .failsToMeetPolicy(reason: "OCSP response returned as status unknown")
            }
        }
    }
}

extension OCSPCertID {
    init(hashAlgorithm: OCSPRequestHashAlgorithm, certificate: Certificate, issuer: Certificate) throws {
        self.init(
            hashAlgorithm: .init(algorithm: hashAlgorithm.oid, parameters: nil),
            issuerNameHash: .init(contentBytes: try hashAlgorithm.issuerNameHashed(issuer)),
            issuerKeyHash: .init(contentBytes: hashAlgorithm.issuerPublicKeyHashed(issuer)),
            serialNumber: certificate.serialNumber
        )
    }
}

extension OCSPRequest {
    init(certID: OCSPCertID, nonce: OCSPNonce) throws {
        self.init(tbsRequest: OCSPTBSRequest(
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
    fileprivate func verifyTime(now: Date) -> PolicyEvaluationResult {
        /// Clients MUST check for the existence of the nextUpdate field and MUST
        /// ensure the current time, expressed in GMT time as described in
        /// Section 2.2.4, falls between the thisUpdate and nextUpdate times.  Ifhttps://www.rfc-editor.org/rfc/rfc5019#section-4
        /// the nextUpdate field is absent, the client MUST reject the response.
        /// https://www.rfc-editor.org/rfc/rfc5019#section-4
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

/// Executes the given `operation` up to `maxDuration` seconds and cancels it if it exceeds the timeout.
/// - Parameters:
///   - maxDuration: max execution duration in seconds of `operation`
///   - operation: the task to start and cancel after `maxDuration` seconds
/// - Returns: the result of `operation`
private func withTimeout<Result>(
    _ maxDuration: TimeInterval,
    operation: @escaping @Sendable () async -> Result
) async -> Result {
    await withTaskGroup(of: Optional<Result>.self) { group in
        // add actual operation
        group.addTask(operation: operation)
        // add watchdog
        group.addTask {
            try? await Task.sleep(nanoseconds: UInt64(maxDuration * 1000 * 1000 * 1000))
            return nil
        }
        // we add two tasks and it is therefore safe to unwrap two calls to `group.next()`
        let firstResult = await group.next()!
        // either the operation or the watchdog has finished
        // regardless of which finished first, we need to cancel the second task
        group.cancelAll()
        let secondResult = await group.next()!
        // the watchdog and the actually operation have now completed.
        // the result of the operation is non-nil and must be in either firstResult or secondResult
        // therefore it is safe to unwrap it
        return (firstResult ?? secondResult)!
    }
}
