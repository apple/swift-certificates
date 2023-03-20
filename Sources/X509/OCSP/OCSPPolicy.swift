//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCertificates open source project
//
// Copyright (c) 2022-2023 Apple Inc. and the SwiftCertificates project authors
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
import Foundation

// Swift CI has implicit concurrency disabled
import _Concurrency

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

struct OCSPResponderSigningPolicy: VerifierPolicy {
    /// direct issuer of the certificate for which we check the OCSP status for
    var issuer: Certificate
    mutating func chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain) async -> PolicyEvaluationResult {
        // The root of the chain is always guaranteed to be the issuer as the root certificate store only contains the issuer
        guard chain.last == issuer else {
            return .failsToMeetPolicy(reason: "OCSP response must be signed by the certificate issuer or a certificate that chains up to the issuer")
        }
        if chain.count == 1 {
            // the leaf is the issuer which does not need to have the OCSP signing extended key usage
            return .meetsPolicy
        }
        
        let leaf = chain.leaf
        
        // RFC 6960 Section 4.2.2.2. Authorized Responders
        // OCSP signing delegation SHALL be designated by the inclusion of
        // id-kp-OCSPSigning in an extended key usage certificate extension
        // included in the OCSP response signer's certificate.
        guard let extendedKeyUsage: ExtendedKeyUsage = try? leaf.extensions.extendedKeyUsage else {
            return .failsToMeetPolicy(reason: "OCSP response certificate has no extended key usages")
        }
        let hasOCSPSigningUsage = extendedKeyUsage.usages.contains {
            $0 == ExtendedKeyUsage.Usage(oid: .ExtendedKeyUsage.ocspSigning)
        }
        guard hasOCSPSigningUsage else {
            return .failsToMeetPolicy(reason: "OCSP response certificate does not have OCSP signing extended key usage set")
        }
        
        
        return .meetsPolicy
    }
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
    private var validationTime: Date
    
    /// If true, a nonce is generated per OCSP request and attached to the request.
    /// If the response contains a nonce, it must match with the initially send nonce.
    /// currently only set to false for testing
    var nonceExtensionEnabled: Bool = true
    
    public init(requester: Requester, validationTime: Date) {
        self.requester = requester
        self.requestHashAlgorithm = .insecureSha1
        self.maxDuration = 10
        self.validationTime = validationTime
    }
    
    // this method currently doesn't need to be mutating. However, we want to reserve the right to change our mind
    // in the future and therefore still declare this method as mutating in the public API.
    public mutating func chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain) async -> PolicyEvaluationResult {
        await withTimeout(maxDuration) { [self] in
            await self.chainMeetsPolicyRequirementsWithoutDeadline(chain: chain)
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
        
        return await self.queryAndVerifyCertificateStatus(for: certID, responderURI: responderURI, issuer: issuer)
    }
    
    private func queryAndVerifyCertificateStatus(for certID: OCSPCertID, responderURI: String, issuer: Certificate) async -> PolicyEvaluationResult {
        let requestNonce = nonceExtensionEnabled ? OCSPNonce() : nil
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
        
        return await self.verifyResponse(response, requestedCertID: certID, requestNonce: requestNonce, issuer: issuer)
    }
    
    private func verifyResponse(_ response: OCSPResponse, requestedCertID: OCSPCertID, requestNonce: OCSPNonce?, issuer: Certificate) async -> PolicyEvaluationResult {
        switch response {
        case .unauthorized, .tryLater, .sigRequired, .malformedRequest, .internalError:
            return .failsToMeetPolicy(reason: "OCSP request failed \(OCSPResponseStatus(response))")
        case .successful(let basicResponse):
            return await self.verifySuccessfulResponse(basicResponse, requestedCertID: requestedCertID, requestNonce: requestNonce, issuer: issuer)
        }
    }
    
    private func verifySuccessfulResponse(_ basicResponse: BasicOCSPResponse, requestedCertID: OCSPCertID, requestNonce: OCSPNonce?, issuer: Certificate) async -> PolicyEvaluationResult {
        guard basicResponse.responseData.version == .v1 else {
            return .failsToMeetPolicy(reason: "OCSP response version unsupported \(basicResponse.responseData.version)")
        }
        
        do {
            // if requestNonce is nil, `nonceExtensionEnabled` is set to false and we therefore skip nonce verification
            if let requestNonce {
                // OCSP responders are allowed to not include the nonce, but if they do it needs to match
                if let responseNonce = try basicResponse.responseData.responseExtensions?.ocspNonce,
                   requestNonce != responseNonce {
                    return .failsToMeetPolicy(reason: "OCSP response nonce does not match request nonce")
                }
            } else {
                precondition(nonceExtensionEnabled == false)
            }
        } catch {
            return .failsToMeetPolicy(reason: "failed to decode nonce response \(error)")
        }
        guard let response = basicResponse.responseData.responses.first(where: { $0.certID == requestedCertID }) else {
            return .failsToMeetPolicy(reason: "OCSP response does not include a response for the queried certificate \(requestedCertID) - responses: \(basicResponse.responseData.responses)")
        }
        
        switch await self.validateResponseSignature(basicResponse, issuer: issuer) {
        case .meetsPolicy:
            break
        case .failsToMeetPolicy(let reason):
            return .failsToMeetPolicy(reason: reason)
        }
        
        switch response.verifyTime(validationTime: self.validationTime) {
        case .meetsPolicy:
            break
        case .failsToMeetPolicy(let reason):
            return .failsToMeetPolicy(reason: reason)
        }
        
        switch response.certStatus {
        case .revoked(let info):
            return .failsToMeetPolicy(reason: "revoked through OCSP, reason: \(info.revocationReason?.description ?? "nil")")
        case .unknown:
            return .failsToMeetPolicy(reason: "OCSP response returned as status unknown")
        case .good:
            return .meetsPolicy
        }
    }
    
    private func validateResponseSignature(
        _ basicResponse: BasicOCSPResponse,
        issuer: Certificate
    ) async -> PolicyEvaluationResult {
        let responderID = basicResponse.responseData.responderID
        
        let leafCertificate: Certificate?
        if issuer.matches(responderID) {
            leafCertificate = issuer
        } else {
            leafCertificate = basicResponse.certs?.first(where: { $0.matches(responderID) })
        }
        
        guard let leafCertificate else {
            return .failsToMeetPolicy(reason: "could not find OCSP responder certificate for id \(responderID)")
        }
        
        let signatureValidationResult = self.validateSignature(
            certificate: leafCertificate,
            tbsResponse: basicResponse.responseDataBytes,
            signatureBytes: basicResponse.signature.bytes,
            signatureAlgorithmIdentifier: basicResponse.signatureAlgorithm
        )
        
        switch signatureValidationResult {
        case .meetsPolicy:
            break
        case .failsToMeetPolicy(let reason):
            return .failsToMeetPolicy(reason: reason)
        }
        
        var verifier = Verifier(
            rootCertificates: CertificateStore([issuer]),
            policy: PolicySet(policies: [
                OCSPResponderSigningPolicy(issuer: issuer),
                RFC5280Policy(validationTime: validationTime),
            ])
        )

        let validationResult = await verifier.validate(leafCertificate: leafCertificate, intermediates: CertificateStore())
        
        switch validationResult {
        case .couldNotValidate(let failures):
            return .failsToMeetPolicy(reason: "could not validate OCSP responder certificates \(failures)")
        case .validCertificate:
            return .meetsPolicy
        }
    }
    
    private func validateSignature(
        certificate: Certificate,
        tbsResponse: ArraySlice<UInt8>,
        signatureBytes: ArraySlice<UInt8>,
        signatureAlgorithmIdentifier: AlgorithmIdentifier
    ) -> PolicyEvaluationResult {
        let signatureAlgorithm = Certificate.SignatureAlgorithm(algorithmIdentifier: signatureAlgorithmIdentifier)
        let signature: Certificate.Signature
        do {
            signature = try Certificate.Signature(signatureAlgorithm: signatureAlgorithm, signatureBytes: .init(bytes: signatureBytes))
        } catch {
            return .failsToMeetPolicy(reason: "could not create signature for OCSP response \(error)")
        }
        
        if certificate.publicKey.isValidSignature(signature, for: tbsResponse, signatureAlgorithm: signatureAlgorithm) {
            return .meetsPolicy
        } else {
            return .failsToMeetPolicy(reason: "OCSP response signature is not valid")
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
    init(certID: OCSPCertID, nonce: OCSPNonce?) throws {
        self.init(tbsRequest: OCSPTBSRequest(
            version: .v1,
            requestList: [
                OCSPSingleRequest(certID: certID)
            ],
            requestExtensions: try .init(builder: {
                if let nonce {
                    nonce
                }
            })
        ))
    }
}

extension OCSPSingleResponse {
    fileprivate func verifyTime(validationTime: Date) -> PolicyEvaluationResult {
        /// Clients MUST check for the existence of the nextUpdate field and MUST
        /// ensure the current time, expressed in GMT time as described in
        /// Section 2.2.4, falls between the thisUpdate and nextUpdate times.  Ifhttps://www.rfc-editor.org/rfc/rfc5019#section-4
        /// the nextUpdate field is absent, the client MUST reject the response.
        /// https://www.rfc-editor.org/rfc/rfc5019#section-4
        guard let nextUpdateGeneralizedTime = self.nextUpdate else {
            return .failsToMeetPolicy(reason: "OCSP response `nextUpdate` is nil")
        }
        
        guard
            let thisUpdate = Date.init(self.thisUpdate),
            let nextUpdate = Date(nextUpdateGeneralizedTime)
        else {
            return .failsToMeetPolicy(reason: "could not convert time specified in certificate to a `Date`")
        }
        guard thisUpdate <= validationTime else {
            return .failsToMeetPolicy(reason: "OCSP response `thisUpdate` (\(self.thisUpdate) is in the future but should be in the past")
        }
        
        guard nextUpdate >= validationTime else {
            return .failsToMeetPolicy(reason: "OCSP response `nextUpdate` (\(nextUpdateGeneralizedTime) is in the past but should be in the future")
        }
        
        return .meetsPolicy
    }
}

extension Certificate {
    fileprivate func matches(_ responderID: ResponderID) -> Bool {
        switch responderID {
        case .byName(let subject):
            return self.subject == subject
        case .byKey(let subjectKeyIdentifier):
            return (try? self.extensions.subjectKeyIdentifier?.keyIdentifier == subjectKeyIdentifier.bytes) ?? false
        }
    }
}

/// Executes the given `operation` up to `maxDuration` seconds and cancels it if it exceeds the timeout.
/// - Parameters:
///   - maxDuration: max execution duration in seconds of `operation`
///   - operation: the task to start and cancel after `maxDuration` seconds
/// - Returns: the result of `operation`
private func withTimeout<Result: Sendable>(
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
