//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCertificates open source project
//
// Copyright (c) 2022-2025 Apple Inc. and the SwiftCertificates project authors
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
#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif

// Swift CI has implicit concurrency disabled
import _Concurrency

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public protocol OCSPRequester: Sendable {
    /// Called with an OCSP Request.
    ///
    /// The ``OCSPVerifierPolicy`` will call this method for each certificate that contains an OCSP URI and will cancel the call if it reaches a deadline.
    /// Therefore the implementation of this method should **not** set a deadline on the HTTP request.
    /// - Parameters:
    ///   - request: DER-encoded request bytes
    ///   - uri: uri of the OCSP responder
    /// - Returns: DER-encoded response bytes if they request was successful or a terminal or non-terminal error.
    func query(request: [UInt8], uri: String) async -> OCSPRequesterQueryResult
}

public struct OCSPRequesterQueryResult: Sendable {
    @usableFromInline
    enum Storage: Sendable {
        case success([UInt8])
        case nonTerminal(Error)
        case terminal(Error)
    }
    @usableFromInline
    var storage: Storage

    @inlinable
    init(_ storage: Storage) {
        self.storage = storage
    }
}

extension OCSPRequesterQueryResult {
    /// The OCSP query is considered successful and has returned the given DER-encoded response bytes.
    /// - Parameter bytes: DER-encoded response bytes
    @inlinable
    public static func response(_ bytes: [UInt8]) -> Self {
        .init(.success(bytes))
    }

    /// The OCSP query is considered unsuccessful but will **not** fail verification, neither in ``OCSPFailureMode/soft`` nor in ``OCSPFailureMode/hard`` failure mode.
    /// The certificate is then considered to meet the ``OCSPVerifierPolicy``.
    /// - Parameter reason: the reason why the OCSP query failed which may be used for diagnostics
    /// - warning: The ``OCSPVerifierPolicy`` will assume that verification has succeeded and therefore pass OCSP verification for the given certificate.
    @inlinable
    public static func nonTerminalError(_ reason: Error) -> Self {
        .init(.nonTerminal(reason))
    }

    /// The OCSP query is considered unsuccessful and will fail verification in both ``OCSPFailureMode/soft`` and ``OCSPFailureMode/hard`` failure mode.
    /// The certificate is then considered to not meet the ``OCSPVerifierPolicy`` and ``OCSPVerifierPolicy/chainMeetsPolicyRequirements(chain:)`` will return ``PolicyEvaluationResult/failsToMeetPolicy(reason:)-3tp9a`` with the given reason.
    /// - Parameter reason: the reason why the OCSP query failed
    @inlinable
    public static func terminalError(_ reason: Error) -> Self {
        .init(.terminal(reason))
    }
}

extension ASN1ObjectIdentifier {
    static let sha256NoSign: Self = [2, 16, 840, 1, 101, 3, 4, 2, 1]
    static let sha1NoSign: Self = [1, 3, 14, 3, 2, 26]
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
struct OCSPResponderSigningPolicy: VerifierPolicy {
    let verifyingCriticalExtensions: [ASN1ObjectIdentifier] = []

    /// direct issuer of the certificate for which we check the OCSP status for
    var issuer: Certificate
    mutating func chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain) async -> PolicyEvaluationResult {
        // The root of the chain is always guaranteed to be the issuer as the root certificate store only contains the issuer
        guard chain.last == issuer else {
            return .failsToMeetPolicy(
                reason:
                    "OCSP response must be signed by the certificate issuer or a certificate that chains up to the issuer"
            )
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

        guard extendedKeyUsage.usages.contains(.ocspSigning) else {
            return .failsToMeetPolicy(
                reason: "OCSP response certificate does not have OCSP signing extended key usage set"
            )
        }

        return .meetsPolicy
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
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
        self.hashed(certificate.publicKey.subjectPublicKeyInfoBytes)
    }
}

/// Defines the behaviour of ``OCSPVerifierPolicy`` in the event of a failure.
/// ``soft`` should be used most of the time and will only fail verification if a verified OCSP response reports a status of revoked.
public struct OCSPFailureMode: Hashable, Sendable {
    /// ``soft`` failure mode will only fail verification if a verified and valid OCSP response reports a status of revoked.
    /// If the request, decoding or validation fails, the certificates will still meet the policy.
    public static var soft: Self { .init(storage: .soft) }
    /// ``hard`` failure mode will fail verification if any of the OCSP request decoding or validation fails in addition to revoked or unknown status reports from the responder.
    /// Verification will succeed if the OCSP response status is good.
    /// In addition, if the request fails or times out the certificate will still meet the policy though to allow the network to be down.
    public static var hard: Self { .init(storage: .hard) }

    enum Storage: Hashable, Sendable {
        case soft
        case hard
    }

    var storage: Storage
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
public struct OCSPVerifierPolicy<Requester: OCSPRequester>: VerifierPolicy, Sendable {
    public let verifyingCriticalExtensions: [ASN1ObjectIdentifier] = []

    struct Storage: Sendable {
        private var failureMode: OCSPFailureMode
        private var requester: Requester
        private var requestHashAlgorithm: OCSPRequestHashAlgorithm

        /// max duration the policy verification is allowed in total
        ///
        /// This is not the duration for a single OCSP request but the total duration of all OCSP requests.
        private var maxDuration: TimeInterval

        /// the time used to decide if the request is relatively recent
        private var fixedValidationTime: Date?

        /// If true, a nonce is generated per OCSP request and attached to the request.
        /// If the response contains a nonce, it must match with the initially send nonce.
        /// currently only set to false for testing
        fileprivate var nonceExtensionEnabled: Bool = true

        fileprivate init(
            failureMode: OCSPFailureMode,
            requester: Requester,
            requestHashAlgorithm: OCSPRequestHashAlgorithm,
            maxDuration: TimeInterval,
            fixedValidationTime: Date? = nil
        ) {
            self.requester = requester
            self.requestHashAlgorithm = requestHashAlgorithm
            self.maxDuration = maxDuration
            self.fixedValidationTime = fixedValidationTime
            self.failureMode = failureMode
        }
    }

    var nonceExtensionEnabled: Bool {
        get {
            self.storage.nonceExtensionEnabled
        }
        set {
            self.storage.nonceExtensionEnabled = newValue
        }
    }

    private var storage: Storage

    private init(failureMode: OCSPFailureMode, requester: Requester, expiryValidationTime: Date?) {
        self.storage = .init(
            failureMode: failureMode,
            requester: requester,
            requestHashAlgorithm: .insecureSha1,
            maxDuration: 10,
            fixedValidationTime: expiryValidationTime
        )
    }

    @available(
        *,
        deprecated,
        message:
            "Use init(failureMode:requester:) to validated expiry against the current time. Otherwise, to validate against a fixed time, import with @_spi(FixedExpiryValidationTime) and use init(failureMode:requester:fixedExpiryValidationTime:)."
    )
    public init(failureMode: OCSPFailureMode, requester: Requester, validationTime: Date) {
        self.init(failureMode: failureMode, requester: requester, expiryValidationTime: validationTime)
    }

    /// Creates an instance with an optional *fixed* validation time.
    ///
    /// - Parameter failureMode: The mode ``OCSPVerifierPolicy`` should use to determine failure.
    /// - Parameter requester: A requester instance conforming to ``OCSPRequester``.
    /// - Parameter fixedValidationTime: The *fixed* time to compare against when determining if the request is recent. A fixed time is a *specific*
    ///   time, either in the past or future, but **not** the current time. To compare against the current time *at the point of validation*, pass `nil` to
    ///   `fixedValidationTime`.
    ///
    /// - Important: Pass `nil` to `fixedValidationTime` for the current time to be obtained at the time of validation and then used for the
    ///   comparison; the validation method may be invoked long after initialization.
    @available(
        *,
        deprecated,
        message:
            "Use init(failureMode:requester:) to validated expiry against the current time. Otherwise, to validate against a fixed time, import with @_spi(FixedExpiryValidationTime) and use init(failureMode:requester:fixedExpiryValidationTime:)."
    )
    public init(failureMode: OCSPFailureMode, requester: Requester, fixedValidationTime: Date? = nil) {
        self.init(failureMode: failureMode, requester: requester, expiryValidationTime: fixedValidationTime)
    }

    /// - Parameter failureMode: The mode ``OCSPVerifierPolicy`` should use to determine failure.
    /// - Parameter requester: A requester instance conforming to ``OCSPRequester``.
    ///
    /// - Note: Certificate expiry is validated against the *current* time (evaluated at the point of validation)
    public init(failureMode: OCSPFailureMode, requester: Requester) {
        self.init(failureMode: failureMode, requester: requester, expiryValidationTime: nil)
    }

    /// Creates an instance with a **fixed** time to validate certificate expiry against (a predetermined time *either*
    /// in the past or future)
    ///
    /// - Parameter failureMode: The mode ``OCSPVerifierPolicy`` should use to determine failure.
    /// - Parameter requester: A requester instance conforming to ``OCSPRequester``.
    /// - Parameter fixedExpiryValidationTime: The *fixed* time to compare against when determining if the certificates
    ///   in the chain have expired. A fixed time is a predetermined time, either in the past or future, but **not** the
    ///   current time. To compare against the current time *at the point of validation*, use
    ///   ``init(failureMode:requester:)``.
    ///
    /// - Warning: Only use this initializer if you want to validate the certificates against a *fixed* time. Most users
    ///   should use ``init()``: the expiry of the certificates will be validated against the current time (evaluated at
    ///   the point of validation) when using that initializer.
    @_spi(FixedExpiryValidationTime)
    public init(failureMode: OCSPFailureMode, requester: Requester, fixedExpiryValidationTime: Date) {
        self.init(failureMode: failureMode, requester: requester, expiryValidationTime: fixedExpiryValidationTime)
    }

    // this method currently doesn't need to be mutating. However, we want to reserve the right to change our mind
    // in the future and therefore still declare this method as mutating in the public API.
    public mutating func chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain) async -> PolicyEvaluationResult
    {
        await self.storage.chainMeetsPolicyWithDeadline(chain: chain)
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension OCSPVerifierPolicy.Storage {

    /// Returns `.meetsPolicy` if the `failureMode` is set to `.soft`.
    /// If it is set to `.hard` it will return `.failsToMeetPolicy` with the given `reason`.
    private func softFailure(reason: PolicyFailureReason) -> PolicyEvaluationResult {
        switch self.failureMode.storage {
        case .soft:
            return .meetsPolicy
        case .hard:
            return .failsToMeetPolicy(reason: reason)
        }
    }

    fileprivate func chainMeetsPolicyWithDeadline(chain: UnverifiedCertificateChain) async -> PolicyEvaluationResult {
        await withTimeout(maxDuration) {
            await self.chainMeetsPolicyRequirementsWithoutDeadline(chain: chain)
        }
    }

    private func chainMeetsPolicyRequirementsWithoutDeadline(
        chain: UnverifiedCertificateChain
    ) async -> PolicyEvaluationResult {
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
            let hasRootCertificateOCSPURI =
                try chain.last?.extensions.authorityInformationAccess?.contains { $0.method == .ocspServer } ?? false
            if hasRootCertificateOCSPURI {
                return .failsToMeetPolicy(reason: "root certificate is not allowed to have an OCSP URI")
            }
        } catch {
            return .failsToMeetPolicy(reason: "failed to parse AuthorityInformationAccess extension")
        }
        return .meetsPolicy
    }

    private func certificateMeetsPolicyRequirements(
        _ certificate: Certificate,
        issuer: Certificate
    ) async -> PolicyEvaluationResult {

        let authorityInformationAccess: AuthorityInformationAccess?
        do {
            authorityInformationAccess = try certificate.extensions.authorityInformationAccess
        } catch {
            return self.softFailure(reason: .init("failed to decode AuthorityInformationAccess \(error)"))
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
            let ocspAccessDescriptions = Array(ocspAccessDescriptions)
            return self.softFailure(
                reason: .init("expected OCSP location to be a URI but got \(ocspAccessDescriptions)")
            )
        }

        let certID: OCSPCertID
        do {
            certID = try OCSPCertID(hashAlgorithm: requestHashAlgorithm, certificate: certificate, issuer: issuer)
        } catch {
            return self.softFailure(reason: .init("failed to create OCSPCertID \(error)"))
        }

        return await self.queryAndVerifyCertificateStatus(for: certID, responderURI: responderURI, issuer: issuer)
    }

    private func queryAndVerifyCertificateStatus(
        for certID: OCSPCertID,
        responderURI: String,
        issuer: Certificate
    ) async -> PolicyEvaluationResult {
        let requestNonce = nonceExtensionEnabled ? OCSPNonce() : nil
        let requestBytes: [UInt8]
        do {
            let request = try OCSPRequest(certID: certID, nonce: requestNonce)
            var serializer = DER.Serializer()
            try serializer.serialize(request)
            requestBytes = serializer.serializedBytes
        } catch {
            return self.softFailure(reason: .init("failed to create OCSPRequest \(error)"))
        }

        let responseDerEncoded: [UInt8]
        switch await self.requester.query(request: requestBytes, uri: responderURI).storage {
        case .success(let responseBytes):
            responseDerEncoded = responseBytes
        case .nonTerminal:
            // TODO: "log" error
            return .meetsPolicy
        case .terminal(let error):
            return .failsToMeetPolicy(reason: String(describing: error))
        }

        let response: OCSPResponse
        do {
            response = try OCSPResponse(derEncoded: responseDerEncoded[...])
        } catch {
            return self.softFailure(reason: .init("OCSP deserialisation failed \(error)"))
        }

        return await self.verifyResponse(response, requestedCertID: certID, requestNonce: requestNonce, issuer: issuer)
    }

    private func verifyResponse(
        _ response: OCSPResponse,
        requestedCertID: OCSPCertID,
        requestNonce: OCSPNonce?,
        issuer: Certificate
    ) async -> PolicyEvaluationResult {
        switch response {
        case .unauthorized, .tryLater, .sigRequired, .malformedRequest, .internalError:
            return self.softFailure(reason: .init("OCSP request failed \(OCSPResponseStatus(response))"))
        case .successful(let basicResponse):
            return await self.verifySuccessfulResponse(
                basicResponse,
                requestedCertID: requestedCertID,
                requestNonce: requestNonce,
                issuer: issuer
            )
        }
    }

    private func verifySuccessfulResponse(
        _ basicResponse: BasicOCSPResponse,
        requestedCertID: OCSPCertID,
        requestNonce: OCSPNonce?,
        issuer: Certificate
    ) async -> PolicyEvaluationResult {
        guard let response = basicResponse.responseData.responses.first(where: { $0.certID == requestedCertID }) else {
            return self.softFailure(
                reason: .init(
                    "OCSP response does not include a response for the queried certificate \(requestedCertID) - responses: \(basicResponse.responseData.responses)"
                )
            )
        }

        switch await self.validateResponseSignature(basicResponse, issuer: issuer) {
        case .meetsPolicy:
            break
        case .failsToMeetPolicy(let reason):
            return self.softFailure(reason: reason)
        }

        guard basicResponse.responseData.version == .v1 else {
            return self.softFailure(
                reason: .init("OCSP response version unsupported \(basicResponse.responseData.version)")
            )
        }

        switch basicResponse.responseData.verifyTime(fixedValidationTime: self.fixedValidationTime) {
        case .failsToMeetPolicy(reason: let reason):
            return self.softFailure(reason: reason)
        case .meetsPolicy:
            break
        }

        do {
            // if requestNonce is nil, `nonceExtensionEnabled` is set to false and we therefore skip nonce verification
            if let requestNonce {
                // OCSP responders are allowed to not include the nonce, but if they do it needs to match
                if let responseNonce = try basicResponse.responseData.responseExtensions?.ocspNonce,
                    requestNonce != responseNonce
                {
                    return self.softFailure(reason: .init("OCSP response nonce does not match request nonce"))
                }
            } else {
                precondition(nonceExtensionEnabled == false)
            }
        } catch {
            return self.softFailure(reason: .init("failed to decode nonce response \(error)"))
        }

        switch response.verifyTime(fixedValidationTime: self.fixedValidationTime) {
        case .meetsPolicy:
            break
        case .failsToMeetPolicy(let reason):
            return self.softFailure(reason: reason)
        }

        switch response.certStatus {
        case .revoked(let info):
            return .failsToMeetPolicy(
                reason: "revoked through OCSP, reason: \(info.revocationReason?.description ?? "nil")"
            )
        case .unknown:
            return self.softFailure(reason: .init("OCSP response returned as status unknown"))
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
            rootCertificates: CertificateStore([issuer])
        ) {
            OCSPResponderSigningPolicy(issuer: issuer)
            if let fixedValidationTime = self.fixedValidationTime {
                RFC5280Policy(fixedExpiryValidationTime: fixedValidationTime)
            } else {
                RFC5280Policy()
            }
        }

        let validationResult = await verifier.validate(
            leaf: leafCertificate,
            intermediates: CertificateStore()
        )

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
            signature = try Certificate.Signature(
                signatureAlgorithm: signatureAlgorithm,
                signatureBytes: .init(bytes: signatureBytes)
            )
        } catch {
            return .failsToMeetPolicy(reason: "could not create signature for OCSP response \(error)")
        }

        guard
            certificate.publicKey.isValidSignature(signature, for: tbsResponse, signatureAlgorithm: signatureAlgorithm)
        else {
            return .failsToMeetPolicy(reason: "OCSP response signature is not valid")
        }
        return .meetsPolicy
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
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

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension OCSPRequest {
    init(certID: OCSPCertID, nonce: OCSPNonce?) throws {
        self.init(
            tbsRequest: OCSPTBSRequest(
                version: .v1,
                requestList: [
                    OCSPSingleRequest(certID: certID)
                ],
                requestExtensions: try .init(builder: {
                    if let nonce {
                        nonce
                    }
                })
            )
        )
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension OCSPResponseData {
    /// 1 hour to address time zone bugs and 15 min for clock skew of the responder/requester
    static let defaultTrustTimeLeeway: TimeInterval = 4500.0

    func verifyTime(
        fixedValidationTime: Date? = nil,
        trustTimeLeeway: TimeInterval = Self.defaultTrustTimeLeeway
    ) -> PolicyEvaluationResult {
        let producedAt = Date(self.producedAt)
        // Obtain the current time if fixedValidationTime is nil.
        let validationTime = fixedValidationTime ?? Date()

        guard producedAt <= validationTime.advanced(by: trustTimeLeeway) else {
            return .failsToMeetPolicy(
                reason:
                    "OCSP response `producedAt` (\(self.producedAt) is in the future (+\(trustTimeLeeway) seconds leeway) but should be in the past"
            )
        }

        return .meetsPolicy
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension OCSPSingleResponse {

    func verifyTime(
        fixedValidationTime: Date? = nil,
        trustTimeLeeway: TimeInterval = OCSPResponseData.defaultTrustTimeLeeway
    ) -> PolicyEvaluationResult {
        /// Clients MUST check for the existence of the nextUpdate field and MUST
        /// ensure the current time, expressed in GMT time as described in
        /// Section 2.2.4, falls between the thisUpdate and nextUpdate times.
        /// If the nextUpdate field is absent, the client MUST reject the response.
        /// https://www.rfc-editor.org/rfc/rfc5019#section-4
        guard let nextUpdateGeneralizedTime = self.nextUpdate else {
            return .failsToMeetPolicy(reason: "OCSP response `nextUpdate` is nil")
        }

        let thisUpdate = Date(self.thisUpdate)
        let nextUpdate = Date(nextUpdateGeneralizedTime)
        // Obtain the current time if fixedValidationTime is nil.
        let validationTime = fixedValidationTime ?? Date()

        guard thisUpdate <= validationTime.advanced(by: trustTimeLeeway) else {
            return .failsToMeetPolicy(
                reason:
                    "OCSP response `thisUpdate` (\(self.thisUpdate) is in the future (+\(trustTimeLeeway) seconds leeway) but should be in the past"
            )
        }

        guard nextUpdate >= validationTime.advanced(by: -trustTimeLeeway) else {
            return .failsToMeetPolicy(
                reason:
                    "OCSP response `nextUpdate` (\(nextUpdateGeneralizedTime) is in the past (-\(trustTimeLeeway) seconds leeway) but should be in the future"
            )
        }

        return .meetsPolicy
    }
}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate {
    fileprivate func matches(_ responderID: ResponderID) -> Bool {
        switch responderID {
        case .byName(let subject):
            return self.subject == subject
        case .byKey(let responderPublicKeyHash):
            let publicKeyHash = Insecure.SHA1.hash(data: self.publicKey.subjectPublicKeyInfoBytes)
            return publicKeyHash == responderPublicKeyHash.bytes
        }
    }
}

/// Executes the given `operation` up to `maxDuration` seconds and cancels it if it exceeds the timeout.
/// - Parameters:
///   - maxDuration: max execution duration in seconds of `operation`
///   - operation: the task to start and cancel after `maxDuration` seconds
/// - Returns: the result of `operation`
@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
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
