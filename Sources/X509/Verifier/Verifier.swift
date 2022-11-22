public struct Verifier {
    public var rootCertificates: CertificateStore

    public var policy: PolicySet

    @inlinable
    public init(rootCertificates: CertificateStore, policy: PolicySet) {
        self.rootCertificates = rootCertificates
        self.policy = policy
    }

    public mutating func validate(leafCertificate: Certificate, intermediates: CertificateStore, diagnosticCallback: ((String) -> Void)? = nil) async -> VerificationResult {
        return .validCertificate
    }
}

public enum VerificationResult: Hashable, Sendable {
    case validCertificate
    case couldNotValidate([PolicyFailure])
}

extension VerificationResult {
    public struct PolicyFailure: Hashable, Sendable {
        public var chain: UnverifiedCertificateChain
        public var policyFailureReason: String

        @inlinable
        public init(chain: UnverifiedCertificateChain, policyFailureReason: String) {
            self.chain = chain
            self.policyFailureReason = policyFailureReason
        }
    }
}
