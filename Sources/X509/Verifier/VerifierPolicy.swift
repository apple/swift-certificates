public protocol VerifierPolicy {
    mutating func chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain) async -> PolicyEvaluationResult
}

public enum PolicyEvaluationResult {
    case meetsPolicy
    case failsToMeetPolicy(reason: String)
}

// TODO: Several enhancements.
//
// This type should properly be a variadic generic over `VerifierPolicy` to allow proper composition.
// Additionally, we should add conditional Sendable, Equatable, and Hashable conformances as needed.
// This will also allow equivalent conditional conformances on `Verifier`.
public struct PolicySet: VerifierPolicy {
    @usableFromInline var policies: [any VerifierPolicy]

    @inlinable
    public init(policies: [any VerifierPolicy]) {
        self.policies = policies
    }

    public mutating func chainMeetsPolicyRequirements(chain: UnverifiedCertificateChain) async -> PolicyEvaluationResult {
        var policyIndex = self.policies.startIndex

        while policyIndex < self.policies.endIndex {
            switch await self.policies[policyIndex].chainMeetsPolicyRequirements(chain: chain) {
            case .meetsPolicy:
                ()
            case .failsToMeetPolicy(reason: let reason):
                return .failsToMeetPolicy(reason: reason)
            }

            self.policies.formIndex(after: &policyIndex)
        }

        return .meetsPolicy
    }
}

