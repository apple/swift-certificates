/// A collection of ``Certificate`` objects for use in a verifier.
public struct CertificateStore: Sendable, Hashable {
    /// Stores the certificates, indexed by DistinguishedName.
    @usableFromInline
    var _certificates: [DistinguishedName: [Certificate]]

    @inlinable
    public init() {
        self._certificates = [:]
    }

    @inlinable
    public init<Certificates: Sequence>(_ certificates: Certificates) where Certificates.Element == Certificate {
        self._certificates = Dictionary(grouping: certificates, by: \.issuer)
    }

    @inlinable
    mutating func insert(_ certificate: Certificate) {
        self._certificates[certificate.issuer, default: []].append(certificate)
    }

    @inlinable
    mutating func insert<Certificates: Sequence>(contentsOf certificates: Certificates) where Certificates.Element == Certificate {
        for certificate in certificates {
            self.insert(certificate)
        }
    }
}
