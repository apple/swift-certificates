public struct UnverifiedCertificateChain: Sendable, Hashable {
    @usableFromInline
    var certificates: [Certificate]

    init(_ certificates: [Certificate]) {
        precondition(!certificates.isEmpty)
        self.certificates = certificates
    }

    @inlinable
    public var leaf: Certificate {
        self.certificates.first!
    }
}

extension UnverifiedCertificateChain: RandomAccessCollection {
    @inlinable
    public var startIndex: Int {
        self.certificates.startIndex
    }

    @inlinable
    public var endIndex: Int {
        self.certificates.endIndex
    }

    @inlinable
    public subscript(position: Int) -> Certificate {
        get {
            self.certificates[position]
        }
    }
}
