import Foundation

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate {

    public protocol Signer: Sendable {

        /// Use the signer to sign the provided bytes with a given signature algorithm.
        ///
        /// - Parameters:
        ///   - bytes: The data to create the signature for.
        ///   - signatureAlgorithm: The signature algorithm to use.
        /// - Returns: The signature.
        @inlinable
        func sign(
            bytes: some DataProtocol,
            signatureAlgorithm: SignatureAlgorithm
        ) throws -> Signature

    }

}

@available(macOS 10.15, iOS 13, watchOS 6, tvOS 13, macCatalyst 13, visionOS 1.0, *)
extension Certificate {

    public protocol AsyncSigner: Sendable {

        /// Use the signer to sign the provided bytes with a given signature algorithm.
        ///
        /// - Parameters:
        ///   - bytes: The data to create the signature for.
        ///   - signatureAlgorithm: The signature algorithm to use.
        /// - Returns: The signature.
        @inlinable
        func sign(
            bytes: some DataProtocol,
            signatureAlgorithm: SignatureAlgorithm
        ) async throws -> Signature

    }

}
