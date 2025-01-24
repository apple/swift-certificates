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

/// Represents an error that may be thrown from the ``Certificate`` module.
///
/// This object contains both an error ``code`` and a textual reason for the error,
/// as well as source code context for the error. When attempting to process a specific
/// error, users are encouraged to check the ``code``. The additional diagnostic information
/// is available by using `String(describing:)` to format ``CertificateError``.
///
/// This type is `Equatable` and `Hashable`, but only the ``code`` field is considered in the
/// implementation of that behaviour. This makes it relatively easy to test code that throws
/// a specific error by creating the error type directly in your own code.
public struct CertificateError: Error, Hashable, CustomStringConvertible {
    private var backing: Backing

    /// Represents the kind of error that was encountered.
    public var code: ErrorCode {
        get {
            self.backing.code
        }
        set {
            self.makeUnique()
            self.backing.code = newValue
        }
    }

    private var reason: String {
        self.backing.reason
    }

    private var file: String {
        self.backing.file
    }

    private var line: UInt {
        self.backing.line
    }

    public var description: String {
        "CertificateError.\(self.code): \(self.reason) \(self.file):\(self.line)"
    }

    private mutating func makeUnique() {
        if !isKnownUniquelyReferenced(&self.backing) {
            self.backing = self.backing.copy()
        }
    }

    /// The signature algorithm used in a ``Certificate`` is not supported by this library.
    /// - Parameter reason: A detailed reason explaining what signature algorithm was not supported.
    /// - Parameter file: The file where the error occurs.
    /// - Parameter line: The line where the error occurs.
    /// - Returns: A ``CertificateError`` with ``code`` set to ``ErrorCode/unsupportedSignatureAlgorithm``.
    @inline(never)
    public static func unsupportedSignatureAlgorithm(
        reason: String,
        file: String = #fileID,
        line: UInt = #line
    ) -> CertificateError {
        return CertificateError(
            backing: .init(
                code: .unsupportedSignatureAlgorithm,
                reason: reason,
                file: file,
                line: line
            )
        )
    }

    /// The private key algorithm used in a ``Certificate`` is not supported by this library.
    /// - Parameter reason: A detailed reason explaining what private key algorithm was not supported.
    /// - Parameter file: The file where the error occurs.
    /// - Parameter line: The line where the error occurs.
    /// - Returns: A ``CertificateError`` with ``code`` set to ``ErrorCode/unsupportedPublicKeyAlgorithm``.
    @inline(never)
    public static func unsupportedPublicKeyAlgorithm(
        reason: String,
        file: String = #fileID,
        line: UInt = #line
    ) -> CertificateError {
        return CertificateError(
            backing: .init(
                code: .unsupportedPublicKeyAlgorithm,
                reason: reason,
                file: file,
                line: line
            )
        )
    }

    /// The signature was not valid for the provided ``Certificate``.
    /// - Parameter reason: A detailed reason detailing the signature and certificate that did not match.
    /// - Parameter file: The file where the error occurs.
    /// - Parameter line: The line where the error occurs.
    /// - Returns: A ``CertificateError`` with ``code`` set to ``ErrorCode/invalidSignatureForCertificate``.
    @inline(never)
    public static func invalidSignatureForCertificate(
        reason: String,
        file: String = #fileID,
        line: UInt = #line
    ) -> CertificateError {
        return CertificateError(
            backing: .init(
                code: .invalidSignatureForCertificate,
                reason: reason,
                file: file,
                line: line
            )
        )
    }

    /// An extension has the wrong OID.
    /// - Parameter reason: A detailed reason detailing the extension and OID that didn't match.
    /// - Parameter file: The file where the error occurs.
    /// - Parameter line: The line where the error occurs.
    /// - Returns: A ``CertificateError`` with ``code`` set to ``ErrorCode/incorrectOIDForExtension``.
    @inline(never)
    public static func incorrectOIDForExtension(
        reason: String,
        file: String = #fileID,
        line: UInt = #line
    ) -> CertificateError {
        return CertificateError(
            backing: .init(
                code: .incorrectOIDForExtension,
                reason: reason,
                file: file,
                line: line
            )
        )
    }

    /// A digest algorithm isn't supported
    /// - Parameter reason: A detailed reason indicating the algorithm identifier for the unsupported digest.
    /// - Parameter file: The file where the error occurs.
    /// - Parameter line: The line where the error occurs.
    /// - Returns: A ``CertificateError`` with ``code`` set to ``ErrorCode/unsupportedDigestAlgorithm``.
    @inline(never)
    public static func unsupportedDigestAlgorithm(
        reason: String,
        file: String = #fileID,
        line: UInt = #line
    ) -> CertificateError {
        return CertificateError(
            backing: .init(
                code: .unsupportedDigestAlgorithm,
                reason: reason,
                file: file,
                line: line
            )
        )
    }

    /// A digest private key isn't supported
    /// - Parameter reason: A detailed reason indicating the unsupported private key.
    /// - Parameter file: The file where the error occurs.
    /// - Parameter line: The line where the error occurs.
    /// - Returns: A ``CertificateError`` with ``code`` set to ``ErrorCode/unsupportedPrivateKey``.
    @inline(never)
    public static func unsupportedPrivateKey(
        reason: String,
        file: String = #fileID,
        line: UInt = #line
    ) -> CertificateError {
        return CertificateError(
            backing: .init(
                code: .unsupportedPrivateKey,
                reason: reason,
                file: file,
                line: line
            )
        )
    }

    /// A CSR attribute has the wrong OID.
    /// - Parameter reason: A detailed reason detailing the attribute and OID that didn't match.
    /// - Parameter file: The file where the error occurs.
    /// - Parameter line: The line where the error occurs.
    /// - Returns: A ``CertificateError`` with ``code`` set to ``ErrorCode/incorrectOIDForAttribute``.
    @inline(never)
    public static func incorrectOIDForAttribute(
        reason: String,
        file: String = #fileID,
        line: UInt = #line
    ) -> CertificateError {
        return CertificateError(
            backing: .init(
                code: .incorrectOIDForAttribute,
                reason: reason,
                file: file,
                line: line
            )
        )
    }

    /// A CSR attribute is invalid.
    /// - Parameter reason: A detailed reason detailing the attribute that is invalid.
    /// - Parameter file: The file where the error occurs.
    /// - Parameter line: The line where the error occurs.
    /// - Returns: A ``CertificateError`` with ``code`` set to ``ErrorCode/invalidCSRAttribute``.
    @inline(never)
    public static func invalidCSRAttribute(
        reason: String,
        file: String = #fileID,
        line: UInt = #line
    ) -> CertificateError {
        return CertificateError(
            backing: .init(
                code: .invalidCSRAttribute,
                reason: reason,
                file: file,
                line: line
            )
        )
    }

    /// An OID is present twice.
    /// - Parameter reason: A detailed reason detailing which OID is duplicate.
    /// - Parameter file: The file where the error occurs.
    /// - Parameter line: The line where the error occurs.
    /// - Returns: A ``CertificateError`` with ``code`` set to ``ErrorCode/duplicateOID``.
    @inline(never)
    public static func duplicateOID(
        reason: String,
        file: String = #fileID,
        line: UInt = #line
    ) -> CertificateError {
        return CertificateError(
            backing: .init(
                code: .duplicateOID,
                reason: reason,
                file: file,
                line: line
            )
        )
    }

    /// The system trust store could not be found or failed to load from disk.
    /// - Parameter reason: A detailed reason included which locations were tried and which error got thrown.
    /// - Parameter file: The file where the error occurs.
    /// - Parameter line: The line where the error occurs.
    /// - Returns: A ``CertificateError`` with ``code`` set to ``ErrorCode/failedToLoadSystemTrustStore``.
    @inline(never)
    public static func failedToLoadSystemTrustStore(
        reason: String,
        file: String = #fileID,
        line: UInt = #line
    ) -> CertificateError {
        return CertificateError(
            backing: .init(
                code: .failedToLoadSystemTrustStore,
                reason: reason,
                file: file,
                line: line
            )
        )
    }
}

// `CertificateError` is `Sendable` because it uses CoW
extension CertificateError: @unchecked Sendable {}

extension CertificateError {
    /// Represents the kind of an error.
    ///
    /// The same kind of error may be thrown from more than one place, for more than one reason. This type represents
    /// only a fairly high level kind of error: use the string representation of ``CertificateError`` to get more details
    /// about the specific cause.
    public struct ErrorCode: Hashable, Sendable, CustomStringConvertible {
        fileprivate enum BackingCode {
            case unsupportedSignatureAlgorithm
            case unsupportedPublicKeyAlgorithm
            case invalidSignatureForCertificate
            case incorrectOIDForExtension
            case unsupportedDigestAlgorithm
            case unsupportedPrivateKey
            case incorrectOIDForAttribute
            case invalidCSRAttribute
            case duplicateOID
            case failedToLoadSystemTrustStore
        }

        fileprivate var backingCode: BackingCode

        fileprivate init(_ backingCode: BackingCode) {
            self.backingCode = backingCode
        }

        /// The signature algorithm used in a ``Certificate`` is not supported by this library.
        public static let unsupportedSignatureAlgorithm = ErrorCode(.unsupportedSignatureAlgorithm)

        /// The public key algorithm used in a ``Certificate`` is not supported by this library.
        public static let unsupportedPublicKeyAlgorithm = ErrorCode(.unsupportedPublicKeyAlgorithm)

        /// The signature was not valid for the provided ``Certificate``.
        public static let invalidSignatureForCertificate = ErrorCode(.invalidSignatureForCertificate)

        /// An extension has the wrong OID.
        public static let incorrectOIDForExtension = ErrorCode(.incorrectOIDForExtension)

        /// The digest algorithm isn't supported.
        public static let unsupportedDigestAlgorithm = ErrorCode(.unsupportedDigestAlgorithm)

        /// The private key isn't supported.
        public static let unsupportedPrivateKey = ErrorCode(.unsupportedPrivateKey)

        /// An attribute has the wrong OID.
        public static let incorrectOIDForAttribute = ErrorCode(.incorrectOIDForAttribute)

        /// A CSR attribute is invalid.
        public static let invalidCSRAttribute = ErrorCode(.invalidCSRAttribute)

        /// An OID is present twice.
        public static let duplicateOID = ErrorCode(.duplicateOID)

        /// The system trust store could not be located or failed to load from disk.
        public static let failedToLoadSystemTrustStore = ErrorCode(.failedToLoadSystemTrustStore)

        public var description: String {
            return String(describing: self.backingCode)
        }
    }
}

extension CertificateError {
    final class Backing: Hashable {
        var code: CertificateError.ErrorCode

        let reason: String

        let file: String

        let line: UInt

        fileprivate init(
            code: CertificateError.ErrorCode,
            reason: String,
            file: String,
            line: UInt
        ) {
            self.code = code
            self.reason = reason
            self.file = file
            self.line = line
        }

        // Only the error code matters for equality.
        static func == (lhs: Backing, rhs: Backing) -> Bool {
            return lhs.code == rhs.code
        }

        func hash(into hasher: inout Hasher) {
            hasher.combine(self.code)
        }

        fileprivate func copy() -> Backing {
            return Backing(code: self.code, reason: self.reason, file: self.file, line: self.line)
        }
    }
}
