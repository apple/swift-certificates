//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftASN1 open source project
//
// Copyright (c) 2020 Apple Inc. and the SwiftASN1 project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftASN1 project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

/// Represents an error that may be thrown from the ``SwiftASN1`` module.
///
/// This object contains both an error ``code`` and a textual reason for the error,
/// as well as source code context for the error. When attempting to process a specific
/// error, users are encouraged to check the ``code``. The additional diagnostic information
/// is available by using `String(describing:)` to format ``ASN1Error``.
///
/// This type is `Equatable` and `Hashable`, but only the ``code`` field is considered in the
/// implementation of that behaviour. This makes it relatively easy to test code that throws
/// a specific error by creating the error type directly in your own code.
public struct ASN1Error: Error, Hashable, CustomStringConvertible {
    private let backing: Backing

    /// Represents the kind of error that was encountered.
    public var code: ErrorCode {
        self.backing.code
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
        "ASN1Error.\(self.code): \(self.reason) \(self.file):\(self.line)"
    }

    /// The ASN.1 tag for the parsed field does not match the tag expected for the field.
    @inline(never)
    public static func unexpectedFieldType(
        _ identifier: ASN1Identifier, file: String = #fileID, line: UInt = #line
    ) -> ASN1Error {
        return ASN1Error(
            backing: .init(
                code: .unexpectedFieldType, reason: "\(identifier)", file: file, line: line
            )
        )
    }

    /// The format of the parsed ASN.1 object does not match the format required for the data type
    /// being decoded.
    @inline(never)
    public static func invalidASN1Object(
        reason: String, file: String = #fileID, line: UInt = #line
    ) -> ASN1Error {
        return ASN1Error(
            backing: .init(
                code: .invalidASN1Object, reason: reason, file: file, line: line
            )
        )
    }

    /// An ASN.1 integer was decoded that does not use the minimum number of bytes for its encoding.
    @inline(never)
    public static func invalidASN1IntegerEncoding(
        reason: String, file: String = #fileID, line: UInt = #line
    ) -> ASN1Error {
        return ASN1Error(
            backing: .init(
                code: .invalidASN1IntegerEncoding, reason: reason, file: file, line: line
            )
        )
    }

    /// An ASN.1 field was truncated and could not be decoded.
    @inline(never)
    public static func truncatedASN1Field(
        file: String = #fileID, line: UInt = #line
    ) -> ASN1Error {
        return ASN1Error(
            backing: .init(
                code: .truncatedASN1Field, reason: "", file: file, line: line
            )
        )
    }

    /// The encoding used for the field length is not supported.
    @inline(never)
    public static func unsupportedFieldLength(
        reason: String, file: String = #fileID, line: UInt = #line
    ) -> ASN1Error {
        return ASN1Error(
            backing: .init(
                code: .unsupportedFieldLength, reason: reason, file: file, line: line
            )
        )
    }

    /// It was not possible to parse a string as a PEM document.
    @inline(never)
    public static func invalidPEMDocument(
        reason: String, file: String = #fileID, line: UInt = #line
    ) -> ASN1Error {
        return ASN1Error(
            backing: .init(
                code: .invalidPEMDocument, reason: reason, file: file, line: line
            )
        )
    }

    /// A string was invalid.
    @inline(never)
    public static func invalidStringRepresentation(
        reason: String, file: String = #fileID, line: UInt = #line
    ) -> ASN1Error {
        return ASN1Error(
            backing: .init(
                code: .invalidStringRepresentation, reason: reason, file: file, line: line
            )
        )
    }
}

extension ASN1Error {
    /// Represents the kind of an error.
    ///
    /// The same kind of error may be thrown from more than one place, for more than one reason. This type represents
    /// only a fairly high level kind of error: use the string representation of ``ASN1Error`` to get more details
    /// about the specific cause.
    public struct ErrorCode: Hashable, Sendable, CustomStringConvertible {
        fileprivate enum BackingCode {
            case unexpectedFieldType
            case invalidASN1Object
            case invalidASN1IntegerEncoding
            case truncatedASN1Field
            case unsupportedFieldLength
            case invalidPEMDocument
            case invalidStringRepresentation
        }

        fileprivate var backingCode: BackingCode

        fileprivate init(_ backingCode: BackingCode) {
            self.backingCode = backingCode
        }

        /// The ASN.1 tag for the parsed field does not match the tag expected for the field.
        public static let unexpectedFieldType = ErrorCode(.unexpectedFieldType)

        /// The format of the parsed ASN.1 object does not match the format required for the data type
        /// being decoded.
        public static let invalidASN1Object = ErrorCode(.invalidASN1Object)

        /// An ASN.1 integer was decoded that does not use the minimum number of bytes for its encoding.
        public static let invalidASN1IntegerEncoding = ErrorCode(.invalidASN1IntegerEncoding)

        /// An ASN.1 field was truncated and could not be decoded.
        public static let truncatedASN1Field = ErrorCode(.truncatedASN1Field)

        /// The encoding used for the field length is not supported.
        public static let unsupportedFieldLength = ErrorCode(.unsupportedFieldLength)

        /// It was not possible to parse a string as a PEM document.
        public static let invalidPEMDocument = ErrorCode(.invalidPEMDocument)

        /// A string was invalid.
        public static let invalidStringRepresentation = ErrorCode(.invalidStringRepresentation)

        public var description: String {
            return String(describing: self.backingCode)
        }
    }
}

extension ASN1Error {
    final class Backing: Hashable, Sendable {
        let code: ASN1Error.ErrorCode

        let reason: String

        let file: String

        let line: UInt

        fileprivate init(
            code: ASN1Error.ErrorCode,
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
        static func ==(lhs: Backing, rhs: Backing) -> Bool {
            return lhs.code == rhs.code
        }

        func hash(into hasher: inout Hasher) {
            hasher.combine(self.code)
        }
    }
}

