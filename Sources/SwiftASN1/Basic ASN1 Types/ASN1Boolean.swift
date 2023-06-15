//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftASN1 open source project
//
// Copyright (c) 2021 Apple Inc. and the SwiftASN1 project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftASN1 project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

extension Bool: DERImplicitlyTaggable {
    @inlinable
    public static var defaultIdentifier: ASN1Identifier {
        .boolean
    }

    @inlinable
    public init(derEncoded node: ASN1Node, withIdentifier identifier: ASN1Identifier) throws {
        guard node.identifier == identifier else {
            throw ASN1Error.unexpectedFieldType(node.identifier)
        }

        guard case .primitive(let bytes) = node.content, bytes.count == 1 else {
            throw ASN1Error.invalidASN1Object(reason: "Invalid content for ASN1Bool")
        }

        switch bytes[bytes.startIndex] {
        case 0:
            // Boolean false
            self = false
        case 0xff:
            // Boolean true in DER
            self = true
        case let byte:
            // If we come to support BER then these values are all "true" as well.
            throw ASN1Error.invalidASN1Object(reason: "Invalid byte for ASN1Bool: \(byte)")
        }
    }

    @inlinable
    public func serialize(into coder: inout DER.Serializer, withIdentifier identifier: ASN1Identifier) throws {
        coder.appendPrimitiveNode(identifier: identifier) { bytes in
            if self {
                bytes.append(0xff)
            } else {
                bytes.append(0)
            }
        }
    }
}
