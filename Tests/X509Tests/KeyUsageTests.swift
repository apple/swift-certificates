//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCertificates open source project
//
// Copyright (c) 2026 Apple Inc. and the SwiftCertificates project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCertificates project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Testing
import X509

@Suite
struct KeyUsageTests {
    @Test("Empty KeyUsage is encoded as an empty BIT STRING")
    func testEmptyKeyUsageEncoding() throws {
        let ext = try Certificate.Extension(KeyUsage(), critical: true)
        #expect(Array(ext.value) == [0x03, 0x01, 0x00])
        #expect(try KeyUsage(ext) == KeyUsage())
    }

    @Test(
        "KeyUsage round-trips through its DER encoding",
        arguments: [
            (KeyUsage(), [UInt8]([0x03, 0x01, 0x00])),
            (KeyUsage(digitalSignature: true), [0x03, 0x02, 0x07, 0x80]),
            (KeyUsage(keyCertSign: true, cRLSign: true), [0x03, 0x02, 0x01, 0x06]),
            (KeyUsage(decipherOnly: true), [0x03, 0x03, 0x07, 0x00, 0x80]),
        ]
    )
    func testKeyUsageRoundTrip(keyUsage: KeyUsage, expectedDER: [UInt8]) throws {
        let ext = try Certificate.Extension(keyUsage, critical: false)
        #expect(Array(ext.value) == expectedDER)
        #expect(try KeyUsage(ext) == keyUsage)
    }
}
