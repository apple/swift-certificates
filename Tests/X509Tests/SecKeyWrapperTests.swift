//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCertificates open source project
//
// Copyright (c) 2024 Apple Inc. and the SwiftCertificates project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCertificates project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import XCTest
@_spi(Testing) @testable import X509

#if canImport(Darwin)
final class SecKeyWrapperTests: XCTestCase {
    struct CandidateKey {
        let key: SecKey
        let type: String
        let keySize: Int
        let sep: Bool
    }
    
    func generateCandidateKeys() throws -> [CandidateKey] {
        var keys : [CandidateKey] = []
        
        // RSA
        keys.append(CandidateKey(key: try SignatureTests.generateSecKey(keyType: kSecAttrKeyTypeRSA, keySize: 2048, useSEP: false), type: "RSA", keySize: 2048, sep: false))
        
        // eliptic curves
        for keyType in [kSecAttrKeyTypeECSECPrimeRandom, kSecAttrKeyTypeEC, kSecAttrKeyTypeECDSA] {
            for keySize in [256, 384] {
                for useSEP in [true, false] {
                    keys.append(CandidateKey(key: try SignatureTests.generateSecKey(keyType: keyType, keySize: keySize, useSEP: useSEP), type: "EC-\(keyType)", keySize: keySize, sep: useSEP))
                }
            }
        }
        return keys
    }
    
    func testPEMExport() throws {
        for candidate in try generateCandidateKeys() {
            try XCTContext.runActivity(named: "Testing \(candidate.type) key (size: \(candidate.keySize))") { _ in
                let secKeyWrapper = try Certificate.PrivateKey.SecKeyWrapper(key: candidate.key)
                
                if !candidate.sep {
                    let pemString = try secKeyWrapper.pemDocument()
                    XCTAssertNotNil(pemString)
                } else {
                    XCTAssertThrowsError(try secKeyWrapper.pemDocument())
                }
            }
        }
    }
}
#endif
