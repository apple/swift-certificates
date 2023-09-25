//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCertificates open source project
//
// Copyright (c) 2023 Apple Inc. and the SwiftCertificates project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCertificates project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import Benchmark
import X509
import SwiftASN1
import Foundation

public func parseWebPKIRootsFromDER() -> () -> Void {
    let derEncodedCAs = try! loadWebPKIAsPemStrings().map { try! PEMDocument(pemString: $0).derBytes }
    return {
        for derEncodedCA in derEncodedCAs {
            blackHole(try! Certificate(derEncoded: derEncodedCA).extensions.count)
        }
    }
}

public func parseWebPKIRootsFromPEMFiles() -> () -> Void {
    let pemEncodedCAs = try! loadWebPKIAsPemStrings()
    return {
        for pemEncodedCertificate in pemEncodedCAs {
            blackHole(try! Certificate(pemEncoded: pemEncodedCertificate).extensions.count)
        }
    }
}

public func parseWebPKIRootsFromMultiPEMFile() -> () -> Void {
    let pemEncodedCAs = try! loadWebPKIAsSingleMuliPEMString()
    return {
        for pemDocument in try! PEMDocument.parseMultiple(pemString: pemEncodedCAs) {
            blackHole(try! Certificate(pemDocument: pemDocument).extensions.count)
        }
    }
}
