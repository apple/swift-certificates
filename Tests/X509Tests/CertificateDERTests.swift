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

import Foundation
import XCTest
import SwiftASN1
import X509
import Crypto

final class CertificateDERTests: XCTestCase {
    static let base64EncodedSampleCert = """
        MIIDsjCCAzigAwIBAgIQDKuq0c7E6XzCZliB0CE49zAKBggqhkjOPQQDAzBhMQsw
        CQYDVQQGEwJVUzEVMBMGA1UEChMMRGlnaUNlcnQgSW5jMRkwFwYDVQQLExB3d3cu
        ZGlnaWNlcnQuY29tMSAwHgYDVQQDExdEaWdpQ2VydCBHbG9iYWwgUm9vdCBHMzAe
        Fw0yMDA0MjkxMjM0NTJaFw0zMDA0MTAyMzU5NTlaMFExCzAJBgNVBAYTAlVTMRMw
        EQYDVQQKEwpBcHBsZSBJbmMuMS0wKwYDVQQDEyRBcHBsZSBQdWJsaWMgRVYgU2Vy
        dmVyIEVDQyBDQSAxIC0gRzEwWTATBgcqhkjOPQIBBggqhkjOPQMBBwNCAAQp+OFa
        uYdEBJj/FpCG+eDhQmVfhv0DGPzGz40TW8BeWxipYTOa4FLieAYoU+3t2tg9FZKt
        A4BDTO43YprLZm6zo4IB4DCCAdwwHQYDVR0OBBYEFOCFSH0TptMQGZ9cy2t4JJL4
        rhuuMB8GA1UdIwQYMBaAFLPbSKT5ocXYrjZBzBFjaWIpvEvGMA4GA1UdDwEB/wQE
        AwIBhjAdBgNVHSUEFjAUBggrBgEFBQcDAQYIKwYBBQUHAwIwEgYDVR0TAQH/BAgw
        BgEB/wIBADA0BggrBgEFBQcBAQQoMCYwJAYIKwYBBQUHMAGGGGh0dHA6Ly9vY3Nw
        LmRpZ2ljZXJ0LmNvbTBCBgNVHR8EOzA5MDegNaAzhjFodHRwOi8vY3JsMy5kaWdp
        Y2VydC5jb20vRGlnaUNlcnRHbG9iYWxSb290RzMuY3JsMIHcBgNVHSAEgdQwgdEw
        gcUGCWCGSAGG/WwCATCBtzAoBggrBgEFBQcCARYcaHR0cHM6Ly93d3cuZGlnaWNl
        cnQuY29tL0NQUzCBigYIKwYBBQUHAgIwfgx8QW55IHVzZSBvZiB0aGlzIENlcnRp
        ZmljYXRlIGNvbnN0aXR1dGVzIGFjY2VwdGFuY2Ugb2YgdGhlIFJlbHlpbmcgUGFy
        dHkgQWdyZWVtZW50IGxvY2F0ZWQgYXQgaHR0cHM6Ly93d3cuZGlnaWNlcnQuY29t
        L3JwYS11YTAHBgVngQwBATAKBggqhkjOPQQDAwNoADBlAjEAyHLAT/4iBuxi4/NH
        hZde4PZO8CnG2/A3oGO0Nsjpoe2SV94Hr+JpYHrBzT8hyeKSAjBnRXyRac9sM8KN
        Fdg3+7LWIiW9sUjtJC6kGmRyGm6vV4oAhEDd9jdk4q+7b5zlid4=
        """

    static let base64EncodedRSARootCert = """
        MIIF2DCCA8CgAwIBAgIQTKr5yttjb+Af907YWwOGnTANBgkqhkiG9w0BAQwFADCB
        hTELMAkGA1UEBhMCR0IxGzAZBgNVBAgTEkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4G
        A1UEBxMHU2FsZm9yZDEaMBgGA1UEChMRQ09NT0RPIENBIExpbWl0ZWQxKzApBgNV
        BAMTIkNPTU9ETyBSU0EgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMTAwMTE5
        MDAwMDAwWhcNMzgwMTE4MjM1OTU5WjCBhTELMAkGA1UEBhMCR0IxGzAZBgNVBAgT
        EkdyZWF0ZXIgTWFuY2hlc3RlcjEQMA4GA1UEBxMHU2FsZm9yZDEaMBgGA1UEChMR
        Q09NT0RPIENBIExpbWl0ZWQxKzApBgNVBAMTIkNPTU9ETyBSU0EgQ2VydGlmaWNh
        dGlvbiBBdXRob3JpdHkwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoICAQCR
        6FSS0gpWsawNJN3Fz0RndJkrN6N9I3AAcbxT38T6KhKPS38QVr2fcHK3YX/JSw8X
        pz3jsARh7v8Rl8f0hj4K+j5c+ZPmNHrZFGvnnLOFoIJ6dq9xkNfs/Q36nGz637CC
        9BR++b7Epi9Pf5l/tfxnQ3K9DADWietrLNPtj5gcFKt+5eNu/Nio5JIk2kNrYrhV
        /erBvGy2i/MOjZrkm2xpmfh4SDBF1a3hDTxFYPwyllEnvGfDyi62a+pGx8cgoLEf
        Zd5ICLqkTqnyg0Y3hOvozIFIQ2dOciqbXL1MGyiKXCJ7tKuY2e7gUYPDCUZObT6Z
        +pUX2nwzV0E8jVHtC7ZcryxjGt9XyD+86V3Em69FmeKjWiS0uqlWPc9vqv9JWL7w
        qP/0uK3pN/u6uPQLOvnoQ0IeidiEyxPx2bvhiWC4jChWrBQdnArncevPDt09qZah
        SL0896+1DSJMwBGB7FY79tOi4lu3sgQiUpWAk2nojkxl8ZEDLXB0AuqLZxUpaVIC
        u9ffUGpVRr+goyhhf3DQw6KqLCGqR84onAZFdr+CGCe01a60y1Dma/RMhnEw6abf
        Fobg2P9A3fvQQoh/ozM6LlweQRGBY84YcWsr7KaKtzFcOmpH4MN5WdYgGq/yapiq
        crxXStJLnbsQ/LBMQeXtHT1eKJ2czL+zUdqnR+WEUwIDAQABo0IwQDAdBgNVHQ4E
        FgQUu69+Aj36pvE8hI6t7jiY7NkyMtQwDgYDVR0PAQH/BAQDAgEGMA8GA1UdEwEB
        /wQFMAMBAf8wDQYJKoZIhvcNAQEMBQADggIBAArx1UaEt65Ru2yyTUEUAJNMnMvl
        wFTPoCWOAvn9sKIN9SCYPBMtrFaisNZ+EZLpLrqeLppysb0ZRGxhNaKatBYSaVqM
        4dc+pBroLwP0rmEdEBsqpIt6xf4FpuHA1sj+nq6PK7o9mfjYcwlYRm6mnPTXJ9OV
        2jeDchzTc+CiR5kDOF3VSXkAKRzH7JsgHAckaVd4sjn8OoSgtZx8jb8uk2Intzna
        FxiuvTwJaP+EmzzV1gsD41eeFPfR60/IvYcjt7ZJQ3mFXLrrkguhxuhoqEwWsRqZ
        CuhTLJK7oQkYdQxlqHvLI7cawiiFwxv/0Cti76R7CZGYZ4wUAc1oBmpjIXUDgIiK
        boHGhfKppC3n9KUkEEeDys30jXlYsQab5xoq2Z0B15R97QNKyvDb6KkBPvVWmcke
        jkk9u+UJueBPSZI9FoJAzMxZxuY67RIuaTxslbH9qh17f4a+Hg4yRvv7E491f0yL
        S0Zj/gA0QHDBw7mh3aZw4gSzQbzpgJHqZJx64SIDqZxubw5lT2yHh17zbqD5daWb
        QOhTsiedSrnAdyGN/4fy3ryM7xfft0kL0fJuMAsaDk527RH89elWsn2/x20Kk4yl
        0MC2Hb46TpSi125sC8KKfPog88Tk5c0NqMuRkrF8hey1FGlmDoLnzc7ILaZRfyHB
        NVOFBkpdn627G190
        """

    /// A Safari codesign chain
    static let codesignCerts = [
        """
        MIIEtDCCA5ygAwIBAgIIZO/q/sI56KUwDQYJKoZIhvcNAQEFBQAwfzELMAkGA1UE
        BhMCVVMxEzARBgNVBAoMCkFwcGxlIEluYy4xJjAkBgNVBAsMHUFwcGxlIENlcnRp
        ZmljYXRpb24gQXV0aG9yaXR5MTMwMQYDVQQDDCpBcHBsZSBDb2RlIFNpZ25pbmcg
        Q2VydGlmaWNhdGlvbiBBdXRob3JpdHkwHhcNMjAxMDI5MTgzMjM4WhcNMjYxMDI0
        MTczOTQxWjBWMQswCQYDVQQGEwJVUzETMBEGA1UECgwKQXBwbGUgSW5jLjEXMBUG
        A1UECwwOQXBwbGUgU29mdHdhcmUxGTAXBgNVBAMMEFNvZnR3YXJlIFNpZ25pbmcw
        ggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQC/MLh0mE+uBguklG4xVG0J
        0TyjsDkQqdDmqmAiXdPkhKJAQZBkxmA9kWHaUqhFJ54sZMvkHqgkClI6s9PsFkF4
        wZ7RBuZ4JWMI89/KQeYd/jXpUVwTFYvp0Z1xe9HJqkuemdqPwCm4L5BvpLtlj4Bq
        1z1obeR4wqUSL/gy6X7JXVyMPhYgG9denRuGLQj3vBmkTQ5BpErbaxqARVAEqUyN
        FQfqaie9u4iePD+yUjmX47fI61RSmIovI1Zl5ekq2VG0I/oE3ffroN/VmvJeCPFf
        h/CxR2x1sbGM0RPjesHsYkF0poM08fladGQ5P1luzyzAYIMpPOfeT18N85M5XzCN
        AgMBAAGjggFbMIIBVzAMBgNVHRMBAf8EAjAAMB8GA1UdIwQYMBaAFI5ppsR3Qk4E
        pVZCnFEfhtrSII8JMIGWBgNVHSAEgY4wgYswgYgGCSqGSIb3Y2QFATB7MHkGCCsG
        AQUFBwICMG0Ma1RoaXMgY2VydGlmaWNhdGUgaXMgdG8gYmUgdXNlZCBleGNsdXNp
        dmVseSBmb3IgZnVuY3Rpb25zIGludGVybmFsIHRvIEFwcGxlIFByb2R1Y3RzIGFu
        ZC9vciBBcHBsZSBwcm9jZXNzZXMuMBYGA1UdJQEB/wQMMAoGCCsGAQUFBwMDMDUG
        A1UdHwQuMCwwKqAooCaGJGh0dHA6Ly9jcmwuYXBwbGUuY29tL2NvZGVzaWduaW5n
        LmNybDAdBgNVHQ4EFgQUxu0+Svsu6D8T1aAVs13Z57P3aDUwDgYDVR0PAQH/BAQD
        AgeAMA8GCSqGSIb3Y2QGFgQCBQAwDQYJKoZIhvcNAQEFBQADggEBAImdqA6ANj/n
        AWa6c4Ijc5udq8taXsIwT5AlYJpJMQQJUja4xm5KZlc/Vazm9eTSdfdbz2WD+yj5
        lWkQSsmpwpz+iyAgipl+m2JBmp+mh7pI9nGwlYwkAgg/PrkW8D74/mf+9tidOr6Q
        wQLQSb+bzRoRGQAFOoAVTX0s4419xIygW2SwzhBvXDW5XhZPy/IdTtej2tN9ovsY
        gOBfN9okEUUes4byotjYEeFMNJSWlchRoQhYM2BvvL3PjFYzdUgS5OZrTZjrVDE1
        8DlIa8DPVeqoeE7C699Yb8dRF9XYVUG8aVXco7QB9N80o0zagpmAQtoHMos3u8rh
        59zvNaFyVtE=
        """,

        """
        MIIEDjCCAvagAwIBAgIBITANBgkqhkiG9w0BAQUFADBiMQswCQYDVQQGEwJVUzET
        MBEGA1UEChMKQXBwbGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlv
        biBBdXRob3JpdHkxFjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwHhcNMTExMDI0MTcz
        OTQxWhcNMjYxMDI0MTczOTQxWjB/MQswCQYDVQQGEwJVUzETMBEGA1UECgwKQXBw
        bGUgSW5jLjEmMCQGA1UECwwdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkx
        MzAxBgNVBAMMKkFwcGxlIENvZGUgU2lnbmluZyBDZXJ0aWZpY2F0aW9uIEF1dGhv
        cml0eTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAKKoEXH/DvkLa/gl
        DZiBXWtZvVobibPn5e7OOZgjNTlInyGrJ9nunCDwZDgIawynz9xQth0GxFvxXRqb
        VGWGcy9i5Ti9ARBkcm18aUdhnBAFJuPrhcIsJNxqwj+I/MysKUyhSXkRmnV25R64
        0NIJtExTePvfGHahj6SpMsqRp7b6l705qs0bUBGIq2rt62bKIEusOy3vqufWyYgt
        acKkKmEv24cC86EhuUyfDvj52S3KcgR/Ha5u+j+Is8yjQO4XhxhRlrzP5C2twulZ
        Tl0cZTMnA6pno5Mkh8eHeQK5XZizDu7NaQg+jEiSJLJt1zC+z9jkyKeXgdAeI9w4
        mV9h/oUCAwEAAaOBsTCBrjAOBgNVHQ8BAf8EBAMCAYYwEwYDVR0lBAwwCgYIKwYB
        BQUHAwMwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUjmmmxHdCTgSlVkKcUR+G
        2tIgjwkwHwYDVR0jBBgwFoAUK9BpR5R2Cf70a40uQKb3R01/CF4wNgYDVR0fBC8w
        LTAroCmgJ4YlaHR0cDovL3d3dy5hcHBsZS5jb20vYXBwbGVjYS9yb290LmNybDAN
        BgkqhkiG9w0BAQUFAAOCAQEAcHOt9lIVarcVGN6pKtGddpsesmmWx8LD4SvQ7wdd
        cPjaPFpIR9s5bIDKc95iG7c6yqNaHuOH2iVKk5vvcxCTc13j9J1+3g+B9qmZwVhu
        nPSJAL7PT/8C0w789fP0choysconDt6o05mPauaZ+2HJT/IXsRhn8DDAxgruyESB
        pIm78XlBw+6uyGtnfMxsSYZMAtPTam4YnPhcOMgwh5ow2mcouOKaedqfpTsfUWI7
        IvF+U3waC8PwTdxJRPKIiM46W7md6bK3W1KnxtVYiXK32MyzqBgdUJc/Hdpqrji/
        e3kxvmO594WFF+ltisTiGJQv129SpZmx3USbB3CSiCZ32w==
        """,

        """
        MIIEuzCCA6OgAwIBAgIBAjANBgkqhkiG9w0BAQUFADBiMQswCQYDVQQGEwJVUzET
        MBEGA1UEChMKQXBwbGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlv
        biBBdXRob3JpdHkxFjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwHhcNMDYwNDI1MjE0
        MDM2WhcNMzUwMjA5MjE0MDM2WjBiMQswCQYDVQQGEwJVUzETMBEGA1UEChMKQXBw
        bGUgSW5jLjEmMCQGA1UECxMdQXBwbGUgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkx
        FjAUBgNVBAMTDUFwcGxlIFJvb3QgQ0EwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAw
        ggEKAoIBAQDkkakJH5HbHkdQ6wXtXnmELes2oldMVeyLGYne+Uts9QerIjAC6Bg+
        +FAJ039BqJj50cpmnCRrEdCju+QbKsMflZ56DKRHi1vUFjczy8QPTc4UadHJGXL1
        XQ7Vf1+b8iUDulWPTV0N8WQ1IxVLFVkds5T39pyez1C6wVhQZ48ItCD3y6wsIG9w
        tj8BMIy3Q88PnT3zK0koGsj+zrW5DtleHNbLPbU6rfQPDgCSC7EhFi501TwN22IW
        q6NxkkdTVcGvL0Gz+PvjcM3mo0xFfh9Ma1CWQYnEdGILEINBhzOKgbEwWOxaBDKM
        aLOPHd5lc/9nXmW8Sdh2nzMUZaF3lMktAgMBAAGjggF6MIIBdjAOBgNVHQ8BAf8E
        BAMCAQYwDwYDVR0TAQH/BAUwAwEB/zAdBgNVHQ4EFgQUK9BpR5R2Cf70a40uQKb3
        R01/CF4wHwYDVR0jBBgwFoAUK9BpR5R2Cf70a40uQKb3R01/CF4wggERBgNVHSAE
        ggEIMIIBBDCCAQAGCSqGSIb3Y2QFATCB8jAqBggrBgEFBQcCARYeaHR0cHM6Ly93
        d3cuYXBwbGUuY29tL2FwcGxlY2EvMIHDBggrBgEFBQcCAjCBthqBs1JlbGlhbmNl
        IG9uIHRoaXMgY2VydGlmaWNhdGUgYnkgYW55IHBhcnR5IGFzc3VtZXMgYWNjZXB0
        YW5jZSBvZiB0aGUgdGhlbiBhcHBsaWNhYmxlIHN0YW5kYXJkIHRlcm1zIGFuZCBj
        b25kaXRpb25zIG9mIHVzZSwgY2VydGlmaWNhdGUgcG9saWN5IGFuZCBjZXJ0aWZp
        Y2F0aW9uIHByYWN0aWNlIHN0YXRlbWVudHMuMA0GCSqGSIb3DQEBBQUAA4IBAQBc
        NplMLXi37Yyb3PN3m/J20ncwT8EfhYOFG5k9RzfyqZtAjizUsZAS2L70c5vu0mQP
        y3lPNNiiPvl4/2vIB+x9OYOLUyDTOMSxv5pPCmv/K/xZpwUJfBdAVhEedNO3iyM7
        R6PVbyTi69G3cN8PReEnyvFteO3ntRcXqNx+IjXKJdXZD9Zr1KIkIxH3oayPc4Fg
        xhtbCS+SsvhESPBgOJ4V9T0mZyCKM2r3DYLP3uujL/lTaltkwGMzd/c6ByxW69oP
        IQ7aunMZT7XZNn/Bh1XZp5m5MkL72NVxnn6hUrcbvZNCJBIqxw8dtk2cXmPIS4AX
        UKqK1drk/NAJBzewdXUh
        """,
    ]

    func testSimpleDecode() throws {
        let binary = Array(Data(base64Encoded: Self.base64EncodedSampleCert, options: .ignoreUnknownCharacters)!)
        let cert = try Certificate(derEncoded: binary)

        let expectedPublicKey = try P256.Signing.PublicKey(
            x963Representation: [
                0x04, 0x29, 0xf8, 0xe1, 0x5a, 0xb9, 0x87, 0x44, 0x04, 0x98, 0xff, 0x16, 0x90, 0x86, 0xf9,
                0xe0, 0xe1, 0x42, 0x65, 0x5f, 0x86, 0xfd, 0x03, 0x18, 0xfc, 0xc6, 0xcf, 0x8d, 0x13, 0x5b,
                0xc0, 0x5e, 0x5b, 0x18, 0xa9, 0x61, 0x33, 0x9a, 0xe0, 0x52, 0xe2, 0x78, 0x06, 0x28, 0x53,
                0xed, 0xed, 0xda, 0xd8, 0x3d, 0x15, 0x92, 0xad, 0x03, 0x80, 0x43, 0x4c, 0xee, 0x37, 0x62,
                0x9a, 0xcb, 0x66, 0x6e, 0xb3,
            ]
        )

        XCTAssertEqual(cert.version, .v3)
        XCTAssertEqual(cert.serialNumber.bytes, [0x0c, 0xab, 0xaa, 0xd1, 0xce, 0xc4, 0xe9, 0x7c, 0xc2, 0x66, 0x58, 0x81, 0xd0, 0x21, 0x38, 0xf7])
        XCTAssertEqual(cert.publicKey, Certificate.PublicKey(expectedPublicKey))

        let expectedNotBefore = Date(timeIntervalSince1970: 1588163692.0)
        let expectedNotAfter = Date(timeIntervalSince1970: 1902095999.0)

        XCTAssertEqual(expectedNotBefore, cert.notValidBefore)
        XCTAssertEqual(expectedNotAfter, cert.notValidAfter)

        let expectedIssuer = try DistinguishedName([
            RelativeDistinguishedName.Attribute(type: .RDNAttributeType.countryName, printableString: "US"),
            RelativeDistinguishedName.Attribute(type: .RDNAttributeType.organizationName, printableString: "DigiCert Inc"),
            RelativeDistinguishedName.Attribute(type: .RDNAttributeType.organizationalUnitName, printableString: "www.digicert.com"),
            RelativeDistinguishedName.Attribute(type: .RDNAttributeType.commonName, printableString: "DigiCert Global Root G3"),
        ])

        let expectedSubject = try DistinguishedName([
            RelativeDistinguishedName.Attribute(type: .RDNAttributeType.countryName, printableString: "US"),
            RelativeDistinguishedName.Attribute(type: .RDNAttributeType.organizationName, printableString: "Apple Inc."),
            RelativeDistinguishedName.Attribute(type: .RDNAttributeType.commonName, printableString: "Apple Public EV Server ECC CA 1 - G1"),
        ])

        XCTAssertEqual(cert.issuer, expectedIssuer)
        XCTAssertEqual(cert.subject, expectedSubject)

        XCTAssertEqual(cert.extensions.count, 8)
        XCTAssertEqual(try cert.extensions.authorityInformationAccess, .init([.init(method: .ocspServer, location: .uniformResourceIdentifier("http://ocsp.digicert.com"))]))
        XCTAssertEqual(
            try cert.extensions.subjectKeyIdentifier,
            .init(keyIdentifier: [0xE0, 0x85, 0x48, 0x7D, 0x13, 0xA6, 0xD3, 0x10, 0x19, 0x9F, 0x5C, 0xCB, 0x6B, 0x78, 0x24, 0x92, 0xF8, 0xAE, 0x1B, 0xAE])
        )
        XCTAssertEqual(
            try cert.extensions.authorityKeyIdentifier,
            .init(keyIdentifier: [0xB3, 0xDB, 0x48, 0xA4, 0xF9, 0xA1, 0xC5, 0xD8, 0xAE, 0x36, 0x41, 0xCC, 0x11, 0x63, 0x69, 0x62, 0x29, 0xBC, 0x4B, 0xC6])
        )
        XCTAssertEqual(
            try cert.extensions.extendedKeyUsage,
            .init([.serverAuth, .clientAuth])
        )
        XCTAssertEqual(
            try cert.extensions.basicConstraints,
            .isCertificateAuthority(maxPathLength: 0)
        )
        XCTAssertEqual(
            try cert.extensions.keyUsage,
            .init(digitalSignature: true, keyCertSign: true, cRLSign: true)
        )

        XCTAssertEqual(cert.signatureAlgorithm, .ecdsaWithSHA384)
    }

    func testMatchingExtensionsViaExtensionBuilder() throws {
        let binary = Array(Data(base64Encoded: Self.base64EncodedSampleCert, options: .ignoreUnknownCharacters)!)
        let cert = try Certificate(derEncoded: binary)

        let expectedExtensions = try Certificate.Extensions {
            SubjectKeyIdentifier(keyIdentifier: [0xE0, 0x85, 0x48, 0x7D, 0x13, 0xA6, 0xD3, 0x10, 0x19, 0x9F, 0x5C, 0xCB, 0x6B, 0x78, 0x24, 0x92, 0xF8, 0xAE, 0x1B, 0xAE])

            AuthorityKeyIdentifier(keyIdentifier: [0xB3, 0xDB, 0x48, 0xA4, 0xF9, 0xA1, 0xC5, 0xD8, 0xAE, 0x36, 0x41, 0xCC, 0x11, 0x63, 0x69, 0x62, 0x29, 0xBC, 0x4B, 0xC6])

            Critical(
                KeyUsage(digitalSignature: true, keyCertSign: true, cRLSign: true)
            )

            ExtendedKeyUsage([.serverAuth, .clientAuth])

            Critical(
                BasicConstraints.isCertificateAuthority(maxPathLength: 0)
            )

            AuthorityInformationAccess([.init(method: .ocspServer, location: .uniformResourceIdentifier("http://ocsp.digicert.com"))])

            // CRL Distribution Points
            Certificate.Extension(
                oid: [2, 5, 29, 31],
                critical: false,
                value: [
                    0x30, 0x39, 0x30, 0x37, 0xA0, 0x35, 0xA0, 0x33, 0x86, 0x31, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F,
                    0x2F, 0x63, 0x72, 0x6C, 0x33, 0x2E, 0x64, 0x69, 0x67, 0x69, 0x63, 0x65, 0x72, 0x74, 0x2E, 0x63,
                    0x6F, 0x6D, 0x2F, 0x44, 0x69, 0x67, 0x69, 0x43, 0x65, 0x72, 0x74, 0x47, 0x6C, 0x6F, 0x62, 0x61,
                    0x6C, 0x52, 0x6F, 0x6F, 0x74, 0x47, 0x33, 0x2E, 0x63, 0x72, 0x6C
                ]
            )

            // Certificate policies
            Certificate.Extension(
                oid: [2, 5, 29, 32],
                critical: false,
                value: [
                    0x30, 0x81, 0xD1, 0x30, 0x81, 0xC5, 0x06, 0x09, 0x60, 0x86, 0x48, 0x01, 0x86, 0xFD, 0x6C, 0x02,
                    0x01, 0x30, 0x81, 0xB7, 0x30, 0x28, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x01,
                    0x16, 0x1C, 0x68, 0x74, 0x74, 0x70, 0x73, 0x3A, 0x2F, 0x2F, 0x77, 0x77, 0x77, 0x2E, 0x64, 0x69,
                    0x67, 0x69, 0x63, 0x65, 0x72, 0x74, 0x2E, 0x63, 0x6F, 0x6D, 0x2F, 0x43, 0x50, 0x53, 0x30, 0x81,
                    0x8A, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x02, 0x02, 0x30, 0x7E, 0x0C, 0x7C, 0x41,
                    0x6E, 0x79, 0x20, 0x75, 0x73, 0x65, 0x20, 0x6F, 0x66, 0x20, 0x74, 0x68, 0x69, 0x73, 0x20, 0x43,
                    0x65, 0x72, 0x74, 0x69, 0x66, 0x69, 0x63, 0x61, 0x74, 0x65, 0x20, 0x63, 0x6F, 0x6E, 0x73, 0x74,
                    0x69, 0x74, 0x75, 0x74, 0x65, 0x73, 0x20, 0x61, 0x63, 0x63, 0x65, 0x70, 0x74, 0x61, 0x6E, 0x63,
                    0x65, 0x20, 0x6F, 0x66, 0x20, 0x74, 0x68, 0x65, 0x20, 0x52, 0x65, 0x6C, 0x79, 0x69, 0x6E, 0x67,
                    0x20, 0x50, 0x61, 0x72, 0x74, 0x79, 0x20, 0x41, 0x67, 0x72, 0x65, 0x65, 0x6D, 0x65, 0x6E, 0x74,
                    0x20, 0x6C, 0x6F, 0x63, 0x61, 0x74, 0x65, 0x64, 0x20, 0x61, 0x74, 0x20, 0x68, 0x74, 0x74, 0x70,
                    0x73, 0x3A, 0x2F, 0x2F, 0x77, 0x77, 0x77, 0x2E, 0x64, 0x69, 0x67, 0x69, 0x63, 0x65, 0x72, 0x74,
                    0x2E, 0x63, 0x6F, 0x6D, 0x2F, 0x72, 0x70, 0x61, 0x2D, 0x75, 0x61, 0x30, 0x07, 0x06, 0x05, 0x67,
                    0x81, 0x0C, 0x01, 0x01
                ]
            )
        }

        XCTAssertEqual(cert.extensions, expectedExtensions)
    }

    func testRSARootCert() throws {
        let binary = Array(Data(base64Encoded: Self.base64EncodedRSARootCert, options: .ignoreUnknownCharacters)!)
        let cert = try Certificate(derEncoded: binary)
        XCTAssertTrue(cert.publicKey.isValidSignature(cert.signature, for: cert))
    }

    func testCodesignChain() throws {
        let binaryCerts = Self.codesignCerts.map { Array(Data(base64Encoded: $0, options: .ignoreUnknownCharacters)!) }
        let certs = try binaryCerts.map { try Certificate(derEncoded: $0) }

        // Confirm basic signature validation.
        XCTAssertTrue(certs[1].publicKey.isValidSignature(certs[0].signature, for: certs[0]))
        XCTAssertTrue(certs[2].publicKey.isValidSignature(certs[1].signature, for: certs[1]))
    }
}
