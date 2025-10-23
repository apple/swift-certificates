//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftCertificates open source project
//
// Copyright (c) 2025 Apple Inc. and the SwiftCertificates project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftCertificates project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

#if canImport(FoundationEssentials)
import FoundationEssentials
#else
import Foundation
#endif
import XCTest
import SwiftASN1
@testable @_spi(FixedExpiryValidationTime) import X509
import Crypto
import _CryptoExtras

#if canImport(Security)
import Security
#endif

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

    #if canImport(Security)
    func testSecCertificateBridge() throws {
        let certificateData = Data(base64Encoded: Self.base64EncodedSampleCert, options: .ignoreUnknownCharacters)!
        let binary = Array(certificateData)

        let cert = try Certificate(derEncoded: binary)

        let certConvertedToSecCert = try SecCertificate.makeWithCertificate(cert)
        let secCertConvertedToCert = try Certificate(certConvertedToSecCert)

        XCTAssertEqual(cert, secCertConvertedToCert)
    }
    #endif

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
        XCTAssertEqual(
            cert.serialNumber.bytes,
            [0x0c, 0xab, 0xaa, 0xd1, 0xce, 0xc4, 0xe9, 0x7c, 0xc2, 0x66, 0x58, 0x81, 0xd0, 0x21, 0x38, 0xf7]
        )
        XCTAssertEqual(cert.publicKey, Certificate.PublicKey(expectedPublicKey))

        let expectedNotBefore = Date(timeIntervalSince1970: 1588163692.0)
        let expectedNotAfter = Date(timeIntervalSince1970: 1902095999.0)

        XCTAssertEqual(expectedNotBefore, cert.notValidBefore)
        XCTAssertEqual(expectedNotAfter, cert.notValidAfter)

        let expectedIssuer = try DistinguishedName([
            RelativeDistinguishedName.Attribute(type: .RDNAttributeType.countryName, printableString: "US"),
            RelativeDistinguishedName.Attribute(
                type: .RDNAttributeType.organizationName,
                printableString: "DigiCert Inc"
            ),
            RelativeDistinguishedName.Attribute(
                type: .RDNAttributeType.organizationalUnitName,
                printableString: "www.digicert.com"
            ),
            RelativeDistinguishedName.Attribute(
                type: .RDNAttributeType.commonName,
                printableString: "DigiCert Global Root G3"
            ),
        ])

        let expectedSubject = try DistinguishedName([
            RelativeDistinguishedName.Attribute(type: .RDNAttributeType.countryName, printableString: "US"),
            RelativeDistinguishedName.Attribute(
                type: .RDNAttributeType.organizationName,
                printableString: "Apple Inc."
            ),
            RelativeDistinguishedName.Attribute(
                type: .RDNAttributeType.commonName,
                printableString: "Apple Public EV Server ECC CA 1 - G1"
            ),
        ])

        XCTAssertEqual(cert.issuer, expectedIssuer)
        XCTAssertEqual(cert.subject, expectedSubject)

        XCTAssertEqual(cert.extensions.count, 8)
        XCTAssertEqual(
            try cert.extensions.authorityInformationAccess,
            .init([.init(method: .ocspServer, location: .uniformResourceIdentifier("http://ocsp.digicert.com"))])
        )
        XCTAssertEqual(
            try cert.extensions.subjectKeyIdentifier,
            .init(keyIdentifier: [
                0xE0, 0x85, 0x48, 0x7D, 0x13, 0xA6, 0xD3, 0x10, 0x19, 0x9F, 0x5C, 0xCB, 0x6B, 0x78, 0x24, 0x92, 0xF8,
                0xAE, 0x1B, 0xAE,
            ])
        )
        XCTAssertEqual(
            try cert.extensions.authorityKeyIdentifier,
            .init(keyIdentifier: [
                0xB3, 0xDB, 0x48, 0xA4, 0xF9, 0xA1, 0xC5, 0xD8, 0xAE, 0x36, 0x41, 0xCC, 0x11, 0x63, 0x69, 0x62, 0x29,
                0xBC, 0x4B, 0xC6,
            ])
        )
        XCTAssertEqual(
            try cert.extensions.extendedKeyUsage,
            try .init([.serverAuth, .clientAuth])
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
            SubjectKeyIdentifier(keyIdentifier: [
                0xE0, 0x85, 0x48, 0x7D, 0x13, 0xA6, 0xD3, 0x10, 0x19, 0x9F, 0x5C, 0xCB, 0x6B, 0x78, 0x24, 0x92, 0xF8,
                0xAE, 0x1B, 0xAE,
            ])

            AuthorityKeyIdentifier(keyIdentifier: [
                0xB3, 0xDB, 0x48, 0xA4, 0xF9, 0xA1, 0xC5, 0xD8, 0xAE, 0x36, 0x41, 0xCC, 0x11, 0x63, 0x69, 0x62, 0x29,
                0xBC, 0x4B, 0xC6,
            ])

            Critical(
                KeyUsage(digitalSignature: true, keyCertSign: true, cRLSign: true)
            )

            try ExtendedKeyUsage([.serverAuth, .clientAuth])

            Critical(
                BasicConstraints.isCertificateAuthority(maxPathLength: 0)
            )

            AuthorityInformationAccess([
                .init(method: .ocspServer, location: .uniformResourceIdentifier("http://ocsp.digicert.com"))
            ])

            // CRL Distribution Points
            Certificate.Extension(
                oid: [2, 5, 29, 31],
                critical: false,
                value: [
                    0x30, 0x39, 0x30, 0x37, 0xA0, 0x35, 0xA0, 0x33, 0x86, 0x31, 0x68, 0x74, 0x74, 0x70, 0x3A, 0x2F,
                    0x2F, 0x63, 0x72, 0x6C, 0x33, 0x2E, 0x64, 0x69, 0x67, 0x69, 0x63, 0x65, 0x72, 0x74, 0x2E, 0x63,
                    0x6F, 0x6D, 0x2F, 0x44, 0x69, 0x67, 0x69, 0x43, 0x65, 0x72, 0x74, 0x47, 0x6C, 0x6F, 0x62, 0x61,
                    0x6C, 0x52, 0x6F, 0x6F, 0x74, 0x47, 0x33, 0x2E, 0x63, 0x72, 0x6C,
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
                    0x81, 0x0C, 0x01, 0x01,
                ]
            )
        }

        XCTAssertEqual(cert.extensions, expectedExtensions)
    }

    func testSubjectKeyIdentifierHash() throws {
        let binary = Array(Data(base64Encoded: Self.base64EncodedSampleCert, options: .ignoreUnknownCharacters)!)
        let cert = try Certificate(derEncoded: binary)

        XCTAssertEqual(try cert.extensions.subjectKeyIdentifier, SubjectKeyIdentifier(hash: cert.publicKey))
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

    func testReencodingDoesntChangeTheBytes() throws {
        // This test validates that we don't change the TBS bytes when we re-encode a certificate.
        //
        // The easiest way to do this is to produce a slightly _weird_ certificate that encodes the signature algorithm
        // in a way we wouldn't.
        let name = try DistinguishedName {
            CommonName("Test")
        }
        let key = try _RSA.Signing.PrivateKey(keySize: .bits2048)

        var coder = DER.Serializer()
        try coder.appendConstructedNode(identifier: .sequence) { coder in
            try coder.serialize(
                Certificate.Version.v3.rawValue,
                explicitlyTaggedWithTagNumber: 0,
                tagClass: .contextSpecific
            )
            try coder.serialize(Certificate.SerialNumber().bytes)
            try coder.serialize(AlgorithmIdentifier.sha256WithRSAEncryptionUsingNil)
            try coder.serialize(name)
            try coder.serialize(
                try Validity(notBefore: .makeTime(from: Date()), notAfter: .makeTime(from: Date() + 100))
            )
            try coder.serialize(name)
            try coder.serialize(SubjectPublicKeyInfo(.init(key.publicKey)))
        }

        let tbsCertificateBytes = coder.serializedBytes

        // Ok, we can construct this into a real certificate now by signing it and producing the signature block.
        let signature = try Certificate.PrivateKey(key).sign(
            bytes: tbsCertificateBytes,
            signatureAlgorithm: .sha256WithRSAEncryption
        )

        coder = DER.Serializer()
        try coder.appendConstructedNode(identifier: .sequence) { coder in
            coder.serializeRawBytes(tbsCertificateBytes)
            try coder.serialize(AlgorithmIdentifier.sha256WithRSAEncryptionUsingNil)
            try coder.serialize(ASN1BitString(signature))
        }

        let serializedCert = coder.serializedBytes

        // Great, done! Now we can deserialize this into a certificate, which should happen without error.
        // Do a few spot checks to confirm it came out ok.
        let cert = try Certificate(derEncoded: serializedCert)
        XCTAssertEqual(cert.subject, name)
        XCTAssertEqual(cert.issuer, name)
        XCTAssertEqual(cert.version, .v3)
        XCTAssertEqual(cert.signatureAlgorithm, .sha256WithRSAEncryption)
        XCTAssertEqual(cert.publicKey, Certificate.PublicKey(key.publicKey))
        XCTAssertTrue(Certificate.PublicKey(key.publicKey).isValidSignature(cert.signature, for: cert))

        // Ok, serialize it back. We must not have canonicalised this.
        coder = DER.Serializer()
        try coder.serialize(cert)
        let reserializedCert = coder.serializedBytes

        XCTAssertEqual(reserializedCert, serializedCert)
    }

    func testRSAKeyFormatOutputIsCorrect() throws {
        // A quick test here, we just encode and decode an RSA key.
        let publicKey = try Certificate.PublicKey(_RSA.Signing.PrivateKey(keySize: .bits2048).publicKey)
        let spki = SubjectPublicKeyInfo(publicKey)

        var encoder = DER.Serializer()
        try encoder.serialize(spki)

        let decodedSPKI = try SubjectPublicKeyInfo(derEncoded: encoder.serializedBytes)
        let newKey = try Certificate.PublicKey(spki: decodedSPKI)
        XCTAssertEqual(publicKey, newKey)
    }

    func testIncorrectParameterSize() throws {
        // This certificate tripped us up and revealed a bug in our ECDSA
        // parsing, so let's use it as a regression test.
        let cert = Array(
            Data(
                base64Encoded: """
                    MIIGATCCBYegAwIBAgIRAJt9HrGyczJOAAAAAFaglHwwCgYIKoZIzj0EAwIwgbox
                    CzAJBgNVBAYTAlVTMRYwFAYDVQQKEw1FbnRydXN0LCBJbmMuMSgwJgYDVQQLEx9T
                    ZWUgd3d3LmVudHJ1c3QubmV0L2xlZ2FsLXRlcm1zMTkwNwYDVQQLEzAoYykgMjAx
                    NiBFbnRydXN0LCBJbmMuIC0gZm9yIGF1dGhvcml6ZWQgdXNlIG9ubHkxLjAsBgNV
                    BAMTJUVudHJ1c3QgQ2VydGlmaWNhdGlvbiBBdXRob3JpdHkgLSBMMUowHhcNMTkx
                    MTEzMDc0MTIwWhcNMjIwMjExMDgxMTE4WjCBpTELMAkGA1UEBhMCU0cxEjAQBgNV
                    BAcTCVNpbmdhcG9yZTETMBEGCysGAQQBgjc8AgEDEwJTRzEcMBoGA1UEChMTVGVt
                    YXNlayBQb2x5dGVjaG5pYzEaMBgGA1UEDxMRR292ZXJubWVudCBFbnRpdHkxEzAR
                    BgNVBAUTClQwOEdCMDA2MkwxHjAcBgNVBAMTFWlzaXMzb3NzY2V0LnRwLmVkdS5z
                    ZzBZMBMGByqGSM49AgEGCCqGSM49AwEHA0IABM2mA20fTxL81TOzHToOMpROOoUO
                    FVwGtdjQlCsN5TQ05Oazts57Cam4TRV437nibW2pHbv4Z6gX5cOj5vtGJFijggN/
                    MIIDezAgBgNVHREEGTAXghVpc2lzM29zc2NldC50cC5lZHUuc2cwggH1BgorBgEE
                    AdZ5AgQCBIIB5QSCAeEB3wB1AId1v+dZfPiMQ5lfvfNu/1aNR1Y2/0q1YMG06v9e
                    oIMPAAABbmPRJr0AAAQDAEYwRAIgDQlMMVr0sZ/vQ6TJayUKr/0uli6JsMdXra7+
                    AXtTAuACIHCqklPVac2HyjMHIcmB9Z9Ff/qdm80cTnJv2D2DF4f1AHYAVYHUwhaQ
                    NgFK6gubVzxT8MDkOHhwJQgXL6OqHQcT0wwAAAFuY9Em+QAABAMARzBFAiBlwOv7
                    uk+wVGWXmZur2HNFHUpY3EL72A6qp0+i+UlNKgIhAPUM6StlYsDeHFBcbwk8Mhsy
                    qvJ/cONzlQoi7aXSKen4AHYAVhQGmi/XwuzT9eG9RLI+x0Z2ubyZEVzA75SYVdaJ
                    0N0AAAFuY9Em+wAABAMARzBFAiAYjMoE9baPZ9jtoL5cLi2hEQFcHmp2V/UkF5gS
                    MCkHbwIhAN0mbQvKboODaXXfPf3K9F5mRks2NYdrpV7I+uTsxxcwAHYAu9nfvB+K
                    cbWTlCOXqpJ7RzhXlQqrUugakJZkNo4e0YUAAAFuY9EmtwAABAMARzBFAiEAocip
                    srDjKmlOd8Zo+mhFFVRmZYlgZMoLV/IvrMTEAFMCIFfzmKsxybQnMGX6iPbTU7nk
                    kAtsnNa6QaTEpRMVmsSEMA4GA1UdDwEB/wQEAwIHgDAdBgNVHSUEFjAUBggrBgEF
                    BQcDAQYIKwYBBQUHAwIwYwYIKwYBBQUHAQEEVzBVMCMGCCsGAQUFBzABhhdodHRw
                    Oi8vb2NzcC5lbnRydXN0Lm5ldDAuBggrBgEFBQcwAoYiaHR0cDovL2FpYS5lbnRy
                    dXN0Lm5ldC9sMWotZWMxLmNlcjAzBgNVHR8ELDAqMCigJqAkhiJodHRwOi8vY3Js
                    LmVudHJ1c3QubmV0L2xldmVsMWouY3JsMEoGA1UdIARDMEEwNgYKYIZIAYb6bAoB
                    AjAoMCYGCCsGAQUFBwIBFhpodHRwOi8vd3d3LmVudHJ1c3QubmV0L3JwYTAHBgVn
                    gQwBATAfBgNVHSMEGDAWgBTD+UUDvsj5CzxFNfPrcuzn6OuUmzAdBgNVHQ4EFgQU
                    7vNz5mM0I6JgWqm+556364tWmW8wCQYDVR0TBAIwADAKBggqhkjOPQQDAgNoADBl
                    AjBwybhS35Z4KFf1pt20LC9/CyxsDya3W/NbMn+bZ0RNNnOPABMv/Z3Xj7w086v4
                    PFcCMQDJVzG8VALwsAvO3JmKPy2LguNq0+pylaihUYGEg6rxxg5WyCXfnpZu0c+i
                    N5YHEvI=
                    """,
                options: .ignoreUnknownCharacters
            )!
        )

        XCTAssertNoThrow(try Certificate(derEncoded: cert))
    }

    @available(*, deprecated, message: "new test added below")
    func testUsingWeirdHashFunctionsDeprecated() async throws {
        let now = Date()
        let issuerKey = P384.Signing.PrivateKey()
        let issuerName = try DistinguishedName {
            CommonName("Issuer")
        }
        let issuer = try Certificate(
            version: .v3,
            serialNumber: .init(),
            publicKey: .init(issuerKey.publicKey),
            notValidBefore: now,
            notValidAfter: now + 100,
            issuer: issuerName,
            subject: issuerName,
            signatureAlgorithm: .ecdsaWithSHA384,
            extensions: try Certificate.Extensions {
                Critical(
                    BasicConstraints.isCertificateAuthority(maxPathLength: nil)
                )
            },
            issuerPrivateKey: .init(issuerKey)
        )

        let leafKey = P384.Signing.PrivateKey()
        let leafName = try DistinguishedName {
            CommonName("Leaf")
        }
        let leaf = try Certificate(
            version: .v3,
            serialNumber: .init(),
            publicKey: .init(leafKey.publicKey),
            notValidBefore: now,
            notValidAfter: now + 50,
            issuer: issuerName,
            subject: leafName,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: try Certificate.Extensions {
                Critical(
                    BasicConstraints.notCertificateAuthority
                )
            },
            issuerPrivateKey: .init(issuerKey)
        )

        // We should be able to serialize and deserialize this, and have it remain equal.
        var serializer = DER.Serializer()
        try serializer.serialize(leaf)
        let parsed = try Certificate(derEncoded: serializer.serializedBytes)
        XCTAssertEqual(parsed, leaf)

        // And we should be able to validate it.
        let roots = CertificateStore([issuer])
        var verifier = Verifier(rootCertificates: roots) {
            RFC5280Policy(fixedExpiryValidationTime: now + 1)
        }
        let result = await verifier.validate(leafCertificate: parsed, intermediates: CertificateStore())

        guard case .validCertificate(let chain) = result else {
            XCTFail("Failed to validate cert")
            return
        }

        XCTAssertEqual(Array(chain), [parsed, issuer])
    }

    func testUsingWeirdHashFunctions() async throws {
        let now = Date()
        let issuerKey = P384.Signing.PrivateKey()
        let issuerName = try DistinguishedName {
            CommonName("Issuer")
        }
        let issuer = try Certificate(
            version: .v3,
            serialNumber: .init(),
            publicKey: .init(issuerKey.publicKey),
            notValidBefore: now,
            notValidAfter: now + 100,
            issuer: issuerName,
            subject: issuerName,
            signatureAlgorithm: .ecdsaWithSHA384,
            extensions: try Certificate.Extensions {
                Critical(
                    BasicConstraints.isCertificateAuthority(maxPathLength: nil)
                )
            },
            issuerPrivateKey: .init(issuerKey)
        )

        let leafKey = P384.Signing.PrivateKey()
        let leafName = try DistinguishedName {
            CommonName("Leaf")
        }
        let leaf = try Certificate(
            version: .v3,
            serialNumber: .init(),
            publicKey: .init(leafKey.publicKey),
            notValidBefore: now,
            notValidAfter: now + 50,
            issuer: issuerName,
            subject: leafName,
            signatureAlgorithm: .ecdsaWithSHA256,
            extensions: try Certificate.Extensions {
                Critical(
                    BasicConstraints.notCertificateAuthority
                )
            },
            issuerPrivateKey: .init(issuerKey)
        )

        // We should be able to serialize and deserialize this, and have it remain equal.
        var serializer = DER.Serializer()
        try serializer.serialize(leaf)
        let parsed = try Certificate(derEncoded: serializer.serializedBytes)
        XCTAssertEqual(parsed, leaf)

        // And we should be able to validate it.
        let roots = CertificateStore([issuer])
        var verifier = Verifier(rootCertificates: roots) {
            RFC5280Policy(fixedExpiryValidationTime: now + 1)
        }
        let result = await verifier.validate(leaf: parsed, intermediates: CertificateStore())

        guard case .validCertificate(let chain) = result else {
            XCTFail("Failed to validate cert")
            return
        }

        XCTAssertEqual(Array(chain), [parsed, issuer])
    }

    func testParsingBigNameConstraints() throws {
        let cert = Array(
            Data(
                base64Encoded: """
                    MIIkKjCCIxKgAwIBAgIJIrmxaudci1hlMA0GCSqGSIb3DQEBCwUAMF0xCzAJBgNV
                    BAYTAkpQMSUwIwYDVQQKExxTRUNPTSBUcnVzdCBTeXN0ZW1zIENPLixMVEQuMScw
                    JQYDVQQLEx5TZWN1cml0eSBDb21tdW5pY2F0aW9uIFJvb3RDQTIwHhcNMjAwMzIz
                    MDcxNzM2WhcNMjkwNTI5MDUwMDM5WjBbMQswCQYDVQQGEwJKUDEqMCgGA1UEChMh
                    TmF0aW9uYWwgSW5zdGl0dXRlIG9mIEluZm9ybWF0aWNzMSAwHgYDVQQDExdOSUkg
                    T3BlbiBEb21haW4gQ0EgLSBHNTCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoC
                    ggEBAMvHidrFR7CRsutS5ioQCQBe5mtBfm1o7d5Hu111so+QrOMzZqtXMFTppYAG
                    qTWst4HW6nNIKgoFcbngQ2motJ44P57oTXu4kUHJO9qti/l9VVU+IIwPgb/xJk6R
                    jp5OcJfg5OPmDc6f3qmzl9803mKO1OO3ldDBGqq430cb1e6EfAD4xw+Rpr7fq5g3
                    PwW1v6cylM6ivOYxYwKhioPUFigzomVNSnCZMzZcsvIjsm+q0UkiCdJf9UcK8/uV
                    tW/3RWLO4SmqAxe+IMnjMO54Bpx1vyLm3jzDC3s4ndtAadQ7+GIvan9RsalRIhjM
                    e851BiXf1URA6BJAVW6bDVOS9ycCAwEAAaOCIO0wgiDpMB0GA1UdDgQWBBRnOjrB
                    a7ccpkFGOTCEyGkAWRFYwTAfBgNVHSMEGDAWgBQKhal3ZQWYfECB+A+XLDjxCuw8
                    zzASBgNVHRMBAf8ECDAGAQH/AgEAMA4GA1UdDwEB/wQEAwIBBjAdBgNVHSUEFjAU
                    BggrBgEFBQcDAQYIKwYBBQUHAwIwSQYDVR0fBEIwQDA+oDygOoY4aHR0cDovL3Jl
                    cG9zaXRvcnkuc2Vjb210cnVzdC5uZXQvU0MtUm9vdDIvU0NSb290MkNSTC5jcmww
                    UgYDVR0gBEswSTBHBgoqgwiMmxtkhwUEMDkwNwYIKwYBBQUHAgEWK2h0dHBzOi8v
                    cmVwb3NpdG9yeS5zZWNvbXRydXN0Lm5ldC9TQy1Sb290Mi8wgYUGCCsGAQUFBwEB
                    BHkwdzAwBggrBgEFBQcwAYYkaHR0cDovL3Njcm9vdGNhMi5vY3NwLnNlY29tdHJ1
                    c3QubmV0MEMGCCsGAQUFBzAChjdodHRwOi8vcmVwb3NpdG9yeS5zZWNvbXRydXN0
                    Lm5ldC9TQy1Sb290Mi9TQ1Jvb3QyY2EuY2VyMIIfOwYDVR0eBIIfMjCCHy6ggh74
                    MAuCCWFndS5hYy5qcDARgg9haWNoaS1lZHUuYWMuanAwE4IRYWljaGktZmFtLXUu
                    YWMuanAwE4IRYWljaGktbWVkLXUuYWMuanAwEIIOYWljaGktcHUuYWMuanAwEoIQ
                    YWljaGktdG9oby5hYy5qcDAPgg1haWNoaS11LmFjLmpwMA6CDGFpdGVjaC5hYy5q
                    cDAOggxha2FzaGkuYWMuanAwEYIPYWtpdGEtbmN0LmFjLmpwMA+CDWFraXRhLXUu
                    YWMuanAwEIIOYW5hbi1uY3QuYWMuanAwDoIMYW5kcmV3LmFjLmpwMAuCCWFwdS5h
                    Yy5qcDASghBhcmlha2UtbmN0LmFjLmpwMBWCE2FzYWhpa2F3YS1tZWQuYWMuanAw
                    FYITYXNhaGlrYXdhLW5jdC5hYy5qcDAPgg1hc2FoaS11LmFjLmpwMBCCDmJ1a2t5
                    by11LmFjLmpwMA6CDGJ1bmt5by5hYy5qcDAPgg1idW5yaS11LmFjLmpwMBCCDmNo
                    aWJha291ZGFpLmpwMA6CDGNoaWt5dS5hYy5qcDANggtjaHVidS5hYy5qcDAQgg5j
                    aHVreW8tdS5hYy5qcDAOggxjaHVvLXUuYWMuanAwEoIQY29uc29ydGl1bS5vci5q
                    cDAQgg5kYWlkby1pdC5hYy5qcDANggtkYWl0by5hYy5qcDAOggxkZW5kYWkuYWMu
                    anAwF4IVZGV2ZWxvcG1lbnQtc2Nob29sLmpwMA2CC2RvaHRvLmFjLmpwMBGCD2Rv
                    a2t5b21lZC5hYy5qcDAQgg5kb3NoaXNoYS5hYy5qcDAMggplZHVyb2FtLmpwMA+C
                    DWVoaW1lLXUuYWMuanAwDIIKZW5yaS5nby5qcDALgglmY3UuYWMuanAwDoIMZmRj
                    bmV0LmFjLmpwMA6CDGZlcnJpcy5hYy5qcDALgglmZXJyaXMuanAwC4IJZml0LmFj
                    LmpwMAuCCWZtdS5hYy5qcDALgglmcHUuYWMuanAwEYIPZnVqaXRhLWh1LmFjLmpw
                    MBGCD2Z1a3VpLW5jdC5hYy5qcDAOggxmdWt1am8uYWMuanAwE4IRZnVrdW9rYS1l
                    ZHUuYWMuanAwFYITZnVrdW9rYS1pbnQtdS5hYy5qcDARgg9mdWt1b2thLXUuYWMu
                    anAwFYITZnVrdXNoaW1hLW5jdC5hYy5qcDATghFmdWt1c2hpbWEtdS5hYy5qcDAS
                    ghBmdWt1eWFtYS11LmFjLmpwMAuCCWZ1bi5hYy5qcDAMggpnYWt1bmluLmpwMA+C
                    DWdpZnUtY24uYWMuanAwE4IRZ2lmdS1rZWl6YWkuYWMuanAwEIIOZ2lmdS1uY3Qu
                    YWMuanAwD4INZ2lmdS1wdS5hYy5qcDAOggxnaWZ1LXUuYWMuanAwC4IJZ2t1LmFj
                    LmpwMA2CC2dyaXBzLmFjLmpwMBCCDmd1bm1hLWN0LmFjLmpwMA+CDWd1bm1hLXUu
                    YWMuanAwFIISaGFjaGlub2hlLWN0LmFjLmpwMBOCEWhhY2hpbm9oZS11LmFjLmpw
                    MBOCEWhha29kYXRlLWN0LmFjLmpwMBCCDmhhbWEtbWVkLmFjLmpwMBSCEmhlaXNl
                    aS1pcnlvdS5hYy5qcDAQgg5oZWlzZWktdS5hYy5qcDAIggZoZ3UuanAwDIIKaGly
                    b2RhaS5qcDAPgg1oaXJva291ZGFpLmpwMBKCEGhpcm9zYWtpLXUuYWMuanAwFYIT
                    aGlyb3NoaW1hLWNtdC5hYy5qcDAUghJoaXJvc2hpbWEtY3UuYWMuanAwE4IRaGly
                    b3NoaW1hLXUuYWMuanAwEIIOaGlyb3NoaW1hLXUuanAwD4INaGktdGVjaC5hYy5q
                    cDANggtoaXQtdS5hYy5qcDAMggpobWpjLmFjLmpwMBKCEGhva2thaS1zLXUuYWMu
                    anAwEYIPaG9ra3lvZGFpLmFjLmpwMA+CDWhva3VkYWkuYWMuanAwE4IRaG9rdS1p
                    cnlvLXUuYWMuanAwEoIQaG9rdXJpa3UtdS5hYy5qcDAPgg1oeW9nby11LmFjLmpw
                    MA2CC2lhbWFzLmFjLmpwMAqCCGlhbWFzLmpwMA+CDWliYXJha2kuYWMuanAwEoIQ
                    aWJhcmFraS1jdC5hYy5qcDALgglpY2MuYWMuanAwEoIQaWNoaW5vc2VraS5hYy5q
                    cDALgglpY3UuYWMuanAwEIIOaWdha3VrZW4ub3IuanAwC4IJaW1zLmFjLmpwMBCC
                    DmludGVybmV0LmFjLmpwMAuCCWlvdC5hYy5qcDAJggdpcG11LmpwMA6CDGlyaS10
                    b2t5by5qcDAKgghpcm9vcC5qcDAUghJpc2hpa2F3YS1uY3QuYWMuanAwC4IJaXNt
                    LmFjLmpwMBCCDml0LWNoaWJhLmFjLmpwMBSCEml0LWhpcm9zaGltYS5hYy5qcDAP
                    gg1pd2FraW11LmFjLmpwMBGCD2l3YXRlLW1lZC5hYy5qcDAPgg1pd2F0ZS11LmFj
                    LmpwMA2CC2phaXN0LmFjLmpwMA+CDWphbXN0ZWMuZ28uanAwCYIHamF4YS5qcDAM
                    ggpqLWZvY3VzLmpwMA2CC2ppY2hpLmFjLmpwMA6CDGppbi1haS5hYy5qcDAOggxq
                    aW5kYWkuYWMuanAwDYILam9zaG8uYWMuanAwC4IJai1wYXJjLmpwMA6CDGpyY2hj
                    bi5hYy5qcDAMggpqc3BzLmdvLmpwMAyCCmp1ZW4uYWMuanAwFYITa2FjaG8tY29s
                    bGVnZS5hYy5qcDAOggxrYWV0c3UuYWMuanAwEoIQa2FnYXdhLW5jdC5hYy5qcDAQ
                    gg5rYWdhd2EtdS5hYy5qcDAUghJrYWdvc2hpbWEtY3QuYWMuanAwE4IRa2Fnb3No
                    aW1hLXUuYWMuanAwEIIOa2FpeW9kYWkuYWMuanAwE4IRa2FuYWdhd2EtaXQuYWMu
                    anAwE4IRa2FuYXphd2EtZ3UuYWMuanAwEoIQa2FuYXphd2EtdS5hYy5qcDALgglr
                    YW5kYWkuanAwEIIOa2Fuc2FpLXUuYWMuanAwFIISa2FzZWktZ2FrdWluLmFjLmpw
                    MAuCCWtidS5hYy5qcDALgglrY3QuYWMuanAwDIIKa2N1YS5hYy5qcDAMggprZWlv
                    LmFjLmpwMAmCB2tlaW8uanAwCIIGa2VrLmpwMA6CDGtpbmRhaS5hYy5qcDARgg9r
                    aW5qby1nYWt1aW4uanAwD4INa2luam8tdS5hYy5qcDAPgg1raXJ5dS11LmFjLmpw
                    MBCCDmtpc2FyYXp1LmFjLmpwMAuCCWtpdC5hYy5qcDAIggZraXQuanAwEYIPa2l0
                    YWt5dS11LmFjLmpwMBGCD2tpdGFtaS1pdC5hYy5qcDARgg9rLWp1bnNoaW4uYWMu
                    anAwDoIMa29iZS1jLmFjLmpwMBGCD2tvYmUtY29sbGVnZS5qcDARgg9rb2JlLWN1
                    ZnMuYWMuanAwEoIQa29iZS1rb3Nlbi5hYy5qcDATghFrb2JlLXRva2l3YS5hYy5q
                    cDAOggxrb2JlLXUuYWMuanAwEIIOa29jaGktY3QuYWMuanAwDYILa29jaGktY3Qu
                    anAwEIIOa29jaGktbXMuYWMuanAwEoIQa29jaGktdGVjaC5hYy5qcDAPgg1rb2No
                    aS11LmFjLmpwMAyCCmtvY2hpLXUuanAwEIIOa29nYWt1aW4uYWMuanAwEoIQa29r
                    dWdha3Vpbi5hYy5qcDASghBrb2t1c2hpa2FuLmFjLmpwMA2CC2tvc2VuLWFjLmpw
                    MA+CDWtvc2VuLWsuZ28uanAwDYILa3BwdWMuYWMuanAwC4IJa3B1LmFjLmpwMA2C
                    C2twdS1tLmFjLmpwMAyCCmt1YXMuYWMuanAwDIIKa3Vmcy5hYy5qcDALgglrdWlu
                    cy5uZXQwEIIOa3VtYWdha3UuYWMuanAwFIISa3VtYW1vdG8taHN1LmFjLmpwMBSC
                    Emt1bWFtb3RvLW5jdC5hYy5qcDASghBrdW1hbW90by11LmFjLmpwMBGCD2t1bml0
                    YWNoaS5hYy5qcDAQgg5rdXJlLW5jdC5hYy5qcDARgg9rdXJ1bWUtaXQuYWMuanAw
                    EoIQa3VydW1lLW5jdC5hYy5qcDAVghNrdXJ1bWUtc2hpbmFpLmFjLmpwMBCCDmt1
                    cnVtZS11LmFjLmpwMBKCEGt1c2hpcm8tY3QuYWMuanAwDIIKa3d1Yy5hYy5qcDAP
                    gg1reW9oYWt1LmdvLmpwMBCCDmt5b2t5by11LmFjLmpwMBGCD2t5b3RvLWFydC5h
                    Yy5qcDASghBreW90by1lY29uLmFjLmpwMBWCE2t5b3RvZ2FrdWVuLXUuYWMuanAw
                    FIISa3lvdG9rYWNoby11LmFjLmpwMBCCDmt5b3RvLXN1LmFjLmpwMA+CDWt5b3Rv
                    LXUuYWMuanAwDIIKa3lvdG8tdS5qcDAQgg5reW90by13dS5hYy5qcDAQgg5reXUt
                    ZGVudC5hYy5qcDAQgg5reXVreW8tdS5hYy5qcDAQgg5reXVzYW4tdS5hYy5qcDAQ
                    gg5reXVzaHUtdS5hYy5qcDAPgg1reXV0ZWNoLmFjLmpwMAyCCmt5dXRlY2guanAw
                    EoIQbWFpenVydS1jdC5hYy5qcDARgg9tYXRzdWUtY3QuYWMuanAwDoIMbWF0c3Vl
                    LWN0LmpwMBOCEW1hdHN1eWFtYS11LmFjLmpwMBCCDm1hdHN1eWFtYS11LmpwMA+C
                    DW1laWppLXUuYWMuanAwDoIMbWVpby11LmFjLmpwMBCCDm1laXJpbi1jLmFjLmpw
                    MA6CDG1lamlyby5hYy5qcDARgg9tZXRyby1jaXQuYWMuanAwDYILbWllLXUuYWMu
                    anAwD4INbWlucGFrdS5hYy5qcDAWghRtaXlha29ub2pvLW5jdC5hYy5qcDARgg9t
                    aXlha3lvLXUuYWMuanAwFIISbWl5YXNhbmtlaS11LmFjLmpwMBOCEW1peWF6YWtp
                    LW11LmFjLmpwMBKCEG1peWF6YWtpLXUuYWMuanAwC4IJbXB1LmFjLmpwMBKCEG11
                    cm9yYW4taXQuYWMuanAwDoIMbXVzYWJpLmFjLmpwMAuCCW15anVlbi5qcDAQgg5t
                    eS1waGFybS5hYy5qcDALgglteXUuYWMuanAwEIIObmFidW5rZW4uZ28uanAwDoIM
                    bmFnYW5vLmFjLmpwMBKCEG5hZ2Fuby1uY3QuYWMuanAwEoIQbmFnYW9rYS1jdC5h
                    Yy5qcDARgg9uYWdhb2thdXQuYWMuanAwEoIQbmFnYXNha2ktdS5hYy5qcDAUghJu
                    YWdveWEtYnVucmkuYWMuanAwEYIPbmFnb3lhLWN1LmFjLmpwMBCCDm5hZ295YS11
                    LmFjLmpwMA2CC25hZ295YS11LmpwMBGCD25hZ295YS13dS5hYy5qcDAKgghuYWlz
                    dC5qcDARgg9uYWthbmlzaGkuYWMuanAwC4IJbmFuemFuLmpwMBCCDm5hbnphbi11
                    LmFjLmpwMAuCCW5hby5hYy5qcDAQgg5uYXJhLWVkdS5hYy5qcDAQgg5uYXJhaGFr
                    dS5nby5qcDAOggxuYXJhLWsuYWMuanAwEYIPbmFyYW1lZC11LmFjLmpwMA+CDW5h
                    cmEtd3UuYWMuanAwDIIKbmFyZWdpLm9yZzAQgg5uYXJ1dG8tdS5hYy5qcDAMggpu
                    Y2dnLmdvLmpwMAyCCm5jZ20uZ28uanAwDIIKbmNucC5nby5qcDARgg9uYy10b3lh
                    bWEuYWMuanAwDoIMbmV0bmZ1Lm5lLmpwMA2CC25ldXJvaW5mLmpwMAiCBm5mdS5q
                    cDALggluZnUubmUuanAwEYIPbi1mdWt1c2hpLmFjLmpwMAyCCm5pYXMuYWMuanAw
                    DIIKbmliYi5hYy5qcDAMggpuaWNoLmdvLmpwMBCCDm5pY2hpYnVuLmFjLmpwMAyC
                    Cm5pZnMuYWMuanAwDoIMbmlmcy1rLmFjLmpwMAuCCW5pZy5hYy5qcDALggluaWgu
                    Z28uanAwD4INbmlob24tdS5hYy5qcDAJggduaWh1LmpwMAuCCW5paS5hYy5qcDAM
                    ggpuaWlkLmdvLmpwMBGCD25paWdhdGEtdS5hYy5qcDATghFuaWloYW1hLW5jdC5h
                    Yy5qcDAMggpuaW1zLmdvLmpwMA6CDG5pbmphbC5hYy5qcDAJggduaW5zLmpwMAyC
                    Cm5pcGguZ28uanAwDIIKbmlwci5hYy5qcDAMggpuaXBzLmFjLmpwMBaCFG5pc2hv
                    Z2FrdXNoYS11LmFjLmpwMA6CDG5pdGVjaC5hYy5qcDALggluaXRlY2guanAwDoIM
                    bml0dGFpLmFjLmpwMAyCCm5peWUuZ28uanAwDYILbm9kYWkuYWMuanAwEIIObi1z
                    ZWlyeW8uYWMuanAwC4IJbnVhLmFjLmpwMAyCCm51YXMuYWMuanAwDYILbnVjYmEu
                    YWMuanAwDIIKbnVmcy5hYy5qcDAMggpudWh3LmFjLmpwMAyCCm51aXMuYWMuanAw
                    EYIPbnVtYXp1LWN0LmFjLmpwMAmCB253ZWMuanAwD4INb2JpaGlyby5hYy5qcDAO
                    ggxvYmlyaW4uYWMuanAwDIIKb2NoYS5hYy5qcDAJggdvaXN0LmpwMAuCCW9pdC5h
                    Yy5qcDAPgg1vaXRhLWN0LmFjLmpwMA6CDG9pdGEtdS5hYy5qcDALgglva2FkYWku
                    anAwDoIMb2thLXB1LmFjLmpwMBGCD29rYXlhbWEtdS5hYy5qcDASghBva2luYXdh
                    LWN0LmFjLmpwMBGCD29raW5hd2EtdS5hYy5qcDAMggpva2l1LmFjLmpwMBKCEG9u
                    b21pY2hpLXUuYWMuanAwDIIKb3Blbi5lZC5qcDAOggxvc2FrYWMuYWMuanAwEIIO
                    b3Nha2EtY3UuYWMuanAwEYIPb3Nha2FmdS11LmFjLmpwMBSCEm9zYWthLWt5b2lr
                    dS5hYy5qcDARgg9vc2FrYS1wY3QuYWMuanAwD4INb3Nha2EtdS5hYy5qcDAQgg5v
                    c2hpbWEtay5hYy5qcDANggtvdGFuaS5hYy5qcDAQgg5vdGFydS11Yy5hYy5qcDAO
                    ggxvdGVtb24uYWMuanAwDIIKb3Vocy5hYy5qcDALgglvdXMuYWMuanAwEIIOb3lh
                    bWEtY3QuYWMuanAwCoIIcGRiai5vcmcwFIIScHUtaGlyb3NoaW1hLmFjLmpwMBOC
                    EXB1LWt1bWFtb3RvLmFjLmpwMAuCCXFzdC5nby5qcDAOggxyYWt1bm8uYWMuanAw
                    DYILcmVoYWIuZ28uanAwEYIPcmVpdGFrdS11LmFjLmpwMBCCDnJla2loYWt1LmFj
                    LmpwMA2CC3Jpa2VuLmdvLmpwMAqCCHJpa2VuLmpwMA6CDHJpa2t5by5hYy5qcDAO
                    ggxyaWtreW8ubmUuanAwEIIOcml0c3VtZWkuYWMuanAwC4IJcmt1LmFjLmpwMAyC
                    CnJvaXMuYWMuanAwEYIPcnVjb25zb3J0aXVtLmpwMA+CDXJ5dWtva3UuYWMuanAw
                    DoIMc2FnYS11LmFjLmpwMBGCD3NhaXRhbWEtdS5hYy5qcDANggtzYW5uby5hYy5q
                    cDAOggxzYXBtZWQuYWMuanAwEYIPc2FwcG9yby11LmFjLmpwMA6CDHNhc2Viby5h
                    Yy5qcDALgglzY3UuYWMuanAwDYILc2Vpam8uYWMuanAwEIIOc2Vpam9oLXUuYWMu
                    anAwDoIMc2Vpa2VpLmFjLmpwMBKCEHNlaW5hbi1nYWt1aW4uanAwEYIPc2VpbmFu
                    LWd1LmFjLmpwMA6CDHNlaXJlaS5hYy5qcDASghBzZWlzYWRvaHRvLmFjLmpwMA6C
                    DHNlaXNlbi5hYy5qcDAQgg5zZWlzZW4tdS5hYy5qcDASghBzZW5kYWktbmN0LmFj
                    LmpwMBCCDnNlbnNodS11LmFjLmpwMA2CC3NlbnNodS11LmpwMBCCDnNldHN1bmFu
                    LmFjLmpwMAuCCXNnay5hYy5qcDALgglzZ3UuYWMuanAwE4IRc2hpYmF1cmEtaXQu
                    YWMuanAwDoIMc2hpZ2Fra2FuLmpwMBGCD3NoaWdhLW1lZC5hYy5qcDAPgg1zaGln
                    YS11LmFjLmpwMBGCD3NoaW1hbmUtdS5hYy5qcDAWghRzaGltb25vc2VraS1jdS5h
                    Yy5qcDARgg9zaGlub25vbWUuYWMuanAwEYIPc2hpbnNodS11LmFjLmpwMBGCD3No
                    aXJheXVyaS5hYy5qcDAQgg5zaGl6dW9rYS5hYy5qcDAOggxzaG9kYWkuYWMuanAw
                    DoIMc2hva2VpLmFjLmpwMBGCD3Nob25hbi1pdC5hYy5qcDAPgg1zaG90b2t1LmFj
                    LmpwMAyCCnNob3Rva3UuanAwD4INc2hvd2EtdS5hYy5qcDAOggxzaHVidW4uYWMu
                    anAwDYILc2luZXQuYWQuanAwDIIKc2lzdC5hYy5qcDALgglzaXUuYWMuanAwDIIK
                    c29jdS5hYy5qcDAOggxzb2pvLXUuYWMuanAwDIIKc29rYS5hYy5qcDANggtzb2tl
                    bi5hYy5qcDAPgg1zcHJpbmc4Lm9yLmpwMBKCEHN1Z2l5YW1hLXUuYWMuanAwEYIP
                    c3V6dWthLWN0LmFjLmpwMAuCCXN3dS5hYy5qcDAQgg50YW1hZ2F3YS5hYy5qcDAN
                    ggt0YW1hZ2F3YS5qcDALggl0YXUuYWMuanAwC4IJdGN1LmFjLmpwMAyCCnRjdWUu
                    YWMuanAwC4IJdGRjLmFjLmpwMBCCDnRlaWt5by11LmFjLmpwMA6CDHRlbnNoaS5h
                    Yy5qcDAUghJ0ZXp1a2F5YW1hLXUuYWMuanAwCIIGdGd1LmpwMAuCCXRodS5hYy5q
                    cDAOggx0aXRlY2guYWMuanAwC4IJdG1kLmFjLmpwMAiCBnRubS5qcDAQgg50b2Jh
                    LWNtdC5hYy5qcDAQgg50b2J1bmtlbi5nby5qcDAOggx0b2hva3UuYWMuanAwFYIT
                    dG9ob2t1LWdha3Vpbi5hYy5qcDASghB0b2hva3UtZ2FrdWluLmpwMBKCEHRvaG9r
                    dS1tcHUuYWMuanAwDoIMdG9oby11LmFjLmpwMA+CDXRvaHRlY2guYWMuanAwDoIM
                    dG9raXdhLmFjLmpwMA6CDHRva29oYS5hYy5qcDARgg90b2tvaGEtamMuYWMuanAw
                    EIIOdG9rb2hhLXUuYWMuanAwE4IRdG9rdXNoaW1hLXUuYWMuanAwEIIOdG9rdXlh
                    bWEuYWMuanAwEIIOdG9reW8tY3QuYWMuanAwFIISdG9tYWtvbWFpLWN0LmFjLmpw
                    MBGCD3RvdHRvcmktdS5hYy5qcDAOggx0b3lha3UuYWMuanAwDIIKdG95by5hYy5q
                    cDARgg90b3lvdGEtY3QuYWMuanAwD4INdHN1a3ViYS5hYy5qcDARgg90c3VrdWJh
                    LWcuYWMuanAwFIISdHN1a3ViYS10ZWNoLmFjLmpwMBSCEnRzdXJ1LWdha3Vlbi5h
                    Yy5qcDARgg90c3VydW1pLXUuYWMuanAwFIISdHN1cnVva2EtbmN0LmFjLmpwMBKC
                    EHRzdXlhbWEtY3QuYWMuanAwDIIKdHVhdC5hYy5qcDAMggp0dWZzLmFjLmpwMAyC
                    CnR1aXMuYWMuanAwDIIKdHVzeS5hYy5qcDALggl0dXQuYWMuanAwDIIKdHdjdS5h
                    Yy5qcDAOggx1LWFpenUuYWMuanAwDYILdWJlLWsuYWMuanAwC4IJdWVjLmFjLmpw
                    MA+CDXUtZnVrdWkuYWMuanAwEYIPdS1nYWt1Z2VpLmFjLmpwMA+CDXUtaHlvZ28u
                    YWMuanAwD4INdS1rb2NoaS5hYy5qcDAQgg51LW5hZ2Fuby5hYy5qcDAPgg11bml2
                    ZXJzaXR5LmpwMA6CDHVvZWgtdS5hYy5qcDAJggd1cGtpLmpwMBCCDnUtcnl1a3l1
                    LmFjLmpwMBGCD3Utc2hpbWFuZS5hYy5qcDAWghR1LXNoaXp1b2thLWtlbi5hYy5q
                    cDAPgg11LXRva3lvLmFjLmpwMBCCDnUtdG95YW1hLmFjLmpwMBSCEnV0c3Vub21p
                    eWEtdS5hYy5qcDAUghJ3YWtheWFtYS1uY3QuYWMuanAwEoIQd2FrYXlhbWEtdS5h
                    Yy5qcDAOggx3YWtob2suYWMuanAwEoIQeWFtYWdhdGEtdS5hYy5qcDATghF5YW1h
                    Z3VjaGktdS5hYy5qcDARgg95YW1hbmFzaGkuYWMuanAwDIIKeWdqYy5hYy5qcDAL
                    ggl5Z3UuYWMuanAwC4IJeW51LmFjLmpwMBCCDnlvbmFnby1rLmFjLmpwMAyCCnl1
                    Z2UuYWMuanAwEYIPdGVpa3lvLWpjLmFjLmpwMBCCDm9zYWthLXVlLmFjLmpwMA2C
                    C3RzdWRhLmFjLmpwMAuCCW5ndS5hYy5qcDALggljMmMuYWMuanAwDoIMYW95YW1h
                    LmFjLmpwMBGCD3VwYy1vc2FrYS5hYy5qcDAIggZmaXQuanAwE4IRZnVrdW9rYS13
                    amMuYWMuanChMDAKhwgAAAAAAAAAADAihyAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
                    AAAAAAAAAAAAADANBgkqhkiG9w0BAQsFAAOCAQEAxWH4we4kk599n+wSNrDE1GDB
                    1P+tBW+X0EUHMeow5Db6EzNFBVr/bgxD/4dTKh0coWo6wzExCBKwag9S4j2eYNre
                    uy8X++HPRoXEqoKhOAIvgj9RLw1eGhW6OJoC++pUXHOAINUrYLgpwxiAZfw0oDAe
                    +NrOXXP/LwDP85gKq+2/QGCsENsxLC4tLhonANethBLExpHaiUhjDVD3IO8w9cmE
                    Fm4c6j6onhml5MChBfLeNoXlc7lG+CKgIV4lQ1AuedV/FcYtNXqADOe5hO4IKENQ
                    PBsG3+c22LGvqt4DsBMYHiGU4AFzT5BLWrYZv1TMIUQ+lSOWvLIsTQSN6WgQ3w==
                    """,
                options: .ignoreUnknownCharacters
            )!
        )

        let decoded = try Certificate(derEncoded: cert)
        XCTAssertNoThrow(try decoded.extensions.nameConstraints)
    }
}

final class CertificatePrivateKeyDEREncodedTests: XCTestCase {
    func testECDSAP256() throws {
        let key = P256.Signing.PrivateKey()
        let derBytes = Array(key.derRepresentation)
        let parsedKey = try Certificate.PrivateKey(derBytes: derBytes)

        XCTAssertEqual(parsedKey.backing, .p256(key))
    }

    func testECDSAP384() throws {
        let key = P384.Signing.PrivateKey()
        let derBytes = Array(key.derRepresentation)
        let parsedKey = try Certificate.PrivateKey(derBytes: derBytes)

        XCTAssertEqual(parsedKey.backing, .p384(key))
    }

    func testECDSAP521() throws {
        let key = P521.Signing.PrivateKey()
        let derBytes = Array(key.derRepresentation)
        let parsedKey = try Certificate.PrivateKey(derBytes: derBytes)

        XCTAssertEqual(parsedKey.backing, .p521(key))
    }

    func testED25519() throws {
        let key = Curve25519.Signing.PrivateKey()
        // swift-crpto offers a similar API but returning Data; use ours as it has wider platform
        // avaialble requirements.
        let derBytes = key.derRepresentation as [UInt8]
        let parsedKey = try Certificate.PrivateKey(derBytes: derBytes)

        XCTAssertEqual(parsedKey.backing, .ed25519(key))
    }

    func testRSA() throws {
        // Unlike other algorithms, RSA's bytes representation is not in PKCS#8 format, so we have
        // to bridge it by first serialising the key as a PKCS#8 PEM document, and then getting
        // its DER bytes.
        let key = try _CryptoExtras._RSA.Signing.PrivateKey(keySize: .bits2048)
        let pkcs8 = key.pkcs8PEMRepresentation
        let pemDoc = try PEMDocument(pemString: pkcs8)
        let derBytes = pemDoc.derBytes
        let parsedKey = try Certificate.PrivateKey(derBytes: derBytes)

        XCTAssertEqual(parsedKey.backing, .rsa(key))
    }
}
