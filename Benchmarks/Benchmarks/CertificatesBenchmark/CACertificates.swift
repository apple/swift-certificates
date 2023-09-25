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

import Foundation

let webPKICertificatesURL = {
    guard
        let certURL = Bundle.module.url(
            forResource: "ca-certificates",
            withExtension: "crt",
            subdirectory: "ca-certificates"
        )
    else {
        fatalError("could not get url in bundle for ca-certificates.crt")
    }
    return certURL
}()

let webPKICertificatesFilePath = webPKICertificatesURL.path

func loadWebPKIAsSingleMuliPEMString() throws -> String {
    try String(decoding: Data(contentsOf: webPKICertificatesURL), as: UTF8.self)
}

func loadWebPKIAsPemStrings() throws -> [String] {
    try caCertificates.map { certName -> String in
        guard
            let extDot = certName.lastIndex(of: "."),
            let extStart = certName.index(extDot, offsetBy: 1, limitedBy: certName.endIndex)
        else {
            fatalError("\(certName) has no extension")
        }
        let name = certName[..<extDot]
        let ext = certName[extStart...]

        guard
            let certURL = Bundle.module.url(
                forResource: String(name),
                withExtension: String(ext),
                subdirectory: "ca-certificates/mozilla"
            )
        else {
            fatalError("could not get url in bundle for cert \(certName)")
        }
        return try String(decoding: Data(contentsOf: certURL), as: UTF8.self)
    }
}

let caCertificates = [
    "AC_RAIZ_FNMT-RCM_SERVIDORES_SEGUROS.crt",
    "AC_RAIZ_FNMT-RCM.crt",
    "ACCVRAIZ1.crt",
    "Actalis_Authentication_Root_CA.crt",
    "AffirmTrust_Commercial.crt",
    "AffirmTrust_Networking.crt",
    "AffirmTrust_Premium_ECC.crt",
    "AffirmTrust_Premium.crt",
    "Amazon_Root_CA_1.crt",
    "Amazon_Root_CA_2.crt",
    "Amazon_Root_CA_3.crt",
    "Amazon_Root_CA_4.crt",
    "ANF_Secure_Server_Root_CA.crt",
    "Atos_TrustedRoot_2011.crt",
    "Autoridad_de_Certificacion_Firmaprofesional_CIF_A62634068_2.crt",
    "Autoridad_de_Certificacion_Firmaprofesional_CIF_A62634068.crt",
    "Baltimore_CyberTrust_Root.crt",
    "Buypass_Class_2_Root_CA.crt",
    "Buypass_Class_3_Root_CA.crt",
    "CA_Disig_Root_R2.crt",
    "Certainly_Root_E1.crt",
    "Certainly_Root_R1.crt",
    "Certigna_Root_CA.crt",
    "Certigna.crt",
    "certSIGN_Root_CA_G2.crt",
    "certSIGN_ROOT_CA.crt",
    "Certum_EC-384_CA.crt",
    "Certum_Trusted_Network_CA_2.crt",
    "Certum_Trusted_Network_CA.crt",
    "Certum_Trusted_Root_CA.crt",
    "CFCA_EV_ROOT.crt",
    "Comodo_AAA_Services_root.crt",
    "COMODO_Certification_Authority.crt",
    "COMODO_ECC_Certification_Authority.crt",
    "COMODO_RSA_Certification_Authority.crt",
    "D-TRUST_BR_Root_CA_1_2020.crt",
    "D-TRUST_EV_Root_CA_1_2020.crt",
    "D-TRUST_Root_Class_3_CA_2_2009.crt",
    "D-TRUST_Root_Class_3_CA_2_EV_2009.crt",
    "DigiCert_Assured_ID_Root_CA.crt",
    "DigiCert_Assured_ID_Root_G2.crt",
    "DigiCert_Assured_ID_Root_G3.crt",
    "DigiCert_Global_Root_CA.crt",
    "DigiCert_Global_Root_G2.crt",
    "DigiCert_Global_Root_G3.crt",
    "DigiCert_High_Assurance_EV_Root_CA.crt",
    "DigiCert_TLS_ECC_P384_Root_G5.crt",
    "DigiCert_TLS_RSA4096_Root_G5.crt",
    "DigiCert_Trusted_Root_G4.crt",
    "e-Szigno_Root_CA_2017.crt",
    "E-Tugra_Certification_Authority.crt",
    "E-Tugra_Global_Root_CA_ECC_v3.crt",
    "E-Tugra_Global_Root_CA_RSA_v3.crt",
    "emSign_ECC_Root_CA_-_C3.crt",
    "emSign_ECC_Root_CA_-_G3.crt",
    "emSign_Root_CA_-_C1.crt",
    "emSign_Root_CA_-_G1.crt",
    "Entrust_Root_Certification_Authority_-_EC1.crt",
    "Entrust_Root_Certification_Authority_-_G2.crt",
    "Entrust_Root_Certification_Authority_-_G4.crt",
    "Entrust_Root_Certification_Authority.crt",
    "Entrust.net_Premium_2048_Secure_Server_CA.crt",
    "ePKI_Root_Certification_Authority.crt",
    "GDCA_TrustAUTH_R5_ROOT.crt",
    "GlobalSign_ECC_Root_CA_-_R4.crt",
    "GlobalSign_ECC_Root_CA_-_R5.crt",
    "GlobalSign_Root_CA_-_R3.crt",
    "GlobalSign_Root_CA_-_R6.crt",
    "GlobalSign_Root_CA.crt",
    "GlobalSign_Root_E46.crt",
    "GlobalSign_Root_R46.crt",
    "GLOBALTRUST_2020.crt",
    "Go_Daddy_Class_2_CA.crt",
    "Go_Daddy_Root_Certificate_Authority_-_G2.crt",
    "GTS_Root_R1.crt",
    "GTS_Root_R2.crt",
    "GTS_Root_R3.crt",
    "GTS_Root_R4.crt",
    "HARICA_TLS_ECC_Root_CA_2021.crt",
    "HARICA_TLS_RSA_Root_CA_2021.crt",
    "Hellenic_Academic_and_Research_Institutions_ECC_RootCA_2015.crt",
    "Hellenic_Academic_and_Research_Institutions_RootCA_2015.crt",
    "HiPKI_Root_CA_-_G1.crt",
    "Hongkong_Post_Root_CA_1.crt",
    "Hongkong_Post_Root_CA_3.crt",
    "IdenTrust_Commercial_Root_CA_1.crt",
    "IdenTrust_Public_Sector_Root_CA_1.crt",
    "ISRG_Root_X1.crt",
    "ISRG_Root_X2.crt",
    "Izenpe.com.crt",
    "Microsec_e-Szigno_Root_CA_2009.crt",
    "Microsoft_ECC_Root_Certificate_Authority_2017.crt",
    "Microsoft_RSA_Root_Certificate_Authority_2017.crt",
    "NAVER_Global_Root_Certification_Authority.crt",
    "NetLock_Arany_=Class_Gold=_Fotanusitvany.crt",
    "OISTE_WISeKey_Global_Root_GB_CA.crt",
    "OISTE_WISeKey_Global_Root_GC_CA.crt",
    "QuoVadis_Root_CA_1_G3.crt",
    "QuoVadis_Root_CA_2_G3.crt",
    "QuoVadis_Root_CA_2.crt",
    "QuoVadis_Root_CA_3_G3.crt",
    "QuoVadis_Root_CA_3.crt",
    "Secure_Global_CA.crt",
    "SecureSign_RootCA11.crt",
    "SecureTrust_CA.crt",
    "Security_Communication_ECC_RootCA1.crt",
    "Security_Communication_Root_CA.crt",
    "Security_Communication_RootCA2.crt",
    "Security_Communication_RootCA3.crt",
    "SSL.com_EV_Root_Certification_Authority_ECC.crt",
    "SSL.com_EV_Root_Certification_Authority_RSA_R2.crt",
    "SSL.com_Root_Certification_Authority_ECC.crt",
    "SSL.com_Root_Certification_Authority_RSA.crt",
    "Starfield_Class_2_CA.crt",
    "Starfield_Root_Certificate_Authority_-_G2.crt",
    "Starfield_Services_Root_Certificate_Authority_-_G2.crt",
    "SwissSign_Gold_CA_-_G2.crt",
    "SwissSign_Silver_CA_-_G2.crt",
    "SZAFIR_ROOT_CA2.crt",
    "T-TeleSec_GlobalRoot_Class_2.crt",
    "T-TeleSec_GlobalRoot_Class_3.crt",
    "Telia_Root_CA_v2.crt",
    "TeliaSonera_Root_CA_v1.crt",
    "Trustwave_Global_Certification_Authority.crt",
    "Trustwave_Global_ECC_P256_Certification_Authority.crt",
    "Trustwave_Global_ECC_P384_Certification_Authority.crt",
    "TUBITAK_Kamu_SM_SSL_Kok_Sertifikasi_-_Surum_1.crt",
    "TunTrust_Root_CA.crt",
    "TWCA_Global_Root_CA.crt",
    "TWCA_Root_Certification_Authority.crt",
    "UCA_Extended_Validation_Root.crt",
    "UCA_Global_G2_Root.crt",
    "USERTrust_ECC_Certification_Authority.crt",
    "USERTrust_RSA_Certification_Authority.crt",
    "vTrus_ECC_Root_CA.crt",
    "vTrus_Root_CA.crt",
    "XRamp_Global_CA_Root.crt",
]
