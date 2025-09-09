##===----------------------------------------------------------------------===##
##
## This source file is part of the SwiftCertificates open source project
##
## Copyright (c) 2023 Apple Inc. and the SwiftCertificates project authors
## Licensed under Apache License v2.0
##
## See LICENSE.txt for license information
## See CONTRIBUTORS.txt for the list of SwiftCertificates project authors
##
## SPDX-License-Identifier: Apache-2.0
##
##===----------------------------------------------------------------------===##

add_library(X509
  "CSR/CSRAttribute.swift"
  "CSR/CSRAttributes.swift"
  "CSR/CSRVersion.swift"
  "CSR/CertificateSigningRequest.swift"
  "CSR/CertificationRequestInfo.swift"
  "CSR/ExtensionRequest.swift"
  "Certificate.swift"
  "CertificatePrivateKey.swift"
  "CertificatePublicKey.swift"
  "CertificateSerialNumber.swift"
  "CertificateVersion.swift"
  "CryptographicMessageSyntax/CMSAttribute.swift"
  "CryptographicMessageSyntax/CMSContentInfo.swift"
  "CryptographicMessageSyntax/CMSEncapsulatedContentInfo.swift"
  "CryptographicMessageSyntax/CMSIssuerAndSerialNumber.swift"
  "CryptographicMessageSyntax/CMSOperations.swift"
  "CryptographicMessageSyntax/CMSSignature.swift"
  "CryptographicMessageSyntax/CMSSignedData.swift"
  "CryptographicMessageSyntax/CMSSignerIdentifier.swift"
  "CryptographicMessageSyntax/CMSSignerInfo.swift"
  "CryptographicMessageSyntax/CMSVersion.swift"
  "Curve25519+DER.swift"
  "Digests.swift"
  "DistinguishedName.swift"
  "DistinguishedNameBuilder/CommonName.swift"
  "DistinguishedNameBuilder/CountryName.swift"
  "DistinguishedNameBuilder/DNBuilder.swift"
  "DistinguishedNameBuilder/DomainComponent.swift"
  "DistinguishedNameBuilder/EmailAddress.swift"
  "DistinguishedNameBuilder/LocalityName.swift"
  "DistinguishedNameBuilder/OrganizationName.swift"
  "DistinguishedNameBuilder/OrganizationalUnitName.swift"
  "DistinguishedNameBuilder/StateOrProvinceName.swift"
  "DistinguishedNameBuilder/StreetAddress.swift"
  "Error.swift"
  "Extension Types/AuthorityInformationAccess.swift"
  "Extension Types/AuthorityKeyIdentifier.swift"
  "Extension Types/BasicConstraints.swift"
  "Extension Types/ExtendedKeyUsage.swift"
  "Extension Types/ExtensionIdentifiers.swift"
  "Extension Types/KeyUsage.swift"
  "Extension Types/NameConstraints.swift"
  "Extension Types/SubjectAlternativeName.swift"
  "Extension Types/SubjectKeyIdentifier.swift"
  "Extension.swift"
  "Extensions.swift"
  "ExtensionsBuilder.swift"
  "GeneralName.swift"
  "Lock.swift"
  "LockedValueBox.swift"
  "OCSP/BasicOCSPResponse.swift"
  "OCSP/DirectoryString.swift"
  "OCSP/OCSPCertID.swift"
  "OCSP/OCSPCertStatus.swift"
  "OCSP/OCSPExtensionID.swift"
  "OCSP/OCSPNonce.swift"
  "OCSP/OCSPPolicy.swift"
  "OCSP/OCSPRequest.swift"
  "OCSP/OCSPResponse.swift"
  "OCSP/OCSPResponseBytes.swift"
  "OCSP/OCSPResponseData.swift"
  "OCSP/OCSPResponseStatus.swift"
  "OCSP/OCSPSignature.swift"
  "OCSP/OCSPSingleRequest.swift"
  "OCSP/OCSPSingleResponse.swift"
  "OCSP/OCSPTBSRequest.swift"
  "OCSP/OCSPVersion.swift"
  "PKCS8PrivateKey.swift"
  "PromiseAndFuture.swift"
  "RDNAttribute.swift"
  "RandomNumberGenerator+bytes.swift"
  "RelativeDistinguishedName.swift"
  "SEC1PrivateKey.swift"
  "SecKeyWrapper.swift"
  "Signature.swift"
  "SignatureAlgorithm.swift"
  "Verifier/AllOfPolicies.swift"
  "Verifier/AnyPolicy.swift"
  "Verifier/CertificateStore.swift"
  "Verifier/CustomCertificateStore.swift"
  "Verifier/OneOfPolicies.swift"
  "Verifier/PolicyBuilder.swift"
  "Verifier/RFC5280/BasicConstraintsPolicy.swift"
  "Verifier/RFC5280/DNSNames.swift"
  "Verifier/RFC5280/DirectoryNames.swift"
  "Verifier/RFC5280/ExpiryPolicy.swift"
  "Verifier/RFC5280/IPConstraints.swift"
  "Verifier/RFC5280/NameConstraintsPolicy.swift"
  "Verifier/RFC5280/RFC5280Policy.swift"
  "Verifier/RFC5280/URIConstraints.swift"
  "Verifier/RFC5280/VersionPolicy.swift"
  "Verifier/ServerIdentityPolicy.swift"
  "Verifier/TrustRootLoading.swift"
  "Verifier/UnverifiedChain.swift"
  "Verifier/ValidatedCertificateChain.swift"
  "Verifier/VerificationDiagnostic.swift"
  "Verifier/Verifier.swift"
  "Verifier/VerifierPolicy.swift"
  "X509BaseTypes/AlgorithmIdentifier.swift"
  "X509BaseTypes/ECDSASignature.swift"
  "X509BaseTypes/RSAPKCS1PublicKey.swift"
  "X509BaseTypes/SubjectPublicKeyInfo.swift"
  "X509BaseTypes/TBSCertificate.swift"
  "X509BaseTypes/Time.swift"
  "X509BaseTypes/TimeCalculations.swift"
  "X509BaseTypes/Validity.swift"
  "X509SendableMetatype.swift"
)

target_link_libraries(X509 PUBLIC
  $<$<NOT:$<PLATFORM_ID:Darwin>>:dispatch>
  $<$<NOT:$<PLATFORM_ID:Darwin>>:Foundation>
  Crypto
  _CryptoExtras
  SwiftASN1
  _CertificateInternals)
set_target_properties(X509 PROPERTIES
  INTERFACE_INCLUDE_DIRECTORIES ${CMAKE_Swift_MODULE_DIRECTORY})

_install_target(X509)
set_property(GLOBAL APPEND PROPERTY SWIFT_CERTIFICATES_EXPORTS X509)
