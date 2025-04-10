# ``X509``

A library for working with X.509 certificates.

## Overview

X.509 certificates are a commonly-used identity format to cryptographically
attest to the identity of an actor in a system. They form part of the X.509
standard created by the ITU-T for defining a public key infrastructure (PKI).
X.509-style PKIs are commonly used in cases where it is necessary to delegate
the authority to attest to an actor's identity to a small number of trusted
parties (called Certificate Authorities).

The most common usage of X.509 certificates today is as part of the WebPKI,
where they are used to secure TLS connections to websites. X.509 certificates
are also used in a wide range of other TLS-based communications, as well as
in code signing infrastructure.

This module makes it possible to serialize, deserialize, create, and interact
with X.509 certificates. This is an essential building-block for a wide range
of PKI applications. It enables building verifiers, interacting with
certificate authorities, authenticating peers, and more.

## Topics

### Articles

- <doc:Examining-Certificates>
- <doc:Creating-Certificates>

### Certificates

- ``Certificate``
- ``Certificate/SerialNumber-swift.struct``
- ``Certificate/Version-swift.struct``
- ``Certificate/PublicKey-swift.struct``
- ``Certificate/PrivateKey``
- ``Certificate/Signature-swift.struct``
- ``Certificate/SignatureAlgorithm-swift.struct``

### X.509 Extensions

- ``Certificate/Extensions-swift.struct``
- ``Certificate/Extension``
- ``ExtensionsBuilder``
- ``CertificateExtensionConvertible``

### Supported Extension Types

- ``AuthorityInformationAccess``
- ``AuthorityKeyIdentifier``
- ``BasicConstraints``
- ``ExtendedKeyUsage``
- ``KeyUsage``
- ``NameConstraints``
- ``SubjectAlternativeNames``
- ``SubjectKeyIdentifier``
- ``Critical``

### Names

- ``DistinguishedName``
- ``RelativeDistinguishedName``
- ``RelativeDistinguishedName/Attribute``
- ``GeneralName``

### Distinguished Name Builder

- ``DistinguishedNameBuilder``
- ``RelativeDistinguishedNameConvertible``
- ``CommonName``
- ``CountryName``
- ``LocalityName``
- ``OrganizationalUnitName``
- ``OrganizationName``
- ``StateOrProvinceName``
- ``StreetAddress``
- ``DomainComponent``
- ``EmailAddress``

### Verifying Certificates

- ``Verifier``
- ``VerifierPolicy``
- ``PolicyBuilder``
- ``PolicyFailureReason``
- ``AnyPolicy``
- ``OneOfPolicyBuilder``
- ``OneOfPolicies``
- ``AllOfPolicies``
- ``CertificateStore``
- ``UnverifiedCertificateChain``
- ``VerificationDiagnostic``

### Pre-implemented Verifier Policies

- ``RFC5280Policy``
- ``ServerIdentityPolicy``
- ``OCSPVerifierPolicy``

### OCSP Policy Helpers

- ``OCSPRequester``
- ``OCSPFailureMode``
- ``OCSPRequesterQueryResult``

### Errors

- ``CertificateError``
