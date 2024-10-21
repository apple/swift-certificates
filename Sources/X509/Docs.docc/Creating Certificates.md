# Creating Certificates

Users often have a need to create certificates. Whether for testing or some other interaction with an
existing system, creating a certificate programmatically is a powerful tool for users.

``X509`` provides a number of conveniences for making this easy. There are two common ways to create
a certificate: directly, or from a CSR.

## Creating Certificates Directly

There are many kinds of certificates that users may want to create, but the most common is to want
to create a self-signed certificate. These are valuable in testing scenarios, as they can serve
both as a trusted root and as an end-entity certificate.

Fortunately, creating a self-signed certificate is very similar to creating an intermediate or leaf
certificate. This document will call out the steps that might need to be different.

### Gathering our requirements

To create a certificate directly we're going to call the
``Certificate/init(version:serialNumber:publicKey:notValidBefore:notValidAfter:issuer:subject:signatureAlgorithm:extensions:issuerPrivateKey:)``
initializer. This requires that we put together the following information:

- Version
- Serial number
- Validity period
- Subject name
- Issuer name
- Extensions
- Signature algorithm
- Public Key
- Issuer private key

### Version

Working out the version to use is easy. When creating our own certificates, we should always create a
``Certificate/Version-swift.struct/v3`` certificate. There is no reason to use any version older than this.

### Serial Number

The certificate serial number forms part of the identifier of the certificate, along with the issuer name. For a given
CA, each certificate it issues must have a unique serial number. Additionally, the
[CAB Forum Baseline Requirements](https://cabforum.org/baseline-requirements-documents/) require that for certificates that
need to conform to this profile the serial number must contain at least 64-bits of output from a CSPRNG.

``Certificate/SerialNumber-swift.struct`` has a helper initializer that will create a 20-byte serial number
consisting entirely of randomness: ``Certificate/SerialNumber-swift.struct/init()``. That's a good default choice for
this kind of use-case.

### Validity Period

The validity period of a certificate is made up of two dates: "not valid before" and "not valid after". The "not valid before" date
refers to the point in time before which a certificate must not be trusted, and is typically set to the date and time at which
the certificate was signed by the issuer. The "not valid after" date refers to the point in time after which the certificate has
expired and should not be trusted.

Together these two dates define a validity period. We'll set "not valid before" to the current time (`Date()`), and we'll set the
certificate to be valid for a year, making the "not valid after" date `now.addingTimeInterval(60 * 60 * 24 * 365)`.

### Subject Name

The subject name identifies the entity to whom the certificate is being issued. This is a hierarchical name type called a
``DistinguishedName``. The full complexity of distinguished names is tackled in the ``DistinguishedName`` API documentation,
but for our use-case it's sufficient to know that we don't need to set anything other than the common name. Additionally, in
all modern use-cases the common name is nothing more than an identifier, so we can set it to whatever we like.

```swift
let subjectName = DistinguishedName {
    CommonName("My awesome subject")
}
```

### Issuer Name

Just as the subject name identifies the entity to whom the subject is being issued, the issuer name identifies the entity that
issued the certificate. In particular, the issuer name should be exactly equivalent to the subject name in the issuing entity's
certificate.

If we were creating a non-self-signed certificate, we'd set `issuerName` equal to ``Certificate/subject`` from the parent
certificate. For self-signed certificates, the issuer and the subject are identical, so we can set `issuerName = subjectName`.

### Extensions

The bulk of the semantic information in a certificate is contained in its extensions. For our case, we care about only a small
few.

We need ``BasicConstraints`` to be present, and set to
`isCertificateAuthority`. We also need ``KeyUsage`` with the appropriate bits
set. Finally, we want to set ``SubjectAlternativeNames`` to include the domain
name we're going to be self-signing for, which in this case we'll set to `localhost`.

We can use the helpful builder syntax for this:

```swift
let extensions = try Certificate.Extensions {
    Critical(
        BasicConstraints.isCertificateAuthority(maxPathLength: nil)
    )
    Critical(
        KeyUsage(digitalSignature: true, keyCertSign: true)
    )
    SubjectAlternativeNames([.dnsName("localhost")])
}
```

### Cryptographic Material

In our case, the public key, signature algorithm, and issuer private key are intimately bound together. For self-signed certs, the
public key is the public key that belongs to the issuer private key. Relatedly, the signature algorithm is constrained to only those
that are supported by our private key, as that'll be the one doing the signing.

If we weren't creating a self-signed certificate, the issuer private key would be the private key for the issuing certificate,
and the signature algorithm would be constrained to what that key is capable of. The public key could be anything, but it needs to
match the private key that the subject entity has attested to possessing.

We can use the keys from `swift-crypto` for this operation. We'll select `P256.Signing.PrivateKey` as our private key, which
we can wrap up in ``Certificate/PrivateKey/init(_:)-6xkmz`` to get `issuerPrivateKey`. We can then derive `publicKey` via
``Certificate/PrivateKey/publicKey``. Finally, we'll pick the only signature algorithm compatible with that key, which is
``Certificate/SignatureAlgorithm-swift.struct/ecdsaWithSHA256``.

### Serializing

Once the certificate is created, we'll want to write it out to a file so we can use it! We can easily output this in DER format,
which is commonly indicated using a `.crt` file extension.

We get the DER representation by using code from `SwiftASN1`. ``Certificate`` conforms to `DERSerializable`, so we can serialize
it like this:

```swift
var serializer = DER.Serializer()
try serializer.serialize(certificate)
```

### Putting it all together

That leaves us with the following code for generating a self-signed certificate.

```swift
import Crypto
import SwiftASN1
import X509

let swiftCryptoKey = P256.Signing.PrivateKey()
let key = Certificate.PrivateKey(swiftCryptoKey)

let subjectName = try DistinguishedName {
    CommonName("My awesome subject")
}
let issuerName = subjectName

let now = Date()

let extensions = try Certificate.Extensions {
    Critical(
        BasicConstraints.isCertificateAuthority(maxPathLength: nil)
    )
    Critical(
        KeyUsage(keyCertSign: true)
    )
    SubjectAlternativeNames([.dnsName("localhost")])
}

let certificate = try Certificate(
    version: .v3,
    serialNumber: Certificate.SerialNumber(),
    publicKey: key.publicKey,
    notValidBefore: now,
    notValidAfter: now.addingTimeInterval(60 * 60 * 24 * 365),
    issuer: issuerName,
    subject: subjectName,
    signatureAlgorithm: .ecdsaWithSHA256,
    extensions: extensions,
    issuerPrivateKey: key)

var serializer = DER.Serializer()
try serializer.serialize(certificate)

let derEncodedCertificate = serializer.serializedBytes
let derEncodedPrivateKey = swiftCryptoKey.derRepresentation
```

### Creating Certificates from SecCertificate and vice versa

An instance of ``Certificate`` can be created from `Security/SecCertificate` (from the `Security` framework) with `Certificate/init(_:)`.
The opposite, that is, creating an instance of `Security/SecCertificate` from `Certificate`, can be achieved with `Security/SecCertificate/makeWithCertificate(_:)`.
