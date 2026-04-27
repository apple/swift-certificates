# Creating Certificates

Create certificates programmatically for testing or other interactions with existing systems.

``X509`` provides a number of conveniences for making this easy. The most common way to create
a certificate is directly, though you can also create one from a ``CertificateSigningRequest``.

## Create certificates directly

Many kinds of certificates are useful to create, but the most common is a self-signed certificate.
These are valuable in testing scenarios, as they can serve both as a trusted root and as an
end-entity certificate.

Fortunately, creating a self-signed certificate is very similar to creating an intermediate or leaf
certificate. This document calls out the steps that might need to be different.

### Gather your requirements

To create a certificate directly, call the
``Certificate/init(version:serialNumber:publicKey:notValidBefore:notValidAfter:issuer:subject:signatureAlgorithm:extensions:issuerPrivateKey:)``
initializer. This requires the following information:

- Version
- Serial number
- Validity period
- Subject name
- Issuer name
- Extensions
- Signature algorithm
- Public Key
- Issuer private key

### Choose a version

Working out the version to use is easy. When creating your own certificates, always create a
``Certificate/Version-swift.struct/v3`` certificate. There is no reason to use any version older than this.

### Set a serial number

The certificate serial number forms part of the identifier of the certificate, along with the issuer name. For a given
CA, each certificate it issues must have a unique serial number. Additionally, the
[CAB Forum Baseline Requirements](https://cabforum.org/baseline-requirements-documents/) require that for certificates that
need to conform to this profile the serial number must contain at least 64-bits of output from a CSPRNG.

``Certificate/SerialNumber-swift.struct`` has a helper initializer that will create a 20-byte serial number
consisting entirely of randomness: ``Certificate/SerialNumber-swift.struct/init()``. That's a good default choice for
this kind of use case.

### Define a validity period

The validity period of a certificate consists of two dates: "not valid before" and "not valid after". The "not valid before" date
refers to the point in time before which a certificate must not be trusted, and is typically set to the date and time at which
the certificate was signed by the issuer. The "not valid after" date refers to the point in time after which the certificate has
expired and should not be trusted.

Together these two dates define a validity period. Set "not valid before" to the current time (`Date()`), and set the
certificate to be valid for a year, making the "not valid after" date `now.addingTimeInterval(60 * 60 * 24 * 365)`.

### Set a subject name

The subject name identifies the entity to whom the certificate is being issued. This is a hierarchical name type called a
``DistinguishedName``. The full complexity of distinguished names is tackled in the ``DistinguishedName`` API documentation,
but for this use case it's sufficient to know that you don't need to set anything other than the common name. Additionally, in
all modern use cases the common name is nothing more than an identifier, so you can set it to whatever you like.

```swift
let subjectName = try DistinguishedName {
    CommonName("My awesome subject")
}
```

### Set an issuer name

Just as the subject name identifies the entity to whom the certificate is being issued, the issuer name identifies the entity that
issued the certificate. In particular, the issuer name should be exactly equivalent to the subject name in the issuing entity's
certificate.

When creating a non-self-signed certificate, set `issuerName` equal to ``Certificate/subject`` from the parent
certificate. For self-signed certificates, the issuer and the subject are identical, so you can set `issuerName = subjectName`.

### Add extensions

The bulk of the semantic information in a certificate is contained in its extensions. For this case, only a small
few matter.

You need ``BasicConstraints`` to be present, and set to
`isCertificateAuthority`. You also need ``KeyUsage`` with the appropriate bits
set. Finally, set ``SubjectAlternativeNames`` to include the domain
name you're going to be self-signing for, which in this case is `localhost`.

You can use the helpful builder syntax for this:

```swift
let extensions = try Certificate.Extensions {
    Critical(
        BasicConstraints.isCertificateAuthority(maxPathLength: nil)
    )
    Critical(
        KeyUsage(keyCertSign: true)
    )
    SubjectAlternativeNames([.dnsName("localhost")])
}
```

### Provide cryptographic material

In this case, the public key, signature algorithm, and issuer private key are intimately bound together. For self-signed certs, the
public key is the public key that belongs to the issuer private key. Relatedly, the signature algorithm is constrained to only those
supported by the private key, as that key does the signing.

When creating a non-self-signed certificate, the issuer private key would be the private key for the issuing certificate,
and the signature algorithm would be constrained to what that key is capable of. The public key could be anything, but it needs to
match the private key that the subject entity has attested to possessing.

You can use the keys from `swift-crypto` for this operation. Select `P256.Signing.PrivateKey` as the private key, which
you can wrap in ``Certificate/PrivateKey/init(_:)-2we15`` to get `issuerPrivateKey`. Then derive `publicKey` via
``Certificate/PrivateKey/publicKey``. Finally, pick the only signature algorithm compatible with that key, which is
``Certificate/SignatureAlgorithm-swift.struct/ecdsaWithSHA256``.

### Serialize the certificate

Once the certificate is created, you'll want to write it out to a file so you can use it. You can easily output this in DER format,
which is commonly indicated using a `.crt` file extension.

Get the DER representation by using code from `SwiftASN1`. ``Certificate`` conforms to `DERSerializable`, so you can serialize
it like this:

```swift
var serializer = DER.Serializer()
try serializer.serialize(certificate)
```

You may also want to save the private key for later use. You can obtain its DER representation from the
original `swift-crypto` key via its `derRepresentation` property.

### Put it all together

Here is the complete code for generating a self-signed certificate.

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

### Convert between Certificate and SecCertificate

Create an instance of ``Certificate`` from `Security/SecCertificate` (from the `Security` framework) with ``Certificate/init(_:)``.
To create an instance of `Security/SecCertificate` from ``Certificate``, use ``Security/SecCertificate/makeWithCertificate(_:)``.
