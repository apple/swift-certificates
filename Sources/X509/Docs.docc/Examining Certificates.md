# Examining Certificates

Decoding and introspecting certificates.

A common use-case is to have received an X.509 certificate from some source, and to want
to inspect it and make decisions based on its content. X.509 certificates are complex
objects with highly dynamic and nested content, so this article attempts to outline
how to work with ``Certificate`` in order to get the most out of the content of an
X.509 certificate.

## Parsing

Certificates are commonly provided in two formats: PEM and DER. The two formats are closely
related. PEM stands for "Privacy Enhanced Mail", and a PEM certificate commonly looks like
this:

```
-----BEGIN CERTIFICATE-----
MIIB0jCCAXegAwIBAgIUKggFG6vN44MJ3HhCMcypJZTjzyUwCgYIKoZIzj0EAwIw
SjELMAkGA1UEBgwCVVMxGjAYBgNVBAoMEVN3aWZ0IENlcnRpZmljYXRlMR8wHQYD
VQQDDBZHb29kIGpvYiBkZWNvZGluZyB0aGlzMB4XDTIyMTAyODEwMTQyMloXDTIz
MTAyODEwMTQyMlowSjELMAkGA1UEBgwCVVMxGjAYBgNVBAoMEVN3aWZ0IENlcnRp
ZmljYXRlMR8wHQYDVQQDDBZHb29kIGpvYiBkZWNvZGluZyB0aGlzMFkwEwYHKoZI
zj0CAQYIKoZIzj0DAQcDQgAEa0NRgN2LXAvr66LEna3rmJTTn2O1WC6tFJCCw6LD
8TRA9Rz6zYzbpD4+rEoxRTyF6AQuIint1+LmbdmcGhTsUqM7MDkwDwYDVR0TAQH/
BAUwAwEB/zAOBgNVHQ8BAf8EBAMCAgQwFgYDVR0RBA8wDYILZXhhbXBsZS5jb20w
CgYIKoZIzj0EAwIDSQAwRgIhAORCXnM39TRyN5RRmsFgEZgojUf1MqyG/azkAMx1
FGgfAiEA1PMpcTTeK8Hi17N0oaNNIWERLqDketPZG5E3OdEDw9E=
-----END CERTIFICATE-----
```

This format is the DER representation of a certificate, base64-encoded, line wrapped at 64
bytes, and bracketed by the `BEGIN X`/`END X` delimiter. As PEMs can easily be translated
to DER bytes and vice-versa, the rest of this document will focus on the DER format.

To parse a certificate from DER, we can construct it with a helper initializer from `SwiftASN1`:

```swift
let derBytes: [UInt8] = // get these from somewhere
let certificate = try Certificate(derEncoded: derBytes)
```

Assuming the certificate is well-formed, this constructor will build us a ``Certificate`` object
that we can work with.

## Introspecting Certificates

Certificates have a wide range of fields. Many of them are not that interesting (for example,
``Certificate/version-swift.property``). However, a number of them make useful attestations about the
subject of the certificate.

### Names

Certificates have at least two names attached to them: ``Certificate/issuer`` and ``Certificate/subject``.
``Certificate/issuer`` provides the name of the entity that issued the certificate, while
``Certificate/subject`` provides the name of the entity to which the certificate was issued. Both of
these names are represented using ``DistinguishedName``.

``DistinguishedName`` is a fairly complex type that is described in more detail in its API documentation.
In short, it's a hierarchical collection of ``RelativeDistinguishedName``s, each of which is made up
of a set of equivalent ``RelativeDistinguishedName/Attribute``s. These ``RelativeDistinguishedName``s
are arranged in order from least specific to most specific, typically ending with a relative
distinguished name containing a ``CommonName`` ``RelativeDistinguishedName/Attribute``.

A string representation of a ``DistinguishedName`` can be obtained by using `String(describing:)`. This
uses the common [RFC4514 format](https://www.rfc-editor.org/rfc/rfc4514) for textual ``DistinguishedName``s.

Generally speaking the specific content of the names in these fields are unimportant to end users, though they do
play a vital role in validating certificates.

### Keys

Certificates are bound to a specific private key, which can be used to authenticate that a specific entity is
the one to whom the certificate was issued. This binding is achieved by embedding the public key corresponding
to the underlying private key into the certificate object itself. This is modelled in the ``Certificate/publicKey-swift.property``
field.

In ``X509`` the ``Certificate/PublicKey-swift.struct`` type is opaque, but they can be compared for equality.

### Extensions

The majority of the semantic information in certificate objects is stored in their X509v3 extensions.
These are a typed key-value dictionary that contain additional information about both the subject of the
certificate and about much of its content.

``X509`` stores the extension information in a ``Certificate/Extensions-swift.struct`` collection. This
is a full-fidelity representation of all extensions found in the certificate. This stores the extensions
as ``Certificate/Extension`` objects, an opaque raw-bytes representation of the extension.

Implementations are generally not required to understand all extensions in a certificate, as many are
strictly informational. However, some extensions must be understood in order for the certificate to safely
fulfil their function. As a result, users of a certificate should always search for extensions that have
the ``Certificate/Extension/critical`` bit set to `true` and, if they do not understand those extensions,
should refuse to trust the certificate.

As the raw representation of extensions is difficult to use, ``X509`` provides a number of higher-level
typed representations of common extensions. These can decode themselves from the ``Certificate/Extension/value``
bytes in an extension, as well as wrap themselves back into the opaque ``Certificate/Extension`` type.

Out of the box, ``X509`` ships support for the following extension types:

- ``AuthorityInformationAccess``
- ``AuthorityKeyIdentifier``
- ``BasicConstraints``
- ``ExtendedKeyUsage``
- ``KeyUsage``
- ``NameConstraints``
- ``SubjectAlternativeNames``
- ``SubjectKeyIdentifier``

To decode an extension usually requires examining its ``Certificate/Extension/oid`` field. For example, to search
for the ``SubjectAlternativeNames``, the typical code would be:

```swift
let opaqueSanExtension = certificate.extensions.first(where: { $0.oid == .X509ExtensionID.subjectAlternativeName })
if let opaqueSanExtension {
    let unwrappedSanExtension = try SubjectAlternativeName(opaqueSanExtension)
}
```

This is verbose and repetitive code, so users are encouraged to use the helper function ``Certificate/Extensions-swift.struct/subscript(oid:)``
to search for a specific extension. The above code could be replaced by:

```swift
if let opaqueSanExtension = certificate.extensions[oid: .X509ExtensionID.subjectAlternativeName] {
    let unwrappedSanExtension = try SubjectAlternativeName(opaqueSanExtension)
}
```

This pattern is itself still somewhat repetitive, so ``Certificate/Extensions-swift.struct`` offers a number of helper properties
that can be used to get a specific typed extension:

- ``Certificate/Extensions-swift.struct/authorityInformationAccess``
- ``Certificate/Extensions-swift.struct/authorityKeyIdentifier``
- ``Certificate/Extensions-swift.struct/basicConstraints``
- ``Certificate/Extensions-swift.struct/extendedKeyUsage``
- ``Certificate/Extensions-swift.struct/keyUsage``
- ``Certificate/Extensions-swift.struct/nameConstraints``
- ``Certificate/Extensions-swift.struct/subjectAlternativeNames``
- ``Certificate/Extensions-swift.struct/subjectKeyIdentifier``

This lets us reduce the above code to a single line:

```swift
let unwrappedSanExtension = try certificate.extensions.subjectAlternativeName
```

This shorthand is most useful when searching for a specific extension. When attempting to work with an entire certificate,
users are encouraged to iterate the ``Certificate/Extensions-swift.struct`` and unwrap each extension in turn. This ensures
that unknown or invalid ``Certificate/Extension/critical`` extensions are not incorrectly tolerated.

### Signatures

All X.509 certificates are signed by their issuer. The issuer calculates the signature over a specific sub-portion
of the certificate called the `TBSCertificate`. The signature is then appended to the `TBSCertificate` along with an
identifier of what the signature algorithm was.

These fields are all exposed on the ``Certificate`` type. The signature itself is represented by ``Certificate/signature-swift.property``,
an opaque object (``Certificate/Signature-swift.struct``) that encapsulates a specific signature field. The signature algorithm is also
represented by ``Certificate/signatureAlgorithm-swift.property`` which stores a simple identifier for the algorithm in question.

The bytes to be signed are also present in the ``Certificate/tbsCertificateBytes`` field. For parsed certificates, these bytes are
the raw certificate bytes as parsed from the wire, which guarantees that there is no encode/decode misrepresentation in these bytes.

Together these objects make it possible to validate that a signature was correctly signed, using
``Certificate/PublicKey-swift.struct/isValidSignature(_:for:)-3cbor``.

> Warning: While this is a necessary condition for determining the issuer of a certificate, it is not a sufficient one.
> Users are strongly discouraged from hand-rolling their own verification logic, and should instead prefer using an
> existing verifier. Wherever possible, prefer to use the platform verifier.
