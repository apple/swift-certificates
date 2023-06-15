# ``SwiftASN1``

An implementation of ASN.1 types and DER serialization.

## Overview

ASN.1, and the DER encoding scheme, is a commonly used object serialization format. The most common use-cases for ASN.1 in
general computing are in the cryptographic space, but there are a number of use-cases in a wide range of fields. This module
provides an implementation of a number of ASN.1 types, as well as the DER serialization format for ASN.1.

ASN.1 can be used abstractly to describe essentially any kind of object. ASN.1 objects are made up of either primitive or
composite (called "constructed") types. Individual scalar objects can be combined into aggregate types, and composed essentially
arbitrarily to form abstract object formats.

Importantly, the ASN.1 object description does not define a specific encoding for these objects. Instead there are a wide range
of possible ways to serialize or deserialize an ASN.1 object. Some of the most prominent are BER (the Basic Encoding Rules),
CER (the Canonical Encoding Rules), DER (the Distinguished Encoding Rules), and XER (the XML Encoding Rules). For the cryptographic
use-case DER is the standard choice, as a given ASN.1 object can be encoded in only one way under DER. This makes signing and verifying
vastly easier, as it is at least in principle possible to perfectly reconstruct the serialization of a parsed object.

This module provides several moving pieces:

1. A high-level representation of an ASN.1 object, in the form of a tree of object nodes (``ASN1Node``).
2. A DER parser that can construct the ASN.1 tree from serialized bytes (``DER/parse(_:)-72yd1``).
3. A DER serializer that can construct serialized bytes from the ASN.1 tree (``DER/Serializer``).
4. A number of built-in ASN.1 types, representing common constructs.
5. A PEM parser and serializer

These moving pieces combine to provide support for the DER representation of ASN.1 suitable for a wide range of cryptographic uses.

## Topics

### Articles

- <doc:DecodingASN1>
- <doc:PEM>

### Parsing DER

- ``DER/parse(_:)-72yd1``
- ``DER/parse(_:)-6uo24``
- ``DERParseable``
- ``DERSerializable``
- ``DERImplicitlyTaggable``
- ``DER/sequence(_:identifier:_:)``
- ``DER/sequence(of:identifier:rootNode:)``
- ``DER/sequence(of:identifier:nodes:)``
- ``DER/set(_:identifier:_:)``
- ``DER/decodeDefault(_:identifier:defaultValue:_:)``
- ``DER/decodeDefaultExplicitlyTagged(_:tagNumber:tagClass:defaultValue:_:)``
- ``DER/decodeDefault(_:defaultValue:)``
- ``DER/decodeDefault(_:identifier:defaultValue:)``
- ``DER/decodeDefaultExplicitlyTagged(_:tagNumber:tagClass:defaultValue:)``
- ``DER/optionalExplicitlyTagged(_:tagNumber:tagClass:_:)``
- ``DER/optionalImplicitlyTagged(_:tag:)``
- ``DER/explicitlyTagged(_:tagNumber:tagClass:_:)-4jacu``
- ``DER/explicitlyTagged(_:tagNumber:tagClass:_:)-7wb7d``

### Serializing DER

- ``DER/Serializer``
- ``DERSerializable``
- ``DERImplicitlyTaggable``

### Representing ASN.1 types

- ``ASN1Node``
- ``ASN1NodeCollection``
- ``ASN1Identifier``

### Built-in ASN.1 types

- ``ASN1IntegerRepresentable``
- ``IntegerBytesCollection``
- ``GeneralizedTime``
- ``ASN1BitString``
- ``UTCTime``
- ``ASN1OctetString``
- ``ASN1Any``
- ``ASN1Null``
- ``ASN1ObjectIdentifier``
- ``ASN1UTF8String``
- ``ASN1PrintableString``
- ``ASN1BMPString``
- ``ASN1IA5String``
- ``ASN1TeletexString``
- ``ASN1UniversalString``

### Parsing and Serializing PEM
- ``PEMRepresentable``
- ``PEMParseable``
- ``PEMSerializable``
- ``PEMDocument``
