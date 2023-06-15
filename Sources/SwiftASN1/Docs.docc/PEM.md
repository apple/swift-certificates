# Parsing and Serializing PEM

Serialize and deserialize objects from PEM format.

### Parsing an object from a PEM string

Types conforming to the ``PEMParseable`` protocol can be constructed from a PEM string by calling ``PEMParseable/init(pemEncoded:)`` on the specific type. This will check that the discriminator matches ``PEMParseable/defaultPEMDiscriminator``, decode the base64 encoded string and then decode the DER encoded bytes using ``DERParseable/init(derEncoded:)-i2rf``.

### Serializing an object as a PEM string
Types conforming to the ``PEMSerializable`` protocol can be serialized to a PEM document by calling ``PEMSerializable/serializeAsPEM()`` on the specific type. This will encode the object through ``DER/Serializer``, then encode the DER encoded bytes as base64 and use ``PEMSerializable/defaultPEMDiscriminator`` as the discriminator. The PEM string can then be access through ``PEMDocument/pemString`` property on ``PEMDocument``.

### Related Types

- ``PEMDocument``
- ``PEMRepresentable``
- ``PEMParseable``
- ``PEMSerializable``
