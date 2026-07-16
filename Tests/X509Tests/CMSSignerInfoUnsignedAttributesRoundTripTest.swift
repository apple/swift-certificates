import XCTest
import SwiftASN1
@testable @_spi(CMS) import X509

final class CMSSignerInfoUnsignedAttributesRoundTripTest: XCTestCase
{
    private func assertRoundTrips<ASN1Object: DERParseable & DERSerializable & Equatable>(_ value: ASN1Object)
        throws
    {
        var serializer = DER.Serializer()
        try serializer.serialize(value)
        let parsed = try ASN1Object(derEncoded: serializer.serializedBytes)
        XCTAssertEqual(parsed, value)
    }

    func testCMSSignerInfoWithUnsignedAttrsRoundTrips()
        throws
    {
        // A SignerInfo carrying unsignedAttrs must survive a serialize/parse round trip.
        // This exercises the `[1] IMPLICIT` unsignedAttrs path.
        let unsignedAttr = CMSAttribute(
            attrType: .contentType,
            attrValues: [try ASN1Any(erasing: ASN1OctetString(contentBytes: [0xDE, 0xAD, 0xBE, 0xEF]))]
        )
        try assertRoundTrips(
            CMSSignerInfo(
                version: .v1,
                signerIdentifier: .issuerAndSerialNumber(
                    .init(
                        issuer: .init {
                            CountryName("US")
                            OrganizationName("Apple Inc.")
                            CommonName("Apple Public EV Server ECC CA 1 - G1")
                        },
                        serialNumber: .init(bytes: [20, 30, 40, 50])
                    )
                ),
                digestAlgorithm: .sha256WithRSAEncryptionUsingNil,
                signatureAlgorithm: .ecdsaWithSHA256,
                signature: .init(contentBytes: [100, 110, 120, 130, 140]),
                unsignedAttrs: [unsignedAttr]
            )
        )
    }
}
