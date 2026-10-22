import Foundation
import Security
import Testing
import X509
import SwiftASN1
@testable import Core

private func attributes(_ values: [(UInt32, Data)]) throws -> ESPKAttributes {
    var data = Data()
    for (type, value) in values {
        for number in [type, UInt32(value.count)] {
            data.append(contentsOf: (0..<4).map { UInt8((number >> ($0 * 8)) & 255) })
        }
        data.append(value)
    }
    return try ESPKAttributes(data: data)
}

@Test func fastcaPairsExactIDsAndRejectsAmbiguousOrUnsupportedKeys() throws {
    let id = Data([0,0xff,7])
    let cert = try attributes([(0,Data([1,0,0,0])), (0x102,id), (0x11,Data([0x30,0]))])
    func key(id: Data, reference: Data = Data([0x20,0xa0,0,0])) throws -> ESPKAttributes {
        try attributes([(0,Data([3,0,0,0])), (0x100,Data([0,0,0,0])), (0x108,Data([1])),
                        (0x102,id), (0x120,Data(repeating: 0x80, count: 256)),
                        (0x122,Data([1,0,1])), (0x80000100,reference)])
    }
    let match = try key(id: id)
    let result = try ESPKSigningIdentity.resolve(certificates: [cert], keys: [match])
    #expect(result.count == 1)
    #expect(result[0].keyReference == 0xa020)
    #expect(result[0].id == id)
    #expect(!RSAPKCS1v15.certificateMatches(result[0])) // malformed certificate cannot reach PIN
    #expect(try ESPKSigningIdentity.resolve(certificates: [cert], keys: [key(id: Data([7]))]).isEmpty)
    #expect(try ESPKSigningIdentity.resolve(certificates: [cert], keys: [key(id: id, reference: Data([0x20,0x24,0,0]))]).isEmpty)
    #expect(throws: ESPKMetadataError.duplicateAttribute) {
        try ESPKSigningIdentity.resolve(certificates: [cert, cert], keys: [match])
    }
    #expect(throws: ESPKMetadataError.duplicateAttribute) {
        try ESPKSigningIdentity.resolve(certificates: [cert], keys: [match, match])
    }
}

@Test func rsaPaddingHonorsMinimumAndPublicKeyDERIsCanonical() throws {
    let payload = Data([0x30,0x31,0x04,0])
    let encoded = try RSAPKCS1v15.encode(payload, modulusBytes: 15)
    #expect(encoded == Data([0,1]) + Data(repeating: 0xff, count: 8) + Data([0]) + payload)
    #expect(throws: ESPKMetadataError.sizeLimit) { try RSAPKCS1v15.encode(payload, modulusBytes: 14) }
    #expect(throws: ESPKMetadataError.sizeLimit) { try RSAPKCS1v15.encode(Data(), modulusBytes: 256) }
    var modulus = Data(repeating: 0x80, count: 256)
    modulus[255] = 0x81 // RSA public modulus must be odd.
    let exponent = Data([1,0,1])
    let der = RSAPKCS1v15.publicKeyDER(modulus: modulus, exponent: exponent)
    let key = try #require(SecKeyCreateWithData(der as CFData, [
        kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeyClass: kSecAttrKeyClassPublic
    ] as CFDictionary, nil))
    #expect(SecKeyCopyExternalRepresentation(key, nil) as Data? == der)
    #expect(der == RSAPKCS1v15.publicKeyDER(modulus: Data([0]) + modulus, exponent: exponent))
}

@Test func rsaVerificationBindsPayloadSignatureAndCertificate() throws {
    func fixture() throws -> (SecKey, Data) {
        let key = try #require(SecKeyCreateRandomKey([
            kSecAttrKeyType: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits: 2048,
            kSecAttrIsPermanent: false
        ] as CFDictionary, nil))
        let privateKey = try Certificate.PrivateKey(key)
        let name = try DistinguishedName { CommonName("TokenSigner test fixture") }
        let cert = try Certificate(version: .v3, serialNumber: .init(bytes: [1]),
                                   publicKey: privateKey.publicKey,
                                   notValidBefore: Date(timeIntervalSince1970: 0),
                                   notValidAfter: Date(timeIntervalSince1970: 1),
                                   issuer: name, subject: name, extensions: Certificate.Extensions {},
                                   issuerPrivateKey: privateKey)
        var serializer = DER.Serializer()
        try serializer.serialize(cert)
        return (key, Data(serializer.serializedBytes))
    }
    let (key, cert) = try fixture()
    let payload = Data(try DigestInfo.sha256Block(Data("FastCA fixture".utf8)))
    let signature = try #require(SecKeyCreateSignature(key, .rsaSignatureDigestPKCS1v15Raw,
                                                     payload as CFData, nil) as Data?)
    // Deliberately expired certificate: mathematical verification is independent of trust.
    #expect(RSAPKCS1v15.verify(signature: signature, payload: payload, certificateDER: cert))
    #expect(!RSAPKCS1v15.verify(signature: signature, payload: payload + Data([0]), certificateDER: cert))
    var changed = signature; changed[0] ^= 1
    #expect(!RSAPKCS1v15.verify(signature: changed, payload: payload, certificateDER: cert))
    let (_, otherCert) = try fixture()
    #expect(!RSAPKCS1v15.verify(signature: signature, payload: payload, certificateDER: otherCert))
}
