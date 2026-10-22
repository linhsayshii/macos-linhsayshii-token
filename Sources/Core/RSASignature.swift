import Foundation
import Security

public enum RSAPKCS1v15 {
    public static func encode(_ payload: Data, modulusBytes: Int) throws -> Data {
        guard modulusBytes >= 11, modulusBytes <= 512, !payload.isEmpty,
              payload.count <= modulusBytes - 11 else { throw ESPKMetadataError.sizeLimit }
        return Data([0,1]) + Data(repeating: 0xff, count: modulusBytes - payload.count - 3)
            + Data([0]) + payload
    }

    /// Canonical PKCS#1 RSAPublicKey for comparison with the certificate key.
    public static func publicKeyDER(modulus: Data, exponent: Data) -> Data {
        func length(_ count: Int) -> Data {
            if count < 128 { return Data([UInt8(count)]) }
            var n = count, bytes: [UInt8] = []
            while n > 0 { bytes.insert(UInt8(n & 255), at: 0); n >>= 8 }
            return Data([0x80 | UInt8(bytes.count)]) + Data(bytes)
        }
        func integer(_ data: Data) -> Data {
            var value = Data(data.drop(while: { $0 == 0 }))
            if value.isEmpty { value = Data([0]) }
            if value.first! & 0x80 != 0 { value.insert(0, at: value.startIndex) }
            return Data([2]) + length(value.count) + value
        }
        let body = integer(modulus) + integer(exponent)
        return Data([0x30]) + length(body.count) + body
    }

    public static func certificateMatches(_ identity: ESPKSigningIdentity) -> Bool {
        guard let cert = SecCertificateCreateWithData(nil, identity.certificateDER as CFData),
              let key = SecCertificateCopyKey(cert),
              let encoded = SecKeyCopyExternalRepresentation(key, nil) as Data? else { return false }
        return encoded == publicKeyDER(modulus: identity.modulus, exponent: identity.exponent)
    }

    /// `payload` is the caller-built DigestInfo, with no additional hash step.
    /// This checks RSA mathematics, independently of certificate expiry/trust.
    public static func verify(signature: Data, payload: Data, certificateDER: Data) -> Bool {
        guard let cert = SecCertificateCreateWithData(nil, certificateDER as CFData),
              let key = SecCertificateCopyKey(cert) else { return false }
        return SecKeyVerifySignature(key, .rsaSignatureDigestPKCS1v15Raw,
                                     payload as CFData, signature as CFData, nil)
    }
}
