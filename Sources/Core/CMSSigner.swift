import Foundation
import CryptoKit
import X509
import SwiftASN1

public enum CMSError: Error { case badCertificate }

/// CMS/PKCS#7 SignedData, detached (no eContent). Signed attrs: contentType,
/// signingTime, messageDigest, signingCertificateV2. The signature is made over
/// the DER SET of the attrs (tag 0x31), per RFC 5652 §5.4.
public enum CMSSigner {
    static func digest(_ d: Data, _ h: HashAlg) -> Data {
        h == .sha256 ? Data(SHA256.hash(data: d)) : Data(Insecure.SHA1.hash(data: d))
    }

    public static func signDetached(content: Data, signer: MessageSigner, hash: HashAlg = .sha256,
                                    signingTime: Date = Date()) async throws -> Data {
        try await sign(content: content, signer: signer, hash: hash, signingTime: signingTime, attached: false)
    }
    public static func signAttached(content: Data, signer: MessageSigner, hash: HashAlg = .sha256,
                                    signingTime: Date = Date()) async throws -> Data {
        try await sign(content: content, signer: signer, hash: hash, signingTime: signingTime, attached: true)
    }
    private static func sign(content: Data, signer: MessageSigner, hash: HashAlg,
                             signingTime: Date, attached: Bool) async throws -> Data {
        let certDER = signer.certificateDER
        guard let cert = try? Certificate(derEncoded: Array(certDER)) else { throw CMSError.badCertificate }
        var s = SwiftASN1.DER.Serializer(); try s.serialize(cert.issuer)
        let issuerDER = Data(s.serializedBytes)
        // Normalize to minimal two's-complement: random serials can have the high bit set.
        var sb = Array(cert.serialNumber.bytes)
        while sb.count > 1, sb[0] == 0, sb[1] & 0x80 == 0 { sb.removeFirst() }
        if sb[0] & 0x80 != 0 { sb.insert(0, at: 0) }
        let serial = DERW.tlv(0x02, Data(sb))

        let digestAlg = DERW.seq(DERW.oid(hash == .sha256 ? "2.16.840.1.101.3.4.2.1" : "1.3.14.3.2.26"), DERW.null)
        func attr(_ oid: String, _ value: Data) -> Data { DERW.seq(DERW.oid(oid), DERW.set([value])) }
        let essCertID = DERW.seq(DERW.octets(Data(SHA256.hash(data: certDER))))   // SHA-256 is the v2 default
        let attrs = [
            attr("1.2.840.113549.1.9.3", DERW.oid("1.2.840.113549.1.7.1")),
            attr("1.2.840.113549.1.9.5", DERW.utcTime(signingTime)),
            attr("1.2.840.113549.1.9.4", DERW.octets(digest(content, hash))),
            attr("1.2.840.113549.1.9.16.2.47", DERW.seq(DERW.seq(essCertID))),
        ]
        let attrSet = DERW.set(attrs)                       // 0x31 ... : what gets signed
        let signature = try await signer.sign(message: attrSet, hash: hash)
        var signedAttrs = attrSet; signedAttrs[0] = 0xA0     // same bytes, [0] IMPLICIT

        let signerInfo = DERW.seq(DERW.int(1), DERW.seq(issuerDER, serial), digestAlg, signedAttrs,
                                 DERW.seq(DERW.oid("1.2.840.113549.1.1.1"), DERW.null), DERW.octets(signature))
        let encapsulated = attached
            ? DERW.seq(DERW.oid("1.2.840.113549.1.7.1"), DERW.tlv(0xA0, DERW.octets(content)))
            : DERW.seq(DERW.oid("1.2.840.113549.1.7.1"))
        let signedData = DERW.seq(DERW.int(1), DERW.set([digestAlg]), encapsulated,
                                 DERW.tlv(0xA0, certDER), DERW.set([signerInfo]))
        return DERW.seq(DERW.oid("1.2.840.113549.1.7.2"), DERW.tlv(0xA0, signedData))
    }
}
