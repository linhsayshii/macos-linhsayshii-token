import Testing
import Foundation
import Security
@testable import Core

func makeTestKey() throws -> SecKey {
    var e: Unmanaged<CFError>?
    let attrs: [String: Any] = [kSecAttrKeyType as String: kSecAttrKeyTypeRSA, kSecAttrKeySizeInBits as String: 2048]
    return try #require(SecKeyCreateRandomKey(attrs as CFDictionary, &e))
}

@Test func softwareSignerSignsSHA256AndSHA1() async throws {
    let key = try makeTestKey()
    let s = SoftwareSigner(key: key, certificateDER: Data([1]))
    let msg = Data("hello".utf8)
    let pub = try #require(SecKeyCopyPublicKey(key))
    for (h, alg) in [(HashAlg.sha256, SecKeyAlgorithm.rsaSignatureMessagePKCS1v15SHA256),
                     (HashAlg.sha1, SecKeyAlgorithm.rsaSignatureMessagePKCS1v15SHA1)] {
        let sig = try await s.sign(message: msg, hash: h)
        #expect(SecKeyVerifySignature(pub, alg, msg as CFData, sig as CFData, nil))
    }
}


@Test func signDigestMatchesMessageSigning() async throws {
    let key = try makeTestKey()
    let s = SoftwareSigner(key: key, certificateDER: Data([1]))
    let msg = Data("hello".utf8)
    let pub = try #require(SecKeyCopyPublicKey(key))
    for h in [HashAlg.sha256, HashAlg.sha1] {
        let sig = try await s.signDigest(CMSSigner.digest(msg, h), hash: h)
        let alg: SecKeyAlgorithm = h == .sha256 ? .rsaSignatureMessagePKCS1v15SHA256 : .rsaSignatureMessagePKCS1v15SHA1
        #expect(SecKeyVerifySignature(pub, alg, msg as CFData, sig as CFData, nil))
    }
}
