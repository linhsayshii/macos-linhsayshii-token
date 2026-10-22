import Foundation
import Security

/// Signs messages or precomputed digests with RSA PKCS#1 v1.5.
/// Hardware signing hashes messages on the host and sends DigestInfo to the card.
public protocol MessageSigner: Sendable {
    var certificateDER: Data { get }
    func sign(message: Data, hash: HashAlg) async throws -> Data
    /// Sign a precomputed digest (PKCS#1 v1.5 DigestInfo). This is how real tokens sign everything.
    func signDigest(_ digest: Data, hash: HashAlg) async throws -> Data
}

public struct SoftwareSigner: MessageSigner, @unchecked Sendable {
    let key: SecKey
    public let certificateDER: Data
    public init(key: SecKey, certificateDER: Data) { self.key = key; self.certificateDER = certificateDER }
    public func sign(message: Data, hash: HashAlg) async throws -> Data {
        let alg: SecKeyAlgorithm = hash == .sha256 ? .rsaSignatureMessagePKCS1v15SHA256 : .rsaSignatureMessagePKCS1v15SHA1
        var e: Unmanaged<CFError>?
        guard let sig = SecKeyCreateSignature(key, alg, message as CFData, &e) else { throw e!.takeRetainedValue() }
        return sig as Data
    }
}

extension SoftwareSigner {
    public func signDigest(_ digest: Data, hash: HashAlg) async throws -> Data {
        let alg: SecKeyAlgorithm = hash == .sha256 ? .rsaSignatureDigestPKCS1v15SHA256 : .rsaSignatureDigestPKCS1v15SHA1
        var e: Unmanaged<CFError>?
        guard let sig = SecKeyCreateSignature(key, alg, digest as CFData, &e) else { throw e!.takeRetainedValue() }
        return sig as Data
    }
}

/// Lets the app keep certificate selection, consent and PIN in one serialized request.
public struct CallbackMessageSigner: MessageSigner {
    public let certificateDER: Data
    let callback: @Sendable (Data, HashAlg) async throws -> Data
    public init(certificateDER: Data, callback: @escaping @Sendable (Data, HashAlg) async throws -> Data) {
        self.certificateDER = certificateDER; self.callback = callback
    }
    public func sign(message: Data, hash: HashAlg) async throws -> Data {
        try await callback(CMSSigner.digest(message, hash), hash)
    }
    public func signDigest(_ digest: Data, hash: HashAlg) async throws -> Data {
        try await callback(digest, hash)
    }
}
