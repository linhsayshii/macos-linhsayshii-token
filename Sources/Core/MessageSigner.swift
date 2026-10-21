import Foundation
import Security

/// Signs a raw message (PKCS#1 v1.5). The token hashes on-card: these tokens
/// cannot sign a precomputed DigestInfo.
public protocol MessageSigner: Sendable {
    var certificateDER: Data { get }
    func sign(message: Data, hash: HashAlg) async throws -> Data
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

public struct BrokerSigner: MessageSigner {
    let broker: TokenBroker, module: ModuleInfo, serial: String, cert: CertInfo
    let pin: @Sendable () async throws -> String
    public var certificateDER: Data { Data(base64Encoded: cert.derB64) ?? Data() }
    public init(broker: TokenBroker, module: ModuleInfo, serial: String, cert: CertInfo,
                pin: @escaping @Sendable () async throws -> String) {
        self.broker = broker; self.module = module; self.serial = serial; self.cert = cert; self.pin = pin
    }
    public func sign(message: Data, hash: HashAlg) async throws -> Data {
        let b64 = try await broker.sign(module: module, serial: serial, certId: cert.id,
                                        mech: hash == .sha256 ? .sha256RSA : .sha1RSA,
                                        dataB64: message.base64EncodedString(), pin: try await pin())
        return Data(base64Encoded: b64) ?? Data()
    }
}
