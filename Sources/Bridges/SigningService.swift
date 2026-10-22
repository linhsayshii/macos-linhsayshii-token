import Foundation
import Core

public struct BridgeContext: Sendable {
    public let bridge: String
    public let origin: String
    public init(bridge: String, origin: String) { self.bridge = bridge; self.origin = origin }
}

public enum SigningFailure: Error, Equatable, Sendable {
    case unknownSerial(String), userDenied, userCancelled, certExpired, bad(String), card(String)
}

/// What the P2 bridges call. Implemented by AppModel: approval → PIN → sign → audit.
/// `serial == nil` asks the native app to let the user select a certificate.
public protocol SigningService: Sendable {
    func certificates() async -> [CertInfo]
    func selectCertificate(_ ctx: BridgeContext, serial: String?) async throws -> CertInfo
    func signXML(_ ctx: BridgeContext, serial: String?, xml: Data, options: XMLSignOptions) async throws -> Data
    /// Hash raw bytes on the host, then sign DigestInfo on-card (PKCS#1 v1.5). For portals that canonicalize themselves.
    func signMessage(_ ctx: BridgeContext, serial: String?, message: Data, hash: HashAlg) async throws -> (signature: Data, certDER: Data)
    /// Sign a precomputed digest (SHA-256 32B / SHA-1 20B) on-card.
    func signDigest(_ ctx: BridgeContext, serial: String?, digest: Data, hash: HashAlg) async throws -> Data
    func signCMSAttached(_ ctx: BridgeContext, serial: String?, content: Data, hash: HashAlg) async throws -> Data
    func signCMS(_ ctx: BridgeContext, serial: String?, content: Data, hash: HashAlg) async throws -> Data
}

public extension SigningService {
    func signCMSAttached(_ ctx: BridgeContext, serial: String?, content: Data, hash: HashAlg) async throws -> Data {
        throw SigningFailure.bad("Attached CMS chưa được hỗ trợ")
    }
    func selectCertificate(_ ctx: BridgeContext, serial: String?) async throws -> CertInfo {
        let matches = await certificates().filter { cert in
            guard let serial, !serial.isEmpty else { return true }
            return cert.serialHex.caseInsensitiveCompare(serial) == .orderedSame
        }
        guard matches.count == 1, let cert = matches.first else { throw SigningFailure.bad("Hãy chọn đúng một chứng thư") }
        return cert
    }
}
