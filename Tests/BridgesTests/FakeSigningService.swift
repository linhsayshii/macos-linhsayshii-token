import Foundation
import Core
@testable import Bridges

final class FakeSigningService: SigningService, @unchecked Sendable {
    struct Call: Equatable { let kind: String; let origin: String; let serial: String?; let input: Data }
    private let lock = NSLock()
    private var _calls: [Call] = []
    var calls: [Call] { lock.lock(); defer { lock.unlock() }; return _calls }
    var failure: SigningFailure?
    var xmlFailure: XMLDSigError?
    var certs = [CertInfo(id: "01", derB64: "AAE=", subject: "CN=Test,MST=0101", issuer: "CN=VNPT-CA SHA2",
                          serialHex: "54010101", notBefore: "2024-01-01 00:00:00", notAfter: "2027-01-01 00:00:00")]

    private func record(_ k: String, _ c: BridgeContext, _ s: String?, _ d: Data) {
        lock.lock(); _calls.append(Call(kind: k, origin: c.origin, serial: s, input: d)); lock.unlock()
    }
    func certificates() async -> [CertInfo] { certs }
    func signXML(_ ctx: BridgeContext, serial: String?, xml: Data, options: XMLSignOptions) async throws -> Data {
        record("xml", ctx, serial, xml); if let failure { throw failure }
        if let xmlFailure { throw xmlFailure }
        return Data("<signed><ds:Signature/></signed>".utf8)
    }
    func signMessage(_ ctx: BridgeContext, serial: String?, message: Data, hash: HashAlg) async throws -> (signature: Data, certDER: Data) {
        record("msg-\(hash)", ctx, serial, message); if let failure { throw failure }
        return (Data([9, 9]), Data([1, 2]))
    }
    func signDigest(_ ctx: BridgeContext, serial: String?, digest: Data, hash: HashAlg) async throws -> Data {
        record("digest-\(hash)", ctx, serial, digest); if let failure { throw failure }
        return Data([7, 7])
    }
    func signCMSAttached(_ ctx: BridgeContext, serial: String?, content: Data, hash: HashAlg) async throws -> Data {
        record("cms-attached", ctx, serial, content); if let failure { throw failure }
        return Data([0x30, 0x03, 0x02, 0x01, 0x01])
    }
    func signCMS(_ ctx: BridgeContext, serial: String?, content: Data, hash: HashAlg) async throws -> Data {
        record("cms", ctx, serial, content); if let failure { throw failure }
        return Data([0x30, 0x03, 0x02, 0x01, 0x01])
    }
}
