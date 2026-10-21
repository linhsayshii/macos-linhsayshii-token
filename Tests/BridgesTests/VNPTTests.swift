import Testing
import Foundation
import Security
import Core
@testable import Bridges

private func obj(_ s: String) -> [String: Any] { try! JSONSerialization.jsonObject(with: Data(s.utf8)) as! [String: Any] }
private func req(_ fid: Int, _ args: [String] = [], cb: String = "cb") -> String {
    String(decoding: try! JSONSerialization.data(withJSONObject: ["functionID": fid, "funcCallback": cb, "args": args]), as: UTF8.self)
}
private let origin = "https://dichvucong.gov.vn"
private let b64 = Data("<doc/>".utf8).base64EncodedString()

@Test func versionEchoesCallback() async {
    let r = obj(await VNPTBridge(service: FakeSigningService()).handle(text: req(11), origin: origin))
    #expect(r["code"] as? Int == 0 && r["data"] as? String == "1.0.0.9" && r["funcCallback"] as? String == "cb")
}

@Test func getCertInfoReturnsJsonString() async {
    let r = obj(await VNPTBridge(service: FakeSigningService()).handle(text: req(0), origin: origin))
    #expect(r["code"] as? Int == 0)
    #expect(obj(r["data"] as! String)["serial"] as? String == "54010101")
}

@Test func signXMLPassesOptionsAndReturnsB64() async {
    let svc = FakeSigningService()
    let opts = #"{"digestMethod":"http://www.w3.org/2000/09/xmldsig#sha1","certificateSerial":"54010101","ParrentTagSigning":"NNT"}"#
    let r = obj(await VNPTBridge(service: svc).handle(text: req(1, [b64, opts]), origin: origin))
    #expect(r["code"] as? Int == 0)
    #expect(svc.calls == [.init(kind: "xml", origin: origin, serial: "54010101", input: Data("<doc/>".utf8))])
    #expect(String(decoding: Data(base64Encoded: r["data"] as! String)!, as: UTF8.self).contains("Signature"))
}

@Test func signCMSAndErrors() async {
    let svc = FakeSigningService()
    let b = VNPTBridge(service: svc)
    #expect(obj(await b.handle(text: req(4, [b64]), origin: origin))["code"] as? Int == 0)
    #expect(svc.calls.first?.kind == "cms")
    let digest = Data(repeating: 0xAB, count: 32).base64EncodedString()
    #expect(obj(await b.handle(text: req(9, [digest]), origin: origin))["code"] as? Int == 0)   // signHash
    #expect(svc.calls.contains { $0.kind == "digest-sha256" })
    #expect(obj(await b.handle(text: req(9, [b64]), origin: origin))["code"] as? Int == 1)      // not a digest length
    #expect(obj(await b.handle(text: req(1, []), origin: origin))["code"] as? Int == 1)
    #expect(obj(await b.handle(text: req(2, [b64]), origin: origin))["error"] as? String == "NOT_SUPPORTED")
    #expect(obj(await b.handle(text: "garbage", origin: origin))["code"] as? Int == 1)
    svc.failure = .userDenied
    #expect(obj(await b.handle(text: req(4, [b64]), origin: origin))["code"] as? Int == 11)
}

/// Trusts only the generated local CA, so the test needs no keychain change.
private final class PinCA: NSObject, URLSessionDelegate, @unchecked Sendable {
    let caPEM: String
    init(_ pem: String) { caPEM = pem }
    func urlSession(_ s: URLSession, didReceive c: URLAuthenticationChallenge,
                    completionHandler: @escaping (URLSession.AuthChallengeDisposition, URLCredential?) -> Void) {
        guard let trust = c.protectionSpace.serverTrust else { return completionHandler(.cancelAuthenticationChallenge, nil) }
        let der = Data(base64Encoded: caPEM.split(separator: "\n").filter { !$0.hasPrefix("-----") }.joined())!
        SecTrustSetAnchorCertificates(trust, [SecCertificateCreateWithData(nil, der as CFData)!] as CFArray)
        SecTrustSetAnchorCertificatesOnly(trust, true)
        var err: CFError?
        SecTrustEvaluateWithError(trust, &err) ? completionHandler(.useCredential, URLCredential(trust: trust))
                                               : completionHandler(.cancelAuthenticationChallenge, nil)
    }
}

@Test func wssRoundTripWithLocalCA() async throws {
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent("wss-\(UUID())")
    let ca = LocalCA(directory: dir)
    let mat = try ca.ensure()
    let store = OriginStore(fileURL: dir.appendingPathComponent("o.json"))
    let bridge = VNPTBridge(service: FakeSigningService())
    let srv = WSServer(ports: [0], pathPrefix: "/plugin/", store: store, tls: try ca.sslContext()) { t, o in await bridge.handle(text: t, origin: o) }
    let port = try await srv.start()
    defer { Task { await srv.stop() } }
    // WebGuard compares Host to the bound port, so the real port must be used. Port 0 → ephemeral.
    let reply = await WSTestClient.roundTrip(port: port, path: "/plugin/x", origin: "https://dichvucong.gov.vn",
                                             send: req(11), scheme: "wss", delegate: PinCA(mat.caCertPEM))
    #expect(reply.map(obj)?["data"] as? String == "1.0.0.9")
}
