import Testing
import Foundation
import Security
import Core
@testable import Bridges

private func req(_ fid: Int, _ args: [String] = [], cb: String = "cb") -> String {
    String(decoding: try! JSONSerialization.data(withJSONObject: ["functionID": fid, "funcCallback": cb, "args": args]), as: UTF8.self)
}
/// Splits the wire reply `<payload>*<callback>`.
private func split(_ s: String) -> (payload: String, cb: String) {
    let i = s.lastIndex(of: "*")!
    return (String(s[..<i]), String(s[s.index(after: i)...]))
}
private func obj(_ s: String) -> [String: Any] { try! JSONSerialization.jsonObject(with: Data(s.utf8)) as! [String: Any] }
private let origin = "https://dichvucong.gov.vn"
private let b64 = Data("<doc/>".utf8).base64EncodedString()

@Test func pluginCheckLicenseAndDialogReplyOneWithCallback() async {
    let b = VNPTBridge(service: FakeSigningService())
    for fid in [7, 6, 37] {
        let r = split(await b.handle(text: req(fid, [""], cb: "callbackDefault"), origin: origin))
        #expect(r.payload == "1" && r.cb == "callbackDefault")
    }
    #expect(split(await b.handle(text: req(11), origin: origin)).payload == "1.0.0.9")
}

@Test func getCertInfoReturnsSerialAndBase64() async {
    let r = split(await VNPTBridge(service: FakeSigningService()).handle(text: req(0, ["0"]), origin: origin))
    let c = obj(r.payload)
    #expect(c["serial"] as? String == "54010101" && c["base64"] as? String == "AAE=")
}

@Test func signArrDataAdvancedReturnsArrayOfJsonStrings() async throws {
    let svc = FakeSigningService()
    let item = String(decoding: try JSONSerialization.data(withJSONObject: ["data": "MTEyMjMzNDQ=", "type": "cmsdetached"]), as: UTF8.self)
    let arr = String(decoding: try JSONSerialization.data(withJSONObject: [item]), as: UTF8.self)
    let r = split(await VNPTBridge(service: svc).handle(text: req(10, [arr, "54010101", "1", "1"]), origin: origin))
    // The portal does JSON.parse(JSON.parse(payload)[0]).data
    let outer = try JSONSerialization.jsonObject(with: Data(r.payload.utf8)) as! [String]
    let inner = obj(outer[0])
    #expect(inner["code"] as? Int == 0)
    #expect(Data(base64Encoded: inner["data"] as! String) == Data([0x30, 0x03, 0x02, 0x01, 0x01]))
    #expect(svc.calls == [.init(kind: "cms", origin: origin, serial: "54010101", input: Data("11223344".utf8))])
}

@Test func signXMLPassesOptionsAndReturnsB64() async {
    let svc = FakeSigningService()
    let opts = #"{"digestMethod":"http://www.w3.org/2000/09/xmldsig#sha1","certificateSerial":"54010101","ParrentTagSigning":"NNT"}"#
    let r = obj(split(await VNPTBridge(service: svc).handle(text: req(1, [b64, opts]), origin: origin)).payload)
    #expect(r["code"] as? Int == 0)
    #expect(svc.calls == [.init(kind: "xml", origin: origin, serial: "54010101", input: Data("<doc/>".utf8))])
    #expect(String(decoding: Data(base64Encoded: r["data"] as! String)!, as: UTF8.self).contains("Signature"))
}

@Test func signCMSHashAndErrors() async {
    let svc = FakeSigningService()
    let b = VNPTBridge(service: svc)
    func code(_ t: String) async -> Int? { obj(split(await b.handle(text: t, origin: origin)).payload)["code"] as? Int }
    #expect(await code(req(4, [b64])) == 0)
    #expect(svc.calls.first?.kind == "cms")
    let digest = Data(repeating: 0xAB, count: 32).base64EncodedString()
    #expect(await code(req(9, [digest])) == 0)
    #expect(svc.calls.contains { $0.kind == "digest-sha256" })
    #expect(await code(req(9, [b64])) == 1)       // not a digest length
    #expect(await code(req(1, [])) == 1)
    #expect(obj(split(await b.handle(text: req(2, [b64]), origin: origin)).payload)["error"] as? String == "NOT_SUPPORTED")
    #expect(split(await b.handle(text: "garbage", origin: origin)).cb == "callbackDefault")
    svc.failure = .userDenied
    #expect(await code(req(4, [b64])) == 11)
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
    let reply = await WSTestClient.roundTrip(port: port, path: "/plugin", origin: "https://dichvucong.gov.vn",
                                             send: req(7), scheme: "wss", delegate: PinCA(mat.caCertPEM))
    #expect(reply == "1*cb")
}
