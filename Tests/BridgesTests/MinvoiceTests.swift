import Testing
import Foundation
@testable import Bridges

private func freshStore() -> OriginStore {
    OriginStore(fileURL: FileManager.default.temporaryDirectory.appendingPathComponent("mi-\(UUID())/o.json"))
}

private func freePort() -> Int {
    let s = socket(AF_INET, SOCK_STREAM, 0); defer { close(s) }
    var a = sockaddr_in(); a.sin_family = sa_family_t(AF_INET); a.sin_addr.s_addr = inet_addr("127.0.0.1")
    var len = socklen_t(MemoryLayout<sockaddr_in>.size)
    _ = withUnsafeMutablePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(s, $0, len) } }
    _ = withUnsafeMutablePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(s, $0, &len) } }
    return Int(UInt16(bigEndian: a.sin_port))
}

private let origin = "https://hddt.minvoice.com.vn"
private let cd = "%5B%7B%22name%22%3A%22handlerHub%22%7D%5D"

private func get(_ url: String, method: String = "GET", body: String? = nil, origin: String? = origin) async -> (Int, [String: Any], HTTPURLResponse?) {
    var r = URLRequest(url: URL(string: url)!)
    r.httpMethod = method
    if let origin { r.setValue(origin, forHTTPHeaderField: "Origin") }
    if let body { r.httpBody = Data(body.utf8); r.setValue("application/x-www-form-urlencoded; charset=UTF-8", forHTTPHeaderField: "Content-Type") }
    guard let (d, resp) = try? await URLSession(configuration: .ephemeral).data(for: r), let h = resp as? HTTPURLResponse
    else { return (0, [:], nil) }
    return (h.statusCode, (try? JSONSerialization.jsonObject(with: d) as? [String: Any]) ?? [:], h)
}

private func startServer() async throws -> (SignalRServer, Int) {
    let svc = FakeSigningService()
    let hub = SignalRHub(handler: MinvoiceBridge(service: svc).handler)
    let port = freePort()
    let srv = SignalRServer(port: port, store: freshStore(), hub: hub)
    _ = try await srv.start()
    return (srv, port)
}

@Test func negotiateAndLongPollRoundTrip() async throws {
    let (srv, port) = try await startServer()
    defer { Task { await srv.stop() } }
    let base = "http://127.0.0.1:\(port)/signalr"
    let (st, neg, resp) = await get("\(base)/negotiate?clientProtocol=1.5&connectionData=\(cd)")
    #expect(st == 200)
    #expect(resp?.value(forHTTPHeaderField: "Access-Control-Allow-Origin") == origin)
    #expect(resp?.value(forHTTPHeaderField: "Access-Control-Allow-Credentials") == "true")
    #expect(neg["ProtocolVersion"] as? String == "1.5")
    let token = (neg["ConnectionToken"] as! String)
    let q = "transport=longPolling&clientProtocol=1.5&connectionToken=\(token)&connectionData=\(cd)"
    let (_, initF, _) = await get("\(base)/connect?\(q)")
    #expect(initF["S"] as? Int == 1)
    #expect((await get("\(base)/start?\(q)")).1["Response"] as? String == "started")

    func send(_ payload: [String: Any]) async -> [String: Any] {
        let j = String(decoding: try! JSONSerialization.data(withJSONObject: payload), as: UTF8.self)
        let enc = j.addingPercentEncoding(withAllowedCharacters: .alphanumerics)!
        return (await get("\(base)/send?\(q)", method: "POST", body: "data=\(enc)")).1
    }
    // getVersion: hub name and method are matched case-insensitively
    let v = await send(["H": "handlerhub", "M": "getVersion", "A": [], "I": 0])
    #expect(v["I"] as? String == "0" && v["R"] as? String == "2.0.0")
    // processMessage -> immediate ack, result arrives through the poll as reponseResult
    let cmd = #"{"BrowserInfo":{"UserName":"u"},"PlugCommand":{"CommandName":"TokenInfo"}}"#
    let ack = await send(["H": "handlerHub", "M": "processMessage", "A": [cmd], "I": 1])
    #expect(ack["I"] as? String == "1" && ack["R"] == nil)
    let (_, pushed, _) = await get("\(base)/poll?\(q)&messageId=x")
    let m = (pushed["M"] as! [[String: Any]]).first!
    #expect(m["M"] as? String == "reponseResult")
    let payload = try JSONSerialization.jsonObject(with: Data((m["A"] as! [String])[0].utf8)) as! [String: Any]
    #expect(payload["code"] as? Int == 1)
    let tok = (payload["data"] as! [String: Any])["token"] as! [String: Any]
    #expect(tok["SerialNumber"] as? String == "54010101")
    #expect(tok["NotBefore"] as? String == "2024-01-01T00:00:00")
    // unsupported command -> non-1 code, never a crash
    _ = await send(["H": "handlerHub", "M": "processMessage", "A": [#"{"PlugCommand":{"CommandName":"SignInvoices"}}"#], "I": 2])
    let (_, p2, _) = await get("\(base)/poll?\(q)")
    let m2 = (p2["M"] as! [[String: Any]]).first!
    #expect(((try JSONSerialization.jsonObject(with: Data((m2["A"] as! [String])[0].utf8))) as! [String: Any])["code"] as? Int == 501)
}

@Test func rejectsUnknownOriginAndBadHost() async throws {
    let (srv, port) = try await startServer()
    defer { Task { await srv.stop() } }
    #expect((await get("http://127.0.0.1:\(port)/signalr/negotiate", origin: "https://evil.example")).0 == 403)
    #expect((await get("http://127.0.0.1:\(port)/signalr/negotiate", origin: nil)).0 == 200)   // native client, no Origin
}

@Test func webSocketTransport() async throws {
    let (srv, port) = try await startServer()
    defer { Task { await srv.stop() } }
    let base = "http://127.0.0.1:\(port)/signalr"
    let token = (await get("\(base)/negotiate?clientProtocol=1.5&connectionData=\(cd)")).1["ConnectionToken"] as! String
    var req = URLRequest(url: URL(string: "ws://127.0.0.1:\(port)/signalr/connect?transport=webSockets&clientProtocol=1.5&connectionToken=\(token)&connectionData=\(cd)")!)
    req.setValue(origin, forHTTPHeaderField: "Origin")
    let t = URLSession(configuration: .ephemeral).webSocketTask(with: req)
    t.resume(); defer { t.cancel() }
    guard case .string(let initF) = try await t.receive() else { Issue.record("no init"); return }
    #expect(initF.contains("\"S\":1"))
    try await t.send(.string(#"{"H":"handlerHub","M":"processMessage","A":["{\"PlugCommand\":{\"CommandName\":\"TokenInfo\"}}"],"I":3}"#))
    var sawAck = false, sawResult = false
    for _ in 0..<2 {
        guard case .string(let s) = try await t.receive() else { break }
        if s.contains("\"I\":\"3\"") { sawAck = true }
        if s.contains("reponseResult") { sawResult = true }
    }
    #expect(sawAck && sawResult)
}
