import Testing
import Foundation
@testable import Bridges

final class WSTestClient {
    /// Connects with optional Origin/Host overrides; returns the echoed reply or nil if the handshake failed.
    static func roundTrip(port: Int, path: String = "/plugin/sign", origin: String?, host: String? = nil,
                          send: String, scheme: String = "ws", delegate: URLSessionDelegate? = nil) async -> String? {
        var req = URLRequest(url: URL(string: "\(scheme)://127.0.0.1:\(port)\(path)")!)
        if let origin { req.setValue(origin, forHTTPHeaderField: "Origin") }
        if let host { req.setValue(host, forHTTPHeaderField: "Host") }
        req.timeoutInterval = 5
        let session = URLSession(configuration: .ephemeral, delegate: delegate, delegateQueue: nil)
        let task = session.webSocketTask(with: req)
        task.resume()
        defer { task.cancel(with: .goingAway, reason: nil); session.invalidateAndCancel() }
        do {
            try await task.send(.string(send))
            if case .string(let s) = try await task.receive() { return s }
        } catch {}
        return nil
    }
}

private func freshStore() -> OriginStore {
    OriginStore(fileURL: FileManager.default.temporaryDirectory.appendingPathComponent("ws-\(UUID())/o.json"))
}

private func freePort() -> Int {
    let s = socket(AF_INET, SOCK_STREAM, 0); defer { close(s) }
    var a = sockaddr_in(); a.sin_family = sa_family_t(AF_INET); a.sin_addr.s_addr = inet_addr("127.0.0.1")
    var len = socklen_t(MemoryLayout<sockaddr_in>.size)
    _ = withUnsafeMutablePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(s, $0, len) } }
    _ = withUnsafeMutablePointer(to: &a) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(s, $0, &len) } }
    return Int(UInt16(bigEndian: a.sin_port))
}

@Test func echoesForAllowedOriginAndRejectsOthers() async throws {
    let store = freshStore()
    let port = freePort()
    let srv = WSServer(ports: [port], pathPrefix: "/plugin/", store: store) { text, origin in "\(origin)|\(text)" }
    #expect(try await srv.start() == port)
    defer { Task { await srv.stop() } }
    let ok = "https://thuedientu.gdt.gov.vn"
    #expect(await WSTestClient.roundTrip(port: port, origin: ok, send: "hi") == "\(ok)|hi")
    #expect(await WSTestClient.roundTrip(port: port, origin: nil, send: "hi") == "local|hi")
    #expect(await WSTestClient.roundTrip(port: port, origin: "https://evil.example", send: "hi") == nil)
    #expect(await store.takePending() == ["https://evil.example"])
    #expect(await WSTestClient.roundTrip(port: port, path: "/other", origin: ok, send: "hi") == nil)
}

@Test func fallsBackWhenPrimaryBusy() async throws {
    let store = freshStore()
    let a = freePort(), b = freePort()
    let first = WSServer(ports: [a], pathPrefix: "/", store: store) { t, _ in t }
    _ = try await first.start()
    let second = WSServer(ports: [a, b], pathPrefix: "/", store: store) { t, _ in t }
    #expect(try await second.start() == b)
    await first.stop(); await second.stop()
}
