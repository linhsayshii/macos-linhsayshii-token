import Foundation
import Darwin
import Testing
@testable import Bridges

private func unusedListenerPort() throws -> Int {
    let fd = socket(AF_INET, SOCK_STREAM, 0); defer { close(fd) }
    var address = sockaddr_in(); address.sin_family = sa_family_t(AF_INET); address.sin_addr.s_addr = inet_addr("127.0.0.1")
    var count = socklen_t(MemoryLayout<sockaddr_in>.size)
    let bound = withUnsafeMutablePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, count) } }
    #expect(bound == 0)
    _ = withUnsafeMutablePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &count) } }
    return Int(UInt16(bigEndian: address.sin_port))
}
private func connectIdleClient(_ port: Int) throws -> Int32 {
    let fd = socket(AF_INET, SOCK_STREAM, 0)
    var address = sockaddr_in(); address.sin_family = sa_family_t(AF_INET)
    address.sin_addr.s_addr = inet_addr("127.0.0.1"); address.sin_port = UInt16(port).bigEndian
    let result = withUnsafePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, socklen_t(MemoryLayout<sockaddr_in>.size)) } }
    guard result == 0 else { close(fd); throw POSIXError(.ECONNREFUSED) }
    var timeout = timeval(tv_sec: 1, tv_usec: 0)
    _ = setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &timeout, socklen_t(MemoryLayout<timeval>.size))
    return fd
}

@Test func listenerShutdownClosesAcceptedClientsAndReleasesHTTPWebSocketSignalRAndTLSPorts() async throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("listener-lifecycle-\(UUID())")
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = OriginStore(fileURL: directory.appendingPathComponent("origins.json"))
    let tls = try LocalCA(directory: directory.appendingPathComponent("tls")).sslContext()
    let httpPort = try unusedListenerPort()
    let http = HTTPServer(bridge: CTSignBridge(backend: FakeBackend()), port: httpPort, store: store)
    let ws = WSServer(ports: [0], pathPrefix: "/", store: store) { t, _ in t }
    let secure = WSServer(ports: [0], pathPrefix: "/", store: store, tls: tls) { t, _ in t }
    let hub = SignalRHub { _, _, _ in nil }
    let signalr = SignalRServer(port: 0, store: store, hub: hub)
    let lifecycles: [(@Sendable () async throws -> Int, @Sendable () async -> Void)] = [
        ({ try await http.start(); return httpPort }, { await http.stop() }),
        ({ try await ws.start() }, { await ws.stop() }),
        ({ try await secure.start() }, { await secure.stop() }),
        ({ try await signalr.start() }, { await signalr.stop() }),
    ]
    for (start, stop) in lifecycles {
        let port = try await start()
        let client = try connectIdleClient(port)
        // Also covers a client accepted while shutdown begins (before HTTP/TLS setup).
        await stop(); await stop() // idempotent: no double event-loop shutdown
        var byte: UInt8 = 0
        let count = recv(client, &byte, 1, 0)
        #expect(count == 0 || (count < 0 && errno == ECONNRESET))
        close(client)
        let replacement = WSServer(ports: [port], pathPrefix: "/", store: store) { t, _ in t }
        #expect(try await replacement.start() == port)
        await replacement.stop()
    }
}

@Test func switchingOffWebSocketClosesUpgradedConnectionAndSignalRInvalidatesSessions() async throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("listener-sessions-\(UUID())")
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = OriginStore(fileURL: directory.appendingPathComponent("origins.json"))
    let server = WSServer(ports: [0], pathPrefix: "/", store: store) { t, _ in t }
    let port = try await server.start()
    let session = URLSession(configuration: .ephemeral)
    let client = session.webSocketTask(with: URL(string: "ws://127.0.0.1:\(port)/")!)
    defer { client.cancel(); session.invalidateAndCancel() }
    client.resume()
    try await client.send(.string("fixture"))
    if case .string(let text) = try await client.receive() { #expect(text == "fixture") }
    await server.stop()
    do { _ = try await client.receive(); Issue.record("disabled WebSocket remained open") } catch {}
    let hub = SignalRHub { _, _, _ in nil }
    let signalr = SignalRServer(port: 0, store: store, hub: hub)
    _ = try await signalr.start()
    let response = await hub.negotiate(origin: "local")
    let json = try #require(JSONSerialization.jsonObject(with: Data(response.utf8)) as? [String: Any])
    let token = try #require(json["ConnectionToken"] as? String)
    #expect(await hub.isKnown(token))
    await signalr.stop()
    #expect(await hub.isKnown(token) == false)
}
