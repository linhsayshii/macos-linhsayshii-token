import Testing
import Foundation
@testable import Bridges
import Core

private actor OriginBackend: SigningBackend {
    var origins: [String] = []
    func certificates() async -> [CertInfo] { [] }
    func sign(serial: String, digestB64: String) async throws -> String { throw CancellationError() }
    func sign(serial: String, digestB64: String, origin: String) async throws -> String {
        origins.append(origin)
        return "fixture-signature"
    }
}

private func availableHTTPPort() -> Int {
    let fd = socket(AF_INET, SOCK_STREAM, 0); defer { close(fd) }
    var address = sockaddr_in(); address.sin_family = sa_family_t(AF_INET); address.sin_addr.s_addr = inet_addr("127.0.0.1")
    var count = socklen_t(MemoryLayout<sockaddr_in>.size)
    _ = withUnsafeMutablePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, count) } }
    _ = withUnsafeMutablePointer(to: &address) { $0.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &count) } }
    return Int(UInt16(bigEndian: address.sin_port))
}

@Test func CTSignHTTPForwardsAllowedOriginAndBlocksUnknownOriginBeforeSigning() async throws {
    let backend = OriginBackend(), port = availableHTTPPort()
    let server = HTTPServer(bridge: CTSignBridge(backend: backend), port: port, allowlist: .defaults)
    try await server.start()
    defer { Task { await server.stop() } }
    let session = URLSession(configuration: .ephemeral)
    defer { session.invalidateAndCancel() }
    let origin = "https://thuedientu.gdt.gov.vn"
    var request = URLRequest(url: URL(string: "http://127.0.0.1:\(port)/api/hubclient/signhash")!)
    request.httpMethod = "POST"
    request.httpBody = try JSONSerialization.data(withJSONObject: ["serinumber": "fixture", "hash": [["DLieuHash": Data(count: 32).base64EncodedString()]]])
    request.setValue(origin, forHTTPHeaderField: "Origin")
    request.setValue("application/json", forHTTPHeaderField: "Content-Type")
    let (_, response) = try await session.data(for: request)
    #expect((response as? HTTPURLResponse)?.statusCode == 200)
    #expect(await backend.origins == [origin])
    request.setValue("https://evil.invalid", forHTTPHeaderField: "Origin")
    let (_, blocked) = try await session.data(for: request)
    #expect((blocked as? HTTPURLResponse)?.statusCode == 403)
    #expect(await backend.origins == [origin])
}

@Test func CTSignSharedOriginStoreUpdatesLiveAndEchoesPreflightHeaders() async throws {
    let directory = FileManager.default.temporaryDirectory.appendingPathComponent("origins-\(UUID())")
    defer { try? FileManager.default.removeItem(at: directory) }
    let store = OriginStore(fileURL: directory.appendingPathComponent("origins.json")), port = availableHTTPPort()
    let server = HTTPServer(bridge: CTSignBridge(backend: OriginBackend()), port: port, store: store)
    try await server.start()
    defer { Task { await server.stop() } }
    let session = URLSession(configuration: .ephemeral)
    defer { session.invalidateAndCancel() }
    var request = URLRequest(url: URL(string: "http://127.0.0.1:\(port)/api/SignHash/Version")!)
    request.setValue("https://approved.example", forHTTPHeaderField: "Origin")
    let (_, blocked) = try await session.data(for: request)
    #expect((blocked as? HTTPURLResponse)?.statusCode == 403)
    #expect(await store.takePending() == ["https://approved.example"])
    try await store.add("approved.example")
    request.httpMethod = "OPTIONS"
    request.setValue("content-type,x-xsrf-token", forHTTPHeaderField: "Access-Control-Request-Headers")
    let (_, allowed) = try await session.data(for: request)
    let response = try #require(allowed as? HTTPURLResponse)
    #expect(response.statusCode == 200)
    #expect(response.value(forHTTPHeaderField: "Access-Control-Allow-Headers") == "content-type,x-xsrf-token")
}
