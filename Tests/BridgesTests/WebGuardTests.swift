import Testing
import Foundation
@testable import Bridges

private let guardian = WebGuard(port: 32001)
private let allow = OriginAllowlist.defaults

@Test func rebindingHostRejected() {
    #expect(guardian.check(host: "evil.com:32001", origin: nil, allowlist: allow) == .badHost)
    #expect(guardian.check(host: "127.0.0.1:9999", origin: nil, allowlist: allow) == .badHost)
    #expect(guardian.check(host: nil, origin: nil, allowlist: allow) == .badHost)
}

@Test func localhostAndAllowedOriginPass() {
    #expect(guardian.check(host: "localhost:32001", origin: nil, allowlist: allow) == .ok(origin: nil))
    let o = "https://thuedientu.gdt.gov.vn"
    #expect(guardian.check(host: "127.0.0.1:32001", origin: o, allowlist: allow) == .ok(origin: o))
    let h = guardian.corsHeaders(origin: o, allowlist: allow)
    #expect(h["Access-Control-Allow-Origin"] == o)
    #expect(h["Access-Control-Allow-Private-Network"] == "true")
}

@Test func unknownOriginRejectedNoCORS() {
    let o = "https://evil.example"
    #expect(guardian.check(host: "127.0.0.1:32001", origin: o, allowlist: allow) == .unknownOrigin(o))
    #expect(guardian.corsHeaders(origin: o, allowlist: allow).isEmpty)
}

@Test func originStorePersistsAndDedupesPending() async throws {
    let url = FileManager.default.temporaryDirectory.appendingPathComponent("os-\(UUID())/origins.json")
    let s = OriginStore(fileURL: url)
    #expect(await s.allowlist().contains("https://thuedientu.gdt.gov.vn"))
    #expect(await !s.allowlist().contains("https://foo.example"))
    await s.notePending("https://foo.example"); await s.notePending("https://foo.example")
    #expect(await s.takePending() == ["https://foo.example"])
    try await s.add("foo.example")
    #expect(await OriginStore(fileURL: url).allowlist().contains("https://foo.example"))
    try await s.remove("foo.example")
    #expect(await !OriginStore(fileURL: url).allowlist().contains("https://foo.example"))
    await #expect(throws: OriginStore.StoreError.self) { try await s.remove("dichvucong.gov.vn") }
}

@Test func preflightEchoesRequestedHeadersForAllowedOrigin() {
    let o = "https://thuedientu.gdt.gov.vn"
    let h = guardian.preflightHeaders(origin: o, allowlist: allow, requestedHeaders: "content-type,x-xsrf-token")
    #expect(h["Access-Control-Allow-Headers"] == "content-type,x-xsrf-token")
    #expect(h["Access-Control-Allow-Origin"] == o && h["Access-Control-Allow-Private-Network"] == "true")
    #expect(h["Access-Control-Allow-Methods"]?.contains("POST") == true)
}

@Test func preflightFallsBackAndRejectsUnknownOrigin() {
    let o = "https://thuedientu.gdt.gov.vn"
    #expect(guardian.preflightHeaders(origin: o, allowlist: allow, requestedHeaders: nil)["Access-Control-Allow-Headers"] == "Content-Type")
    #expect(guardian.preflightHeaders(origin: o, allowlist: allow, requestedHeaders: "x\r\nEvil: 1")["Access-Control-Allow-Headers"] == "Content-Type")
    #expect(guardian.preflightHeaders(origin: "https://evil.example", allowlist: allow, requestedHeaders: "x-a").isEmpty)
}
