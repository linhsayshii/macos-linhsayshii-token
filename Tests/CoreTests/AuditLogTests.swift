import Testing
import Foundation
@testable import Core

@Test func auditStoresHashNotContent() async throws {
    let url = FileManager.default.temporaryDirectory.appendingPathComponent("audit-\(UUID())/audit.jsonl")
    let log = AuditLog(fileURL: url)
    await log.append(origin: "https://a.gdt.gov.vn", bridge: "esigner", certSerial: "01", operation: "signxml",
                     input: Data("SECRET-DOC".utf8), result: "ok")
    await log.append(origin: "https://b.gdt.gov.vn", bridge: "vnpt", certSerial: "02", operation: "signcms",
                     input: Data("x".utf8), result: "denied")
    let recent = await log.recent(1)
    #expect(recent.first?.origin == "https://b.gdt.gov.vn")
    let raw = try String(contentsOf: url, encoding: .utf8)
    #expect(!raw.contains("SECRET-DOC"))
    #expect((await log.recent(2)).first?.inputSHA256.count == 64)
    let perm = try FileManager.default.attributesOfItem(atPath: url.path)[.posixPermissions] as? Int
    #expect(perm == 0o600)
}
