import Testing
import Foundation
@testable import Core

private func fakeHelper() throws -> URL {
    let url = FileManager.default.temporaryDirectory.appendingPathComponent("fakehelper-\(UUID()).sh")
    // Matches Swift's synthesized enum Codable: {"tokens":{"_0":[ TokenInfo... ]}}
    let script = """
    #!/bin/sh
    read line
    printf '{"tokens":{"_0":[{"slot":1,"reader":"R","serial":"S","label":"L","flags":[]}]}}\\n'
    """
    try script.write(to: url, atomically: true, encoding: .utf8)
    try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: url.path)
    return url
}

@Test func brokerSpawnsHelperAndParsesResponse() async throws {
    let helper = try fakeHelper()
    let broker = TokenBroker(helperURL: helper, shimURL: helper, moduleDir: URL(fileURLWithPath: "/tmp"))
    let module = ModuleInfo(ca: "VNPT", moduleName: "x.dylib", arch: .universal)
    let resp = try await broker.request(.listTokens, module: module)
    #expect(resp == .tokens([TokenInfo(slot: 1, reader: "R", serial: "S", label: "L", flags: [])]))
}
