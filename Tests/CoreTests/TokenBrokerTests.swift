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
    // Put a dummy module file in a search dir so resolve() finds it.
    let dir = helper.deletingLastPathComponent()
    let moduleName = "x.dylib"
    FileManager.default.createFile(atPath: dir.appendingPathComponent(moduleName).path, contents: Data())
    let broker = TokenBroker(helperURL: helper, shimURL: helper, moduleDirs: [dir])
    let module = ModuleInfo(ca: "VNPT", moduleName: moduleName, arch: .universal)
    let resp = try await broker.request(.listTokens, module: module)
    #expect(resp == .tokens([TokenInfo(slot: 1, reader: "R", serial: "S", label: "L", flags: [])]))
}
