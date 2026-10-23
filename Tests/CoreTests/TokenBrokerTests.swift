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

@Test(arguments: ["fastca", "efy"]) func nativeESPKBrokerNeedsNoVendorModuleAndPreservesRuntimeErrors(backend: String) async throws {
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: dir) }
    let helper = dir.appendingPathComponent("helper.sh")
    let script = """
    #!/bin/sh
    [ "$1" = --backend ] && [ "$2" = \(backend) ] || exit 21
    [ -z "${DYLD_INSERT_LIBRARIES:-}" ] || exit 22
    [ "$OPENSC_DEBUG" = 0 ] || exit 23
    while IFS= read -r line; do
      printf '%s\\n' '{"error":{"_0":"OpenSC runtime unavailable"}}'
    done
    """
    try script.write(to: helper, atomically: true, encoding: .utf8)
    try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: helper.path)
    let broker = TokenBroker(helperURL: helper, shimURL: dir.appendingPathComponent("absent-shim"), moduleDirs: [])
    let module = try #require(ModuleRegistry.lookup(atr: backend == "efy" ? EfyProfile.atr : FastCAProfile.atr))
    #expect(try await broker.request(.listTokens, module: module) == .error("OpenSC runtime unavailable"))
    do {
        _ = try await broker.sign(module: module, serial: "fixture", certId: "01",
                                  mech: .rsaPKCS, dataB64: "AA==", pin: "test fixture only")
        Issue.record("Expected missing-runtime error")
    } catch {
        #expect(error as? TokenBroker.SignError == .card("OpenSC runtime unavailable"))
    }
}

@Test func discoveryProbeScopesOnePhysicalReaderAndPreservesTypedRuntimeFailure() async throws {
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent(UUID().uuidString)
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
    defer { try? FileManager.default.removeItem(at: dir) }
    let helper = dir.appendingPathComponent("probe.sh")
    let script = """
    #!/bin/sh
    [ "$1" = --backend ] && [ "$2" = espk-discovery ] || exit 21
    [ "$3" = --reader ] && [ "$4" = 'Reader 17 with spaces' ] || exit 22
    [ -z "${DYLD_INSERT_LIBRARIES:-}" ] && [ "$OPENSC_DEBUG" = 0 ] || exit 23
    read line
    printf '%s\\n' '{"failure":{"_0":{"code":"runtimeUnavailable","message":"Fixture runtime missing"}}}'
    """
    try script.write(to: helper, atomically: true, encoding: .utf8)
    try FileManager.default.setAttributes([.posixPermissions: 0o755], ofItemAtPath: helper.path)
    let broker = TokenBroker(helperURL: helper, shimURL: helper, moduleDirs: [])
    let response = try await broker.request(.listTokens, module: ModuleRegistry.espkDiscovery, reader: "Reader 17 with spaces")
    #expect(response == .failure(TokenFailure(code: .runtimeUnavailable, message: "Fixture runtime missing")))
}
