import Testing
@testable import Bridges

@Test func catalogCoversEveryServiceAndBothAlternates() throws {
    let endpoints = try BridgeCatalog.endpoints()
    #expect(Set(endpoints.map(\.kind)) == Set(BridgeKind.allCases))
    #expect(BridgeService.allCases.map(\.name) == ["CTSigningHub", "eSigner", "Minvoice", "VNPT-CA"])
    #expect(endpoints.filter { $0.kind.service == .esigner }.map(\.port) == [8768,8769])
    #expect(endpoints.filter { $0.kind.service == .vnpt }.map(\.port) == [4433,4434])
    #expect(endpoints.map(\.port) == [32001,8768,8769,4433,4434,16080])
    #expect(endpoints.filter(\.tls).map(\.port) == [4433,4434])
    #expect(try BridgeCatalog.endpoints(offset: 100).map(\.port) == endpoints.map { $0.port + 100 })
    #expect(throws: BridgeCatalog.ConfigurationError.self) { try BridgeCatalog.endpoints(offset: -1) }
    #expect(throws: BridgeCatalog.ConfigurationError.self) { try BridgeCatalog.endpoints(offset: 65535) }
}
