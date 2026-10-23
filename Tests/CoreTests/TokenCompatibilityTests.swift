import Foundation
import Testing
@testable import Core

private func variant(_ source: [UInt8], changes: [(Int, UInt8)]) -> [UInt8] {
    var bytes = source
    for (index, value) in changes { bytes[index] = value }
    bytes[22] = bytes[1..<22].reduce(0, ^)
    return bytes
}

@Test func atrParserChecksFramingHistoricalLengthAndChecksum() throws {
    #expect(TokenATR([0x3b,0])?.protocols == [0])
    #expect(TokenATR([0x3b,2,0xaa,0xbb])?.historicalBytes == [0xaa,0xbb])
    #expect(TokenATR([0x3b,0x80,1,0x81])?.protocols == [1])
    let observed = try #require(TokenATR(FastCAProfile.atr0631))
    #expect(observed.historicalBytes.count == 15 && observed.protocols == [1,1])
    let malformed: [[UInt8]] = [[], [0x3b], [0x3b,0x80], [0x3b,0x80,1], [0x3b,0,0], [0,0], [0x3b,0x80,1,0]]
    for bytes in malformed {
        #expect(TokenATR(bytes) == nil)
        #expect(ModuleRegistry.candidates(atr: bytes).isEmpty)
    }
}

@Test func firmwareFamilyVariantsReachPublicDiscoveryWithoutInheritingPINProtocol() {
    for observed in [FastCAProfile.atr, FastCAProfile.atr0631, EfyProfile.atr] {
        for offset in [12,13,14,20,21] {
            for value in UInt8.min...UInt8.max {
                let changed = variant(observed, changes: [(offset,value)])
                #expect(ESPKFamily.matches(atr: changed))
                #expect(ModuleRegistry.lookup(atr: changed)?.backend == (observed[19] == 0x51 ? .efy : .fastca))
                let measured = observed[19] == 0x51 ? changed == EfyProfile.atr : FastCAProfile.supportedATRs.contains(changed)
                #expect((observed[19] == 0x51 ? EfyProfile.hasVerifiedPINProtocol(atr: changed) : FastCAProfile.hasVerifiedPINProtocol(atr: changed)) == measured)
            }
        }
    }
    let wrongFamily = variant(FastCAProfile.atr, changes: [(8,0x65)])
    #expect(!ESPKFamily.matches(atr: wrongFamily))
    #expect(ModuleRegistry.lookup(atr: wrongFamily) == nil)
}

@Test func providerCandidatesKeepIssuerAndOEMSeparateAndBoundFallbacks() throws {
    // OneCA V2's documented EnterSafe personalization is not Longmai V3.
    let onecaV2 = variant(FastCAProfile.atr, changes: [(12,0x10),(13,0x06),(14,0x31),(19,0x81)])
    #expect(ModuleRegistry.lookup(atr: onecaV2)?.backend == .espkDiscovery)
    #expect(ModuleRegistry.lookup(atr: OneCAProfile.atr)?.backend == .oneca)
    let onecaV1: [UInt8] = [0x3b,0x9f,0x11,0x81,0x31,0xfe,0x9f,0,0x6a,0x6d,0x54,0x6f,
        0x6b,0x65,0x6e,0x2d,0x5a,0,5,0x81,0x90,0,0x60]
    #expect(ModuleRegistry.candidates(atr: onecaV1).isEmpty)
    #expect(TokenCompatibility.knownUnsupportedModel(atr: onecaV1)?.issuer == "OneCA V1")
    #expect(TokenCompatibility.knownUnsupportedModel(atr: OneCAProfile.atr) == nil)
    for customer in [UInt8(0x59),0x32,0x61,0x72] {
        let atr = variant(FastCAProfile.atr, changes: [(19,customer)])
        let providers = ModuleRegistry.candidates(atr: atr)
        #expect(providers.map(\.backend) == [.pkcs11,.espkDiscovery])
    }
    let unknownIssuer = variant(FastCAProfile.atr, changes: [(19,0xab)])
    #expect(ModuleRegistry.lookup(atr: unknownIssuer)?.ca == "ESPK")
    var badChecksum = unknownIssuer; badChecksum[22] ^= 1
    #expect(ModuleRegistry.candidates(atr: badChecksum).isEmpty)
    #expect(TokenCompatibility.providers.count >= 5)
}

@Test func helperFailuresRoundTripWithoutLosingMachineReadableCause() throws {
    let response = HelperResponse.failure(TokenFailure(code: .runtimeUnavailable, message: "Fixture driver missing"))
    #expect(try JSONDecoder().decode(HelperResponse.self, from: JSONEncoder().encode(response)) == response)
}

@Test func unseenATRCanUseOnlyRegisteredVendorProvidersBoundToItsReader() {
    let unseen: [UInt8] = [0x3b,0]
    #expect(ModuleRegistry.lookup(atr: unseen) == nil)
    let candidates = ModuleRegistry.candidates(atr: unseen, includeVendorDiscovery: true)
    #expect(candidates.count == 4 && candidates.allSatisfy { $0.backend == .pkcs11 && $0.tokenScope == .reader && $0.isExperimental })
    let other = TokenInfo(slot: 1, reader: "Other device", serial: "OTHER", label: "Fixture", flags: [])
    let matching = TokenInfo(slot: 2, reader: "New reader", serial: "MATCH", label: "Fixture", flags: [])
    for provider in candidates {
        #expect(provider.tokensForReader("New reader", from: [other]).isEmpty)
        #expect(provider.tokensForReader("New reader", from: [other,matching]) == [matching])
    }
    #expect(ModuleRegistry.candidates(atr: [0x3b,0x80], includeVendorDiscovery: true).isEmpty)
    #expect(ModuleRegistry.candidates(atr: FastCAProfile.atr, includeVendorDiscovery: true).map(\.backend) == [.fastca])
}
