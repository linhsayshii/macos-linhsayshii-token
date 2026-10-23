import Testing
@testable import Core

@Test func vnptAtrMapsToVnptModule() {
    let atr: [UInt8] = [0x3b,0x9f,0x95,0x81,0x31,0xfe,0x9f,0x00,0x66,0x46,0x53,0x05,
                        0x34,0x00,0x25,0x71,0xdf,0x00,0x00,0x32,0x00,0x00,0x20]
    let m = ModuleRegistry.lookup(atr: atr)
    #expect(m?.ca == "VNPT")
    #expect(m?.moduleName == "libvnptca_p11_v8.dylib")
}

@Test func nccaAtrByte19Is0x59() {
    var atr = FastCAProfile.atr
    atr[19] = 0x59
    atr[22] = atr[1..<22].reduce(0, ^)
    #expect(ModuleRegistry.lookup(atr: atr)?.ca == "NC-CA")
}

@Test func unknownCustomerByteIsNil() {
    var atr = [UInt8](repeating: 0, count: 23)
    atr[19] = 0xAB
    #expect(ModuleRegistry.lookup(atr: atr) == nil)
}

@Test func shortAtrIsNil() {
    #expect(ModuleRegistry.lookup(atr: [0x3b, 0x9f]) == nil)
}

@Test func efyRequiresExactProfileAndScopesTokensToTheirPhysicalReader() throws {
    let module = try #require(ModuleRegistry.lookup(atr: EfyProfile.atr))
    #expect(module.ca == "EFY-CA" && module.moduleName == "EFY-ESPK")
    #expect(module.backend == .efy && module.arch == .universal)
    #expect(module.isExperimental && module.tokenScope == .reader)
    for index in EfyProfile.atr.indices {
        var other = EfyProfile.atr; other[index] ^= 1
        #expect(ModuleRegistry.lookup(atr: other)?.backend != .efy)
    }
    #expect(ModuleRegistry.lookup(atr: Array(EfyProfile.atr.dropLast())) == nil)
    let token = TokenInfo(slot: 2, reader: "EFY reader", serial: "EFY-test", label: "EFY-CA", flags: [])
    let other = TokenInfo(slot: 0, reader: "Other", serial: "OTHER", label: "ESPK", flags: [])
    #expect(module.tokensForReader(token.reader, from: [other, token]) == [token])
    #expect(module.tokensForReader("missing", from: [token]).isEmpty)
    #expect(ModuleRegistry.lookup(atr: FastCAProfile.atr)?.backend == .fastca)
    #expect(ModuleRegistry.lookup(atr: OneCAProfile.atr)?.backend == .oneca)
}

@Test func onecaUsesExactLongmaiProfileAndFailsClosedForAmbiguousReaders() throws {
    let module = try #require(ModuleRegistry.lookup(atr: OneCAProfile.atr))
    #expect(module.backend == .oneca)
    #expect(module.arch == .universal)
    #expect(module.isExperimental)
    #expect(module.tokenScope == .reader)
    var other = OneCAProfile.atr
    other[22] ^= 1
    #expect(ModuleRegistry.lookup(atr: other) == nil)
    let token = TokenInfo(slot: 0, reader: "CryptoIDA PKCS11 Module 2.0 0", serial: "ONE-test", label: "OneCA", flags: [])
    let reader = (reader: "Longmai mToken OneCAV3", atr: OneCAProfile.atr)
    let bound = OneCAProfile.bind(readers: [reader], tokens: [token])
    #expect(bound.first?.reader == reader.reader)
    #expect(module.tokensForReader(reader.reader, from: bound) == bound)
    #expect(OneCAProfile.bind(readers: [reader, (reader.reader + " 1", other)], tokens: [token]).isEmpty)
    #expect(OneCAProfile.bind(readers: [reader], tokens: [token, token]).isEmpty)
    #expect(OneCAProfile.bind(readers: [("Other", reader.atr)], tokens: [token]).isEmpty)
}

@Test func fastcaUsesNativeBackendWithoutCapturingOtherReaders() throws {
    let atr: [UInt8] = [0x3b,0x9f,0x95,0x81,0x31,0xfe,0x9f,0x00,0x66,0x46,0x53,0x05,
                        0x10,0x52,0x39,0x71,0xdf,0x00,0x00,0x69,0x00,0x00,0x11]
    let module = try #require(ModuleRegistry.lookup(atr: atr))
    #expect(module.ca == "FastCA")
    #expect(module.moduleName == "FastCA-ESPK")
    #expect(module.backend == .fastca)
    #expect(module.arch == .universal)
    #expect(module.isExperimental)
    let fastca = TokenInfo(slot: 2, reader: "FT ePass2003Auto 05", serial: "FAST", label: "HYP2003", flags: [])
    let other = TokenInfo(slot: 1, reader: "FT ePass2003Auto", serial: "OTHER", label: "HYP2003", flags: [])
    let unknownReader = TokenInfo(slot: 3, reader: "ES SLOT 3", serial: "UNKNOWN", label: "HYP2003", flags: [])
    #expect(module.tokensForReader(fastca.reader, from: [other, fastca, unknownReader]) == [fastca])
    #expect(module.tokensForReader("absent", from: [fastca, unknownReader]).isEmpty)
    // A single unrelated token must not be accepted as a fallback match.
    #expect(module.tokensForReader(fastca.reader, from: [other]).isEmpty)
    var otherProfile = atr
    otherProfile[12] ^= 1
    #expect(ModuleRegistry.lookup(atr: otherProfile) == nil)
    #expect(ModuleRegistry.lookup(atr: Array(atr.dropLast())) == nil)
}

@Test func fastcaSupportsBothMeasuredProfilesAndRejectsNearMatches() throws {
    for atr in FastCAProfile.supportedATRs {
        #expect(ModuleRegistry.lookup(atr: atr)?.backend == .fastca)
        for index in atr.indices {
            var other = atr; other[index] ^= 1
            #expect(!FastCAProfile.matches(atr: other))
            #expect(ModuleRegistry.lookup(atr: other)?.backend != .fastca)
            // Other issuers still use their existing customer-byte routing.
            if index != 19 { #expect(ModuleRegistry.lookup(atr: other) == nil) }
        }
        #expect(!FastCAProfile.matches(atr: Array(atr.dropLast())))
    }
    #expect(!FastCAProfile.matches(atr: EfyProfile.atr))
}
