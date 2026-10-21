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
    var atr = [UInt8](repeating: 0, count: 23)
    atr[19] = 0x59
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
