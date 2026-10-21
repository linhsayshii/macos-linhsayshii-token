import Testing
import TSShim

private func reencode(_ bytes: [UInt8]) -> [UInt8]? {
    var out = [UInt8](repeating: 0, count: bytes.count + 8)
    let n = bytes.withUnsafeBufferPointer { inp in
        out.withUnsafeMutableBufferPointer { o in
            ts_reencode(inp.baseAddress, bytes.count, o.baseAddress, o.count)
        }
    }
    return n == 0 ? nil : Array(out.prefix(n))
}

@Test func malformedSMReadBinaryIsExtended() {
    let data: [UInt8] = [0x97,0x02,0x00,0xEF,0x8E,0x08,0x9b,0x80,0xc9,0x7a,0x19,0x5e,0x65,0x17]
    let apdu: [UInt8] = [0x0C,0xB0,0x00,0x00,0x0E] + data + [0x00,0xEF]
    let got = reencode(apdu)
    let want: [UInt8] = [0x0C,0xB0,0x00,0x00,0x00,0x00,0x0E] + data + [0x00,0xEF]
    #expect(got == want)
}

@Test func validShortApduUntouched() {
    let apdu: [UInt8] = [0x00,0x84,0x00,0x00,0x08]
    #expect(reencode(apdu) == nil)
}

@Test func validSMShortWithoutTrailingLeUntouched() {
    let apdu: [UInt8] = [0x0C,0xA4,0x00,0x00,0x02,0x2F,0x01]
    #expect(reencode(apdu) == nil)
}

@Test func extendedLcWithOneByteLeGetsTwoByteLe() {
    // Seen on hardware (NC-CA SM signing): 0c2a9080 00 0112 <274 bytes> 20  -> Le widened to 0x0020.
    let data = [UInt8](repeating: 0x5A, count: 274)
    let apdu: [UInt8] = [0x0C,0x2A,0x90,0x80,0x00,0x01,0x12] + data + [0x20]
    #expect(reencode(apdu) == [0x0C,0x2A,0x90,0x80,0x00,0x01,0x12] + data + [0x00,0x20])
}

@Test func wellFormedExtendedApdusUntouched() {
    let data = [UInt8](repeating: 1, count: 300)
    #expect(reencode([0x0C,0x2A,0x90,0x80,0x00,0x01,0x2C] + data) == nil)               // no Le
    #expect(reencode([0x0C,0x2A,0x90,0x80,0x00,0x01,0x2C] + data + [0x00,0x00]) == nil) // proper 2-byte Le
}
