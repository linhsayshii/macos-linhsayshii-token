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

private func chunks(_ apdu: [UInt8], max: Int = 200) -> [[UInt8]] {
    var res: [[UInt8]] = [], off = 0
    while true {
        var out = [UInt8](repeating: 0, count: 300), dl = 0, last: Int32 = 0
        let n = apdu.withUnsafeBufferPointer { a in
            out.withUnsafeMutableBufferPointer { o in ts_chain_chunk(a.baseAddress, apdu.count, off, max, o.baseAddress, o.count, &dl, &last) }
        }
        if n == 0 { return res }
        res.append(Array(out.prefix(n))); off += dl
        if last != 0 { return res }
    }
}

@Test func extendedSMApduIsChained() {
    let data = (0..<266).map { UInt8($0 & 0xFF) }
    let apdu: [UInt8] = [0x0C,0x2A,0x90,0x80,0x00,0x01,0x0A] + data + [0x00,0x00]
    let c = chunks(apdu)
    #expect(c.count == 2)
    #expect(Array(c[0].prefix(5)) == [0x1C,0x2A,0x90,0x80,200] && Array(c[0].dropFirst(5)) == Array(data.prefix(200)))
    #expect(Array(c[1].prefix(5)) == [0x0C,0x2A,0x90,0x80,66])
    #expect(Array(c[1].dropFirst(5)) == Array(data.dropFirst(200)) + [0x00])   // Le 0x0000 -> short 0x00
}

@Test func smallOrShortApdusAreNotChained() {
    #expect(chunks([0x0C,0x2A,0x90,0x80,0x02,0xAA,0xBB]).isEmpty)
    let ext200: [UInt8] = [0x0C,0x2A,0x90,0x80,0x00,0x00,0xC8] + [UInt8](repeating: 1, count: 200)
    #expect(chunks(ext200).isEmpty)           // Lc <= 255 goes through the normal path
    #expect(chunks([0x00,0x84,0x00,0x00,0x08]).isEmpty)
}
