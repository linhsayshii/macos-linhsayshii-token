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
    // NC-CA PSO signing: RSA padding produces 274 SM data bytes even when the
    // host's DigestInfo is only 51 bytes. The vendor appends a short Le (0x20).
    let data = [UInt8](repeating: 0x5A, count: 274)
    let header: [UInt8] = [0x0C,0x2A,0x90,0x80,0x00,0x01,0x12]
    let got = reencode(header + data + [0x20])
    #expect(got == header + data + [0x00,0x20])
}

@Test func wellFormedExtendedApdusUntouched() {
    let data = [UInt8](repeating: 1, count: 300)
    let header: [UInt8] = [0x0C,0x2A,0x90,0x80,0x00,0x01,0x2C]
    #expect(reencode(header + data) == nil)
    #expect(reencode(header + data + [0x00,0x20]) == nil)
    #expect(reencode(header + data + [0x00,0x00]) == nil)
}

@Test func extendedLcRepairPreservesSecureMessageAndChecksCapacity() {
    let data = (0..<274).map { UInt8($0 % 256) }
    let apdu: [UInt8] = [0x0C,0x2A,0x90,0x80,0x00,0x01,0x12] + data + [0x20]
    var out = [UInt8](repeating: 0xCC, count: apdu.count + 1)
    let n = apdu.withUnsafeBufferPointer { input in
        out.withUnsafeMutableBufferPointer { output in
            ts_reencode(input.baseAddress, input.count, output.baseAddress, apdu.count)
        }
    }
    #expect(n == 0)
    #expect(out.allSatisfy { $0 == 0xCC })
    let repaired = reencode(apdu)
    #expect(repaired?.dropLast(2) == apdu.dropLast())
    #expect(repaired?.suffix(2) == [0x00,0x20])
}

@Test func extendedLcMalformedOrNonSecureCommandsUntouched() {
    #expect(reencode([0x0C,0x2A,0x90,0x80,0x00,0x00]) == nil)
    #expect(reencode([0x0C,0x2A,0x90,0x80,0x00,0x00,0x00,0x20]) == nil)
    #expect(reencode([0x0C,0x2A,0x90,0x80,0x00,0x01,0x12,0x20]) == nil)
    #expect(reencode([0x00,0x2A,0x90,0x80,0x00,0x01,0x12] + [UInt8](repeating: 0x5A, count: 274) + [0x20]) == nil)
}
