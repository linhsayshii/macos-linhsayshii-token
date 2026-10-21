import Testing
@testable import Core

@Test func sha256DigestInfoHasCorrectPrefixAndLength() throws {
    let digest = [UInt8](repeating: 0xAB, count: 32)
    let d = try DigestInfo.wrap(digest, .sha256)
    let prefix: [UInt8] = [0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,
                           0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20]
    #expect(Array(d.prefix(prefix.count)) == prefix)
    #expect(d.count == prefix.count + 32)
    #expect(Array(d.suffix(32)) == digest)
}

@Test func sha256RejectsWrongLength() {
    #expect(throws: (any Error).self) {
        _ = try DigestInfo.wrap([UInt8](repeating: 0, count: 31), .sha256)
    }
}

@Test func sha1DigestInfoLength() throws {
    let d = try DigestInfo.wrap([UInt8](repeating: 1, count: 20), .sha1)
    #expect(d.count == 15 + 20)
}
