import Testing
import TSShim

@Test func shimLinks() {
    var out = [UInt8](repeating: 0, count: 8)
    let n = out.withUnsafeMutableBufferPointer { ts_reencode(nil, 0, $0.baseAddress, $0.count) }
    #expect(n == 0)
}
