import Foundation
import CPCSC

/// PC/SC reader + ATR enumeration, used to route by ATR before any module loads.
/// All winscard calls live in the CPCSC C shim; this is a thin wrapper.
public struct ReaderScanner {
    public init() {}

    public func readers() -> [(reader: String, atr: [UInt8])] {
        var buf = [cpcsc_reader](repeating: cpcsc_reader(), count: 32)
        let n = buf.withUnsafeMutableBufferPointer { cpcsc_list_readers($0.baseAddress, Int32($0.count)) }
        guard n > 0 else { return [] }
        return (0..<Int(n)).map { i in
            let rec = buf[i]
            let name = withUnsafeBytes(of: rec.name) { raw -> String in
                let bytes = raw.prefix(while: { $0 != 0 }).map { UInt8($0) }
                return String(decoding: bytes, as: UTF8.self)
            }
            let len = min(Int(rec.atr_len), 33)
            let atr = withUnsafeBytes(of: rec.atr) { raw in (0..<len).map { raw[$0] } }
            return (reader: name, atr: atr)
        }
    }
}
