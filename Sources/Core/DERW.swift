import Foundation

/// Minimal DER writer for the few fixed structures CMS needs. Hand-built rather
/// than a generic ASN.1 model: the shapes are fixed and tests (openssl) check them.
enum DERW {
    static func tlv(_ tag: UInt8, _ content: Data) -> Data {
        var out = Data([tag])
        let n = content.count
        if n < 0x80 { out.append(UInt8(n)) }
        else {
            var b: [UInt8] = []; var v = n
            while v > 0 { b.insert(UInt8(v & 0xff), at: 0); v >>= 8 }
            out.append(0x80 | UInt8(b.count)); out.append(contentsOf: b)
        }
        return out + content
    }
    static func seq(_ parts: Data...) -> Data { tlv(0x30, parts.reduce(Data(), +)) }
    static func set(_ parts: [Data]) -> Data { tlv(0x31, parts.sorted { $0.lexicographicallyPrecedes($1) }.reduce(Data(), +)) }
    static func oid(_ s: String) -> Data {
        let a = s.split(separator: ".").map { UInt64($0)! }
        var body = Data([UInt8(a[0] * 40 + a[1])])
        for v in a.dropFirst(2) {
            var chunk: [UInt8] = [UInt8(v & 0x7f)]; var x = v >> 7
            while x > 0 { chunk.insert(UInt8(x & 0x7f) | 0x80, at: 0); x >>= 7 }
            body.append(contentsOf: chunk)
        }
        return tlv(0x06, body)
    }
    static let null = Data([0x05, 0x00])
    static func int(_ v: Int) -> Data { tlv(0x02, Data([UInt8(v)])) }
    static func octets(_ d: Data) -> Data { tlv(0x04, d) }
    static func utcTime(_ date: Date) -> Data {
        let f = DateFormatter(); f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "UTC"); f.dateFormat = "yyMMddHHmmss'Z'"
        return tlv(0x17, Data(f.string(from: date).utf8))
    }
}
