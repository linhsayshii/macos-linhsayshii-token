import Foundation
import Core
import CMinvoiceZIP

/// Bounded single-file ZIP reader. No extraction paths or files on disk.
/// ZIP64, encryption, multi-disk and auxiliary entries are not supported yet.
enum MinvoiceZIP {
    static func extract(_ bytes: Data) throws -> (id: UUID, xml: Data) {
        let b = [UInt8](bytes)
        guard (22...(2 << 20)).contains(b.count) else { throw MinvoiceError.invalidInput }
        func u16(_ p: Int) throws -> Int {
            guard p >= 0, p <= b.count - 2 else { throw MinvoiceError.invalidInput }
            return Int(b[p]) | Int(b[p+1]) << 8
        }
        func u32(_ p: Int) throws -> Int {
            let low = try u16(p), high = try u16(p+2)
            return low | high << 16
        }
        let end = b.count - 22
        guard try u32(end) == 0x06054b50, try u16(end+4) == 0, try u16(end+6) == 0,
              try u16(end+8) == 1, try u16(end+10) == 1, try u16(end+20) == 0 else { throw MinvoiceError.unsupported }
        let central = try u32(end+16), centralSize = try u32(end+12)
        guard central + centralSize == end, try u32(central) == 0x02014b50,
              try u16(central+34) == 0, try u32(central+42) == 0 else { throw MinvoiceError.invalidInput }
        let flags = try u16(central+8), method = try u16(central+10)
        let checksum = try u32(central+16), compressed = try u32(central+20), size = try u32(central+24)
        let nameLength = try u16(central+28), extraLength = try u16(central+30), commentLength = try u16(central+32)
        let attributes = try u32(central+38) >> 16
        guard flags & ~0x808 == 0, method == 0 || method == 8, (1...(8 << 20)).contains(size),
              compressed > 0, compressed <= 2 << 20,
              attributes & 0xf000 == 0 || attributes & 0xf000 == 0x8000,
              nameLength == 40, central + 46 + nameLength + extraLength + commentLength == end else { throw MinvoiceError.unsupported }
        let name = Array(b[(central+46)..<(central+46+nameLength)])
        let filename = String(decoding: name, as: UTF8.self)
        guard filename.hasSuffix(".xml"), let entryID = UUID(uuidString: String(filename.dropLast(4))),
              filename.lowercased() == entryID.uuidString.lowercased() + ".xml",
              try u32(0) == 0x04034b50, try u16(6) == flags, try u16(8) == method,
              try u16(26) == nameLength else { throw MinvoiceError.invalidInput }
        let dataStart = try 30 + nameLength + u16(28)
        let dataEnd = dataStart + compressed
        guard dataStart >= 30, dataEnd <= central, Array(b[30..<(30+nameLength)]) == name else { throw MinvoiceError.invalidInput }
        if flags & 8 == 0 {
            guard try u32(14) == checksum, try u32(18) == compressed, try u32(22) == size, dataEnd == central else { throw MinvoiceError.invalidInput }
        } else {
            let descriptor = (try u32(dataEnd)) == 0x08074b50 ? dataEnd + 4 : dataEnd
            guard descriptor + 12 == central, try u32(descriptor) == checksum,
                  try u32(descriptor+4) == compressed, try u32(descriptor+8) == size else { throw MinvoiceError.invalidInput }
        }
        let input = Array(b[dataStart..<dataEnd])
        var output = [UInt8](repeating: 0, count: size)
        if method == 0 {
            guard size == compressed else { throw MinvoiceError.invalidInput }; output = input
        } else {
            guard mvzip_inflate(input, input.count, &output, output.count) == 0 else { throw MinvoiceError.invalidInput }
        }
        guard Int(mvzip_crc(output, output.count)) == checksum else { throw MinvoiceError.invalidInput }
        return (entryID, Data(output))
    }
}
