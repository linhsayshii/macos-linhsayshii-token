import Foundation
import Core
import CMinvoiceZIP

/// Bounded in-memory ZIP reader; names never become filesystem paths.
/// Supports stored/deflated GUID.xml entries; rejects ZIP64, encryption and multi-disk.
enum MinvoiceZIP {
    struct Entry: Sendable { let id: UUID; let xml: Data }
    static func extract(_ bytes: Data) throws -> (id: UUID, xml: Data) {
        let entries = try extractAll(bytes)
        guard entries.count == 1, let entry = entries.first else { throw MinvoiceError.unsupported }
        return (entry.id, entry.xml)
    }
    static func extractAll(_ bytes: Data) throws -> [Entry] {
        guard (22...MinvoiceBatchLimits.archiveBytes).contains(bytes.count) else { throw MinvoiceError.invalidInput }
        let b = [UInt8](bytes)
        func u16(_ p: Int) throws -> Int {
            guard p >= 0, p <= b.count - 2 else { throw MinvoiceError.invalidInput }
            return Int(b[p]) | Int(b[p+1]) << 8
        }
        func u32(_ p: Int) throws -> Int { try u16(p) | u16(p+2) << 16 }
        let end = b.count - 22
        let count = try u16(end+10)
        guard try u32(end) == 0x06054b50, try u16(end+4) == 0, try u16(end+6) == 0,
              try u16(end+8) == count, (1...MinvoiceBatchLimits.maxDocuments).contains(count),
              try u16(end+20) == 0 else { throw MinvoiceError.unsupported }
        let central = try u32(end+16), centralSize = try u32(end+12)
        guard central >= 0, central + centralSize == end else { throw MinvoiceError.invalidInput }
        var cursor = central, localCursor = 0, expanded = 0
        var ids = Set<UUID>(), entries: [Entry] = []
        for _ in 0..<count {
            guard cursor + 46 <= end, try u32(cursor) == 0x02014b50,
                  try u16(cursor+34) == 0 else { throw MinvoiceError.invalidInput }
            let flags = try u16(cursor+8), method = try u16(cursor+10)
            let checksum = try u32(cursor+16), compressed = try u32(cursor+20), size = try u32(cursor+24)
            let nameLength = try u16(cursor+28), extraLength = try u16(cursor+30), commentLength = try u16(cursor+32)
            let attributes = try u32(cursor+38) >> 16, local = try u32(cursor+42)
            let next = cursor + 46 + nameLength + extraLength + commentLength
            expanded += size
            guard flags & ~0x808 == 0, method == 0 || method == 8,
                  (1...MinvoiceBatchLimits.documentBytes).contains(size), expanded <= MinvoiceBatchLimits.expandedBytes,
                  compressed > 0, compressed <= MinvoiceBatchLimits.archiveBytes,
                  attributes & 0xf000 == 0 || attributes & 0xf000 == 0x8000,
                  nameLength == 40, next <= end, local == localCursor, local + 30 <= central
            else { throw MinvoiceError.unsupported }
            let name = Array(b[(cursor+46)..<(cursor+46+nameLength)])
            let filename = String(decoding: name, as: UTF8.self)
            guard filename.hasSuffix(".xml"), let id = UUID(uuidString: String(filename.dropLast(4))),
                  filename.lowercased() == id.uuidString.lowercased() + ".xml", ids.insert(id).inserted,
                  try u32(local) == 0x04034b50, try u16(local+6) == flags, try u16(local+8) == method,
                  try u16(local+26) == nameLength else { throw MinvoiceError.invalidInput }
            let dataStart = try local + 30 + nameLength + u16(local+28), dataEnd = dataStart + compressed
            guard local + 30 + nameLength <= central, dataStart <= central, dataEnd <= central,
                  Array(b[(local+30)..<(local+30+nameLength)]) == name else { throw MinvoiceError.invalidInput }
            if flags & 8 == 0 {
                guard try u32(local+14) == checksum, try u32(local+18) == compressed, try u32(local+22) == size
                else { throw MinvoiceError.invalidInput }
                localCursor = dataEnd
            } else {
                let descriptor = (try u32(dataEnd)) == 0x08074b50 ? dataEnd + 4 : dataEnd
                guard descriptor + 12 <= central, try u32(descriptor) == checksum,
                      try u32(descriptor+4) == compressed, try u32(descriptor+8) == size else { throw MinvoiceError.invalidInput }
                localCursor = descriptor + 12
            }
            let input = Array(b[dataStart..<dataEnd])
            var output = [UInt8](repeating: 0, count: size)
            if method == 0 { guard size == compressed else { throw MinvoiceError.invalidInput }; output = input }
            else { guard mvzip_inflate(input, input.count, &output, output.count) == 0 else { throw MinvoiceError.invalidInput } }
            guard Int(mvzip_crc(output, output.count)) == checksum else { throw MinvoiceError.invalidInput }
            entries.append(.init(id: id, xml: Data(output)))
            cursor = next
        }
        guard cursor == end, localCursor == central else { throw MinvoiceError.invalidInput }
        return entries
    }
}
