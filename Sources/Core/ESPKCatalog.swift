import Foundation

/// The read-only directory and PKCS#11 attribute format observed on the user's
/// FastCA ENTERSAFE-ESPK card. This layer never authenticates or sends APDUs.
public enum ESPKMetadataError: Error, Equatable {
    case invalidCatalogSize, invalidName, duplicateFile, truncatedAttribute
    case duplicateAttribute, sizeLimit, invalidAttribute
}

public struct ESPKFile: Equatable, Sendable {
    public let id: UInt16
    public let directory: String
    public let name: String
}

public enum ESPKCatalog {
    public static func parse(_ data: Data) throws -> [ESPKFile] {
        guard data.count == 50 * 30 else { throw ESPKMetadataError.invalidCatalogSize }
        let bytes = Array(data)
        var files: [ESPKFile] = []
        var ids = Set<UInt16>()
        var names = Set<String>()
        for start in stride(from: 0, to: bytes.count, by: 30) {
            let id = UInt16(bytes[start]) | UInt16(bytes[start + 1]) << 8
            // Zero records are unused. FFFF records describe directories.
            guard id != 0 && id != 0xffff else { continue }
            let directory = try name(bytes[(start + 2)..<(start + 12)])
            let file = try name(bytes[(start + 12)..<(start + 24)])
            guard !file.isEmpty else { throw ESPKMetadataError.invalidName }
            guard ids.insert(id).inserted,
                  names.insert(directory + "/" + file).inserted else {
                throw ESPKMetadataError.duplicateFile
            }
            files.append(ESPKFile(id: id, directory: directory, name: file))
        }
        return files
    }

    private static func name(_ field: ArraySlice<UInt8>) throws -> String {
        let value = field.prefix { $0 != 0 }
        // Logical names are bounded ASCII fields, not paths to host files.
        guard value.allSatisfy({ $0 >= 0x20 && $0 <= 0x7e && $0 != 0x2f && $0 != 0x5c }) else {
            throw ESPKMetadataError.invalidName
        }
        return String(decoding: value, as: UTF8.self)
    }
}

public struct ESPKAttributes: Equatable, Sendable {
    public let values: [UInt32: Data]
    public init(data: Data) throws {
        guard data.count <= 65_536 else { throw ESPKMetadataError.sizeLimit }
        let bytes = Array(data)
        var offset = 0
        var result: [UInt32: Data] = [:]
        while offset < bytes.count {
            guard bytes.count - offset >= 8 else { throw ESPKMetadataError.truncatedAttribute }
            let type = Self.uint32(bytes, offset)
            let length = Int(Self.uint32(bytes, offset + 4))
            offset += 8
            guard length <= bytes.count - offset else { throw ESPKMetadataError.truncatedAttribute }
            guard result[type] == nil else { throw ESPKMetadataError.duplicateAttribute }
            guard result.count < 128 else { throw ESPKMetadataError.sizeLimit }
            result[type] = Data(bytes[offset..<(offset + length)])
            offset += length
        }
        values = result
    }

    public func uint32(_ type: UInt32) throws -> UInt32? {
        guard let data = values[type] else { return nil }
        guard data.count == 4 else { throw ESPKMetadataError.invalidAttribute }
        return Self.uint32(Array(data), 0)
    }

    public func boolean(_ type: UInt32) throws -> Bool? {
        guard let data = values[type] else { return nil }
        guard data.count == 1, let byte = data.first, byte <= 1 else {
            throw ESPKMetadataError.invalidAttribute
        }
        return byte == 1
    }

    private static func uint32(_ bytes: [UInt8], _ offset: Int) -> UInt32 {
        UInt32(bytes[offset]) | UInt32(bytes[offset + 1]) << 8 |
        UInt32(bytes[offset + 2]) << 16 | UInt32(bytes[offset + 3]) << 24
    }
}
