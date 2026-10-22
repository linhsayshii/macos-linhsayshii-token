import Foundation
import CryptoKit

public struct AuditEntry: Codable, Equatable, Sendable {
    public let time: String
    public let origin, bridge, certSerial, operation, inputSHA256, result: String
}

/// Append-only audit.jsonl. Stores the SHA-256 of the input, never the input,
/// and never a PIN.
public actor AuditLog {
    private let fileURL: URL
    public init(fileURL: URL) { self.fileURL = fileURL }

    public func append(origin: String, bridge: String, certSerial: String, operation: String,
                       input: Data, result: String) {
        let e = AuditEntry(time: ISO8601DateFormatter().string(from: Date()), origin: origin, bridge: bridge,
                           certSerial: certSerial, operation: operation,
                           inputSHA256: SHA256.hash(data: input).map { String(format: "%02x", $0) }.joined(),
                           result: result)
        guard var line = try? JSONEncoder().encode(e) else { return }
        line.append(0x0a)
        let fm = FileManager.default
        try? fm.createDirectory(at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        if !fm.fileExists(atPath: fileURL.path) {
            fm.createFile(atPath: fileURL.path, contents: nil, attributes: [.posixPermissions: 0o600])
        }
        guard let h = try? FileHandle(forWritingTo: fileURL) else { return }
        defer { try? h.close() }
        _ = try? h.seekToEnd()
        try? h.write(contentsOf: line)
    }

    public func recent(_ n: Int) -> [AuditEntry] {
        guard let data = try? Data(contentsOf: fileURL) else { return [] }
        let all = data.split(separator: 0x0a).compactMap { try? JSONDecoder().decode(AuditEntry.self, from: Data($0)) }
        return Array(all.suffix(n))
    }
}
