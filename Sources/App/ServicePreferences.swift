import Foundation
import Bridges

/// A fresh installation retains all services. Persist only the four public groups,
/// so enabling a service always includes its alternate port.
struct ServicePreferences {
    let fileURL: URL
    func load() -> Set<BridgeService> {
        guard let bytes = try? Data(contentsOf: fileURL),
              let flags = try? JSONDecoder().decode([String: Bool].self, from: bytes) else {
            return Set(BridgeService.allCases)
        }
        return Set(BridgeService.allCases.filter { flags[$0.rawValue] ?? true })
    }
    func save(_ enabled: Set<BridgeService>) throws {
        let flags = Dictionary(uniqueKeysWithValues: BridgeService.allCases.map { ($0.rawValue, enabled.contains($0)) })
        let encoder = JSONEncoder(); encoder.outputFormatting = [.prettyPrinted, .sortedKeys]
        try FileManager.default.createDirectory(at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        try encoder.encode(flags).write(to: fileURL, options: .atomic)
    }
}

/// Each transition serializes calls to a listener; NIO start and stop never overlap.
struct BridgeListener: Sendable {
    let start: @Sendable () async throws -> Void
    let stop: @Sendable () async -> Void
}
