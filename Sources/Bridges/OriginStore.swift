import Foundation

/// User-editable origin allowlist persisted at origins.json, plus the set of
/// unknown origins waiting for the user's decision.
public actor OriginStore {
    public enum StoreError: Error { case isDefault }
    private let fileURL: URL
    private var extra: [String]
    private var pending: [String] = []

    public init(fileURL: URL) {
        self.fileURL = fileURL
        let data = try? Data(contentsOf: fileURL)
        extra = (data.flatMap { try? JSONDecoder().decode([String: [String]].self, from: $0) })?["origins"] ?? []
    }

    public func allowlist() -> OriginAllowlist {
        OriginAllowlist(patterns: OriginAllowlist.defaultPatterns + extra)
    }

    public func userPatterns() -> [String] { extra }

    public func add(_ pattern: String) throws {
        if !extra.contains(pattern), !OriginAllowlist.defaultPatterns.contains(pattern) { extra.append(pattern) }
        pending.removeAll { OriginAllowlist.host(of: $0) == pattern }
        try save()
    }

    public func remove(_ pattern: String) throws {
        if OriginAllowlist.defaultPatterns.contains(pattern) { throw StoreError.isDefault }
        extra.removeAll { $0 == pattern }
        try save()
    }

    public func notePending(_ origin: String) { if !pending.contains(origin) { pending.append(origin) } }
    public func takePending() -> [String] { defer { pending = [] }; return pending }

    private func save() throws {
        try FileManager.default.createDirectory(at: fileURL.deletingLastPathComponent(), withIntermediateDirectories: true)
        try JSONEncoder().encode(["origins": extra]).write(to: fileURL, options: .atomic)
    }
}
