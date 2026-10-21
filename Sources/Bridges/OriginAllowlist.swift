import Foundation

/// Matches request Origins against a list of patterns. A pattern may be an exact
/// host ("dichvucong.gov.vn") or a wildcard ("*.gdt.gov.vn") matching that host
/// and any subdomain. Scheme must be https (or http://127.0.0.1 / http://localhost
/// for local testing). Matching is on the Origin's host only.
public struct OriginAllowlist: Sendable {
    private let patterns: [String]

    public static let defaults = OriginAllowlist(patterns: [
        "*.gdt.gov.vn",
        "dichvucong.gov.vn",
        "*.dichvucong.gov.vn",
        "*.baohiemxahoi.gov.vn",
        "*.minvoice.vn",
        "*.minvoice.com.vn",
        "*.minvoice.net",
    ])

    public init(patterns: [String]) { self.patterns = patterns }

    public func contains(_ origin: String) -> Bool {
        guard let host = Self.host(of: origin) else { return false }
        for p in patterns {
            if p.hasPrefix("*.") {
                let suffix = String(p.dropFirst(1)) // ".gdt.gov.vn"
                let bare = String(p.dropFirst(2))   // "gdt.gov.vn"
                if host == bare || host.hasSuffix(suffix) { return true }
            } else if host == p {
                return true
            }
        }
        return false
    }

    static func host(of origin: String) -> String? {
        guard let url = URL(string: origin), let scheme = url.scheme, let host = url.host else { return nil }
        if scheme == "https" { return host }
        if scheme == "http", host == "127.0.0.1" || host == "localhost" { return host }
        return nil
    }
}
