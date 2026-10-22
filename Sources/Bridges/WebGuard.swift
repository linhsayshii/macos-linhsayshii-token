import Foundation

/// Host + Origin + CORS decisions shared by every bridge (DNS-rebinding guard).
public struct WebGuard: Sendable {
    public enum Verdict: Equatable, Sendable { case ok(origin: String?), badHost, unknownOrigin(String) }
    let port: Int
    public init(port: Int) { self.port = port }

    public func check(host: String?, origin: String?, allowlist: OriginAllowlist) -> Verdict {
        guard let host, host == "127.0.0.1:\(port)" || host == "localhost:\(port)" else { return .badHost }
        guard let origin else { return .ok(origin: nil) }   // no Origin: curl / native client
        return allowlist.contains(origin) ? .ok(origin: origin) : .unknownOrigin(origin)
    }

    /// Preflight answer for an allowlisted origin. The requested headers are echoed (portals add e.g. X-XSRF-TOKEN);
    /// only plain header-name characters are echoed, anything else falls back to Content-Type.
    public func preflightHeaders(origin: String?, allowlist: OriginAllowlist, requestedHeaders: String?) -> [String: String] {
        var h = corsHeaders(origin: origin, allowlist: allowlist)
        guard !h.isEmpty else { return h }
        let ok = requestedHeaders.map { !$0.isEmpty && $0.allSatisfy { $0.isLetter || $0.isNumber || "-, ".contains($0) } } ?? false
        h["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS"
        h["Access-Control-Allow-Headers"] = ok ? requestedHeaders! : "Content-Type"
        h["Access-Control-Max-Age"] = "600"
        return h
    }

    public func corsHeaders(origin: String?, allowlist: OriginAllowlist) -> [String: String] {
        guard let origin, allowlist.contains(origin) else { return [:] }
        return ["Access-Control-Allow-Origin": origin, "Access-Control-Allow-Private-Network": "true", "Vary": "Origin"]
    }
}
