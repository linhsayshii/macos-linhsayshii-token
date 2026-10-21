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

    public func corsHeaders(origin: String?, allowlist: OriginAllowlist) -> [String: String] {
        guard let origin, allowlist.contains(origin) else { return [:] }
        return ["Access-Control-Allow-Origin": origin, "Access-Control-Allow-Private-Network": "true", "Vary": "Origin"]
    }
}
