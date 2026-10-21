import Foundation
import Core

/// M-Invoice desktop plugin ("handlerHub" on :16080). Wire format confirmed from the vendor web app's own bundle
/// (hddt.minvoice.com.vn main.*.js, 2026-10-22; see docs/re/minvoice-plugin.md "2.0 delta"):
/// the page invokes `processMessage(json)` with `{BrowserInfo:{Cookie,UserAgent,UserName,Pass,LinkApi}, PlugCommand:{CommandName,…}}`
/// and waits for the server→client callback `reponseResult(jsonString)` where `code == 1` means success.
/// `getVersion` must be >= the page's `minimumPluginVersion` ("1.1.1").
///
/// Not implemented yet: SignInvoices / SignSS04 / SignDeclaration / StatementInvoice(Buyer) / SignSummary. In 2.0 the page sends
/// only invoice ids; the plugin itself downloads the XML from api-hddt.minvoice.com.vn, signs, and uploads it. The download/upload
/// endpoints are not visible in the web bundle, so those commands answer an explicit error rather than guess.
/// BrowserInfo (it carries the user's cookie and password) is never logged, stored or forwarded.
public struct MinvoiceBridge: Sendable {
    let service: any SigningService
    public static let version = "2.0.0"
    public init(service: any SigningService) { self.service = service }

    public var handler: SignalRHub.Handler {
        { method, args, call in try await self.invoke(method, args, call) }
    }

    func invoke(_ method: String, _ args: [String], _ call: SignalRCall) async throws -> String? {
        switch method.lowercased() {
        case "getversion": return Self.version
        case "getcommandinfo", "runupdate": return nil
        case "processmessage":
            // Fire-and-forget like the original: the result arrives later as the `reponseResult` callback.
            let text = args.first ?? ""
            Task { await call.push("reponseResult", [await self.dispatch(text, origin: call.origin)]) }
            return nil
        case "swichtask", "voucherhub":
            return await dispatch(args.first ?? "", origin: call.origin)
        default:
            throw SignalRInvokeError.message("Method '\(method)' not found")
        }
    }

    /// Returns the `reponseResult` JSON string.
    func dispatch(_ text: String, origin: String) async -> String {
        guard let d = text.data(using: .utf8), let root = try? JSONSerialization.jsonObject(with: d) as? [String: Any]
        else { return Self.result(code: 400, message: "Bad request") }
        // Older 1.x pages send the command at the top level; 2.0 nests it under PlugCommand.
        let cmd = (root["PlugCommand"] as? [String: Any]) ?? root
        let name = (cmd["CommandName"] as? String) ?? ""
        switch name {
        case "TokenInfo", "GetCertificate", "GetInfoToken":
            return await tokenInfo(serial: cmd["SerialNumber"] as? String)
        default:
            return Self.result(code: 501, message: "TokenSigner chưa hỗ trợ lệnh \(name.isEmpty ? "(trống)" : name) của M-Invoice")
        }
    }

    private func tokenInfo(serial: String?) async -> String {
        let certs = await service.certificates()
        guard let c = serial.flatMap({ s in certs.first { $0.serialHex.caseInsensitiveCompare(s) == .orderedSame } }) ?? certs.first
        else { return Self.result(code: 404, message: "Không tìm thấy chứng thư số") }
        let token: [String: Any] = ["Issuer": c.issuer, "SerialNumber": c.serialHex, "Subject": c.subject,
                                    "NotBefore": Self.iso(c.notBefore), "NotAfter": Self.iso(c.notAfter),
                                    "Base64Certificate": c.derB64]
        return Self.result(code: 1, data: ["token": token])
    }

    /// The page does `new Date(NotBefore)`: "yyyy-MM-dd HH:mm:ss" is not portable, ISO-8601 is.
    static func iso(_ s: String) -> String {
        s.count == 19 && s.dropFirst(10).first == " " ? s.replacingOccurrences(of: " ", with: "T") : s
    }

    static func result(code: Int, message: String = "", data: [String: Any] = [:]) -> String {
        SignalRHub.json(["code": code, "message": message, "data": data] as [String: Any])
    }
}
