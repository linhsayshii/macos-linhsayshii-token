import Foundation
import Core

/// shortcut: per-function `args` layouts and the XmlSignatureOption / SignatureOption JSON field names are
/// reconstructed from static RE notes (docs/re/vnpt-plugin.md §3); the plugin license forbids reverse
/// engineering the vendor binary, so confirm only against captured portal traffic.
public enum VNPTArgsAdapter {
    struct Parsed { var data: Data; var options: [String: Any] }

    static func parse(_ args: [String]) -> Parsed? {
        guard let first = args.first, let d = Data(base64Encoded: first), !d.isEmpty else { return nil }
        let opts = args.dropFirst().first.flatMap { $0.data(using: .utf8) }
            .flatMap { try? JSONSerialization.jsonObject(with: $0) as? [String: Any] } ?? [:]
        return Parsed(data: d, options: opts)
    }

    static func hash(_ o: [String: Any]) -> HashAlg {
        let s = ((o["digestMethod"] ?? o["signatureMethod"] ?? o["DigestAlgrothim"]) as? String)?.lowercased() ?? ""
        return s.contains("sha1") || s.contains("sha-1") ? .sha1 : .sha256
    }

    public static func signXML(args: [String]) -> (xml: Data, options: XMLSignOptions, serial: String?)? {
        guard let p = parse(args) else { return nil }
        var o = XMLSignOptions()
        o.hash = hash(p.options)
        o.kind = .underElement(p.options["ParrentTagSigning"] as? String)
        return (p.data, o, p.options["certificateSerial"] as? String)
    }

    public static func signHash(args: [String]) -> (digest: Data, hash: HashAlg, serial: String?)? {
        guard let p = parse(args), p.data.count == 32 || p.data.count == 20 else { return nil }
        return (p.data, p.data.count == 32 ? .sha256 : .sha1, p.options["certificateSerial"] as? String)
    }

    public static func signCMS(args: [String]) -> (content: Data, hash: HashAlg, serial: String?)? {
        guard let p = parse(args) else { return nil }
        return (p.data, hash(p.options), p.options["certificateSerial"] as? String)
    }
}

/// VNPT-CA Plugin. Wire format confirmed from the DVC portal's own public client script (vnpt-plugin.js) and its
/// login code (2026-10-22): the request is the JSON `{functionID, funcCallback, args[], domain}`; the reply is the
/// text `<payload>*<funcCallback>` and the page calls `window[funcCallback](payload)`.
/// Payloads: CheckPlugin / SetLicenseKey / SetShowCertListDialog -> "1" (the page tests `=== "1"`);
/// GetCertInfo -> JSON `{serial, base64, ...}`; signArrDataAdvanced -> JSON array of JSON strings, each
/// `{code,data,error}` where `data` is the base64 CMS (the login code does JSON.parse(JSON.parse(p)[0]).data).
/// shortcut: payloads for SignXML(1) / SignCMS(4) / signHash(9) are unconfirmed: they use the same `{code,data,error}` JSON
/// as one array item; confirm against a captured call from a page that uses them.
public struct VNPTBridge: Sendable {
    let service: any SigningService
    let version: String
    public init(service: any SigningService, version: String = "1.0.0.9") { self.service = service; self.version = version }

    // SIGNING_RESULT ordinals from vnpt-plugin.md
    enum Code: Int { case ok = 0, badInput = 1, signFailed = 3, noKey = 4, unknown = 5, userCancel = 11, internalError = 12 }

    public func handle(text: String, origin: String) async -> String {
        guard text.utf8.count <= 32 << 20, let d = text.data(using: .utf8), let root = try? JSONSerialization.jsonObject(with: d) as? [String: Any],
              let fid = root["functionID"] as? Int else { return frame(result(.badInput, error: "Bad input"), cb: nil) }
        let cb = root["funcCallback"] as? String
        let args = (root["args"] as? [String]) ?? []
        let ctx = BridgeContext(bridge: "vnpt", origin: origin)
        switch fid {
        case 7, 6, 37:                                   // CheckPlugin, SetLicenseKey (accepted: our access control is the origin allowlist), SetShowCertListDialog
            return frame("1", cb: cb)
        case 11:                                         // getVersion
            return frame(version, cb: cb)
        case 13:                                         // checkPluginAdvanced needs the vendor's signed challenge: not supported
            return frame("-1", cb: cb)
        case 0:                                          // GetCertInfo
            let c: CertInfo
            do { c = try await service.selectCertificate(ctx, serial: nil) }
            catch { return frame("", cb: cb) }
            let info: [String: Any] = ["serial": c.serialHex, "base64": c.derB64, "subject": c.subject, "issuer": c.issuer,
                                       "notBefore": c.notBefore, "notAfter": c.notAfter]
            return frame(Self.json(info), cb: cb)
        case 10:                                         // signArrDataAdvanced(arrData, serial, clearPIN, showCertList)
            return await frame(signArray(args: args, ctx: ctx), cb: cb)
        case 1:                                          // SignXML
            guard let r = VNPTArgsAdapter.signXML(args: args) else { return frame(result(.badInput, error: "Bad input"), cb: cb) }
            return frame(await run { try await service.signXML(ctx, serial: r.serial, xml: r.xml, options: r.options) }, cb: cb)
        case 4:                                          // SignCMS (detached)
            guard let r = VNPTArgsAdapter.signCMS(args: args) else { return frame(result(.badInput, error: "Bad input"), cb: cb) }
            return frame(await run { try await service.signCMS(ctx, serial: r.serial, content: r.content, hash: r.hash) }, cb: cb)
        case 9:                                          // signHash: args[0] = base64 SHA-256/SHA-1 digest
            guard let r = VNPTArgsAdapter.signHash(args: args) else { return frame(result(.badInput, error: "Bad input"), cb: cb) }
            return frame(await run { try await service.signDigest(ctx, serial: r.serial, digest: r.digest, hash: r.hash) }, cb: cb)
        default:                                         // SignPDF (P3), Office, file ops (never), validators…
            return frame(result(.badInput, error: "NOT_SUPPORTED"), cb: cb)
        }
    }

    /// args = [JSON array of JSON-string items {data: base64, type}, serial, clearPIN, showCertList].
    private func signArray(args: [String], ctx: BridgeContext) async -> String {
        guard let first = args.first, let d = first.data(using: .utf8),
              let items = try? JSONSerialization.jsonObject(with: d) as? [String], !items.isEmpty, items.count <= 32 else { return result(.badInput, error: "Bad input") }
        let serial = args.count > 1 && !args[1].isEmpty ? args[1] : nil
        var out: [String] = []
        for item in items {
            guard let id = item.data(using: .utf8), let o = try? JSONSerialization.jsonObject(with: id) as? [String: Any],
                  let b64 = o["data"] as? String, let content = Data(base64Encoded: b64) else { out.append(result(.badInput, error: "Bad input")); continue }
            let type = (o["type"] as? String)?.lowercased() ?? ""
            guard type == "cmsdetached" || type == "cms" else { out.append(result(.badInput, error: "NOT_SUPPORTED")); continue }
            if type == "cms" {
                out.append(await run { try await service.signCMSAttached(ctx, serial: serial, content: content, hash: .sha256) })
            } else {
                out.append(await run { try await service.signCMS(ctx, serial: serial, content: content, hash: .sha256) })
            }
        }
        return Self.json(out)
    }

    private func run(_ op: () async throws -> Data) async -> String {
        do { return result(.ok, data: try await op().base64EncodedString()) }
        catch is CancellationError { return result(.userCancel, error: "Đã huỷ yêu cầu ký") }
        catch let e as SigningFailure {
            switch e {
            case .userDenied, .userCancelled: return result(.userCancel, error: "The action was cancelled by the user")
            case .unknownSerial: return result(.noKey, error: "Not found certificate")
            case .certExpired: return result(.signFailed, error: "Certificate expired")
            case .bad(let m): return result(.badInput, error: m)
            case .card(let m): return result(.signFailed, error: m)
            }
        } catch { return result(.internalError, error: "\(error)") }
    }

    /// One `{code,data,error}` result as a JSON string.
    private func result(_ code: Code, data: String = "", error: String = "") -> String {
        Self.json(["code": code.rawValue, "data": data, "error": error] as [String: Any])
    }

    private func frame(_ payload: String, cb: String?) -> String { "\(payload)*\(cb ?? "callbackDefault")" }

    static func json(_ o: Any) -> String {
        String(decoding: (try? JSONSerialization.data(withJSONObject: o, options: [.sortedKeys, .withoutEscapingSlashes])) ?? Data("{}".utf8), as: UTF8.self)
    }
}
