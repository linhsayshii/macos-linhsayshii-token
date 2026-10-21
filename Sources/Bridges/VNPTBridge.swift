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

    public static func signCMS(args: [String]) -> (content: Data, hash: HashAlg, serial: String?)? {
        guard let p = parse(args) else { return nil }
        return (p.data, hash(p.options), p.options["certificateSerial"] as? String)
    }
}

/// VNPT-CA Plugin `Connector{functionID, funcCallback, args[]}` → `{code, data, error}`.
public struct VNPTBridge: Sendable {
    let service: any SigningService
    let version: String
    public init(service: any SigningService, version: String = "1.0.0.9") { self.service = service; self.version = version }

    // SIGNING_RESULT ordinals from vnpt-plugin.md
    enum Code: Int { case ok = 0, badInput = 1, signFailed = 3, noKey = 4, unknown = 5, userCancel = 11, internalError = 12 }

    public func handle(text: String, origin: String) async -> String {
        guard let d = text.data(using: .utf8), let root = try? JSONSerialization.jsonObject(with: d) as? [String: Any],
              let fid = root["functionID"] as? Int else { return reply(.badInput, error: "Bad input", cb: nil) }
        let cb = root["funcCallback"] as? String
        let args = (root["args"] as? [String]) ?? []
        let ctx = BridgeContext(bridge: "vnpt", origin: origin)
        switch fid {
        case 7, 11, 13:                                  // CheckPlugin, getVersion, checkPluginAdvanced
            return reply(.ok, data: version, cb: cb)
        case 6:                                          // SetLicenseKey: accepted; our access control is the origin allowlist
            return reply(.ok, data: "", cb: cb)
        case 0:                                          // GetCertInfo
            // shortcut: the vendor pops a cert chooser; we return the first certificate.
            guard let c = await service.certificates().first else { return reply(.noKey, error: "Not found certificate", cb: cb) }
            let info: [String: Any] = ["serial": c.serialHex, "subject": c.subject, "issuer": c.issuer,
                                       "notBefore": c.notBefore, "notAfter": c.notAfter, "certificate": c.derB64]
            let json = String(decoding: (try? JSONSerialization.data(withJSONObject: info)) ?? Data(), as: UTF8.self)
            return reply(.ok, data: json, cb: cb)
        case 1:                                          // SignXML
            guard let r = VNPTArgsAdapter.signXML(args: args) else { return reply(.badInput, error: "Bad input", cb: cb) }
            return await run(cb) { try await service.signXML(ctx, serial: r.serial, xml: r.xml, options: r.options) }
        case 4:                                          // SignCMS (detached)
            guard let r = VNPTArgsAdapter.signCMS(args: args) else { return reply(.badInput, error: "Bad input", cb: cb) }
            return await run(cb) { try await service.signCMS(ctx, serial: r.serial, content: r.content, hash: r.hash) }
        case 9:                                          // signHash: precomputed hashes cannot be signed on these tokens
            return reply(.signFailed, error: "Token chỉ ký trên dữ liệu gốc, không ký được hash dựng sẵn", cb: cb)
        default:                                         // SignPDF (P3), Office, file ops (never), validators…
            return reply(.badInput, error: "NOT_SUPPORTED", cb: cb)
        }
    }

    private func run(_ cb: String?, _ op: () async throws -> Data) async -> String {
        do { return reply(.ok, data: try await op().base64EncodedString(), cb: cb) }
        catch let e as SigningFailure {
            switch e {
            case .userDenied, .userCancelled: return reply(.userCancel, error: "The action was cancelled by the user", cb: cb)
            case .unknownSerial: return reply(.noKey, error: "Not found certificate", cb: cb)
            case .certExpired: return reply(.signFailed, error: "Certificate expired", cb: cb)
            case .bad(let m): return reply(.badInput, error: m, cb: cb)
            case .card(let m): return reply(.signFailed, error: m, cb: cb)
            }
        } catch { return reply(.internalError, error: "\(error)", cb: cb) }
    }

    private func reply(_ code: Code, data: String = "", error: String = "", cb: String?) -> String {
        var o: [String: Any] = ["code": code.rawValue, "data": data, "error": error]
        if let cb { o["funcCallback"] = cb }
        return String(decoding: (try? JSONSerialization.data(withJSONObject: o, options: [.sortedKeys])) ?? Data("{}".utf8), as: UTF8.self)
    }
}
