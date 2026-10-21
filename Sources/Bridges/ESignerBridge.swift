import Foundation
import Core

public enum ESignerRequestAdapter {
    /// shortcut: the request is nested `{"CODE","INPUT":{…}}` per esigner.md or flat per MacSigner, and
    /// which one the eTax portal sends is unconfirmed. Both are accepted: INPUT (if an object) wins,
    /// otherwise the root object is the field set. Confirm against captured traffic.
    public static func fields(from root: [String: Any]) -> [String: Any] {
        if let input = root["INPUT"] as? [String: Any] { return root.merging(input) { _, new in new } }
        return root
    }
}

/// eSigner `{CODE, INPUT}` handler. Pure: JSON text in, JSON text out.
public struct ESignerBridge: Sendable {
    let service: any SigningService
    let chooser: (any FileChooser)?
    let uploader: any SignedFileUploader
    let files = ESignerFiles()
    public static let version = "1.1.0"
    public init(service: any SigningService, chooser: (any FileChooser)? = nil, uploader: any SignedFileUploader = URLSessionUploader()) {
        self.service = service; self.chooser = chooser; self.uploader = uploader
    }

    public func handle(text: String, origin: String) async -> String {
        guard let data = text.data(using: .utf8), let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return Self.json(["SUCCESS": "FALSE", "ERROR": "BAD_JSON"]) }
        let f = ESignerRequestAdapter.fields(from: root)
        let code = (f["CODE"] as? String) ?? ""
        FrameLog.record("<-", origin: origin, root)
        let ctx = BridgeContext(bridge: "esigner", origin: origin)
        // PIN_CODE / file-path fields in the request are deliberately never read.
        var out: [String: Any]
        switch code {
        case "CHECK_VERSION":
            out = ["SUCCESS": "TRUE", "IS_UPDATE": "N", "VERSION": Self.version]
        case "CER_002":
            out = await certInfo(f)
        case "CER_001", "NTDT_CER_001", "ONLINE_XML_CER_001", "ONLINE_SUBMIT_SIGNING_001":
            out = await sign(code: code, f: f, ctx: ctx)
        case "CHOOSE_FILE":
            out = await chooseFile()
        case "OFFLINE_XML_SIGN_002":
            out = await signFile(f, ctx: ctx)
        case "OFFLINE_XML_SIGN_003":
            out = await uploadFile(f, origin: origin)
        default:
            out = ["SUCCESS": "FALSE", "ERROR": "NOT_SUPPORTED"]
        }
        out["CODE"] = code
        FrameLog.record("->", origin: origin, out)
        return Self.json(out)
    }

    private func serial(_ f: [String: Any]) -> String? {
        for k in ["SERIAL_NUMBER", "ACTIVE_CERT_SERIAL", "CHECK_CERT_SERIAL"] {
            if let s = f[k] as? String, !s.isEmpty { return s }
        }
        return nil
    }

    private func certInfo(_ f: [String: Any]) async -> [String: Any] {
        let certs = await service.certificates()
        guard let c = serial(f).flatMap({ s in certs.first { $0.serialHex.caseInsensitiveCompare(s) == .orderedSame } }) ?? certs.first
        else { return ["SUCCESS": "FALSE", "ERROR": "NO_CERT"] }
        var o: [String: Any] = ["SUCCESS": "TRUE", "HEX_SERIAL": c.serialHex, "CERT_SUBJECT": c.subject,
                                "CERT_ISSUER": c.issuer, "NGAY_HLUC": c.notBefore, "NGAY_HHAN": c.notAfter,
                                "CERT_CHAIN": c.derB64, "CERT": c.derB64]
        if let r = c.subject.range(of: #"MST[:=]\s*([0-9][0-9-]*)"#, options: .regularExpression) {
            o["MST"] = c.subject[r].drop { !$0.isNumber }.description
        }
        return o
    }

    // MARK: eTax "Nộp tờ khai XML": CHOOSE_FILE → OFFLINE_XML_SIGN_002 (sign) → OFFLINE_XML_SIGN_003 (upload)

    private func chooseFile() async -> [String: Any] {
        guard let chooser else { return ["SUCCESS": "FALSE", "ERROR": "NOT_SUPPORTED"] }
        guard let url = await chooser.chooseXML() else {
            return ["SUCCESS": "FALSE", "ERROR": "USER_CANCELLED", "TKHAI_FORMAT": "0", "FULL_PATH_URL": "", "FILE_NAME": ""]
        }
        guard let data = try? Data(contentsOf: url), data.count <= ESignerFiles.maxBytes
        else { return ["SUCCESS": "FALSE", "ERROR": "BAD_FILE"] }
        await files.issue(url.path)
        return ["SUCCESS": "TRUE", "TKHAI_FORMAT": ESignerFileOps.tkhaiFormat(data), "FULL_PATH_URL": url.path, "FILE_NAME": url.lastPathComponent]
    }

    private func signFile(_ f: [String: Any], ctx: BridgeContext) async -> [String: Any] {
        guard let path = f["URL_FILE_NAME"] as? String, await files.isIssued(path), let xml = try? Data(contentsOf: URL(fileURLWithPath: path))
        else { return ["SUCCESS": "FALSE", "ERROR": "BAD_INPUT"] }
        var serialHex: String?
        if let dec = serial(f), !dec.isEmpty {
            let want = ESignerFileOps.decimalToHex(dec) ?? dec
            let certs = await service.certificates()
            guard let c = certs.first(where: { ESignerFileOps.sameSerial($0.serialHex, want) }) else { return ["SUCCESS": "FALSE", "ERROR": "NO_CERT"] }
            serialHex = c.serialHex
            if (f["CHECK_TIN"] as? String) == "true", let tin = f["TIN_VALID"] as? String, !tin.isEmpty,
               let r = c.subject.range(of: #"MST[:=]\s*([0-9][0-9-]*)"#, options: .regularExpression),
               c.subject[r].drop(while: { !$0.isNumber }).description != tin { return ["SUCCESS": "FALSE", "ERROR": "TIN_MISMATCH"] }
        }
        let opt = ESignerFileOps.signOptions(xpathData: f["XPATH_DATA"] as? String ?? "", xpathSign: f["XPATH_SIGN"] as? String ?? "",
                                             signingTime: ESignerFileOps.parseSigningTime(f["DATE_SIGNING"] as? String, zone: f["TIMEZONE_SIGNING"] as? String))
        do {
            let signed = try await service.signXML(ctx, serial: serialHex, xml: xml, options: opt)
            await files.setSigned(signed, for: path)
            return ["SUCCESS": "TRUE"]
        } catch let e as SigningFailure { return ["SUCCESS": "FALSE", "ERROR": Self.describe(e)] }
        catch { return ["SUCCESS": "FALSE", "ERROR": "\(error)"] }
    }

    private func uploadFile(_ f: [String: Any], origin: String) async -> [String: Any] {
        guard let path = f["URL_FILE_NAME"] as? String, await files.isIssued(path),
              let data = await files.signedData(path) ?? (try? Data(contentsOf: URL(fileURLWithPath: path))),
              let action = (f["REQUEST_URL_ACTION"] as? String).flatMap(URL.init(string:)),
              let name = f["UPLOADED_FILE_NAME"] as? String, let cn = f["COOKIE_NAME"] as? String, let cv = f["COOKIE_VALUE"] as? String
        else { return ["SUCCESS": "FALSE", "ERROR": "BAD_INPUT"] }
        // The session cookie only goes back to the portal that is calling us.
        guard action.scheme == "https", let host = action.host, host == URL(string: origin)?.host
        else { return ["SUCCESS": "FALSE", "ERROR": "BAD_UPLOAD_URL"] }
        do {
            try await uploader.upload(to: action, cookieName: cn, cookieValue: cv, uploadedFileName: name,
                                      fileName: URL(fileURLWithPath: path).lastPathComponent, data: data)
            return ["SUCCESS": "TRUE", "PIN_CODE": ESignerFileOps.maTKhai(data)]
        } catch { return ["SUCCESS": "FALSE", "ERROR": "UPLOAD_FAILED"] }
    }

    private func sign(code: String, f: [String: Any], ctx: BridgeContext) async -> [String: Any] {
        do {
            // BASE64_VALUE = bytes the portal already canonicalized (MacSigner: "prepared-byte", SHA1withRSA);
            // VALUE = whole XML document to sign (esigner.md). shortcut: confirm which the eTax portal sends.
            if let b = f["BASE64_VALUE"] as? String {
                guard let bytes = Data(base64Encoded: b) else { return ["SUCCESS": "FALSE", "ERROR": "BAD_INPUT"] }
                let hash: HashAlg = code == "CER_001" ? .sha1 : .sha256
                let r = try await service.signMessage(ctx, serial: serial(f), message: bytes, hash: hash)
                return ["SUCCESS": "TRUE", "SIGNED_CONTENT": r.signature.base64EncodedString(),
                        "CERT": r.certDER.base64EncodedString(), "CERT_CHAIN": r.certDER.base64EncodedString(), "PIN_CODE": ""]
            }
            guard let v = f["VALUE"] as? String, let xml = Data(base64Encoded: v), !xml.isEmpty
            else { return ["SUCCESS": "FALSE", "ERROR": "BAD_INPUT"] }
            var opt = XMLSignOptions(); opt.kind = .toKhai
            let signed = try await service.signXML(ctx, serial: serial(f), xml: xml, options: opt)
            return ["SUCCESS": "TRUE", "SIGNED_CONTENT": signed.base64EncodedString()]
        } catch let e as SigningFailure {
            return ["SUCCESS": "FALSE", "ERROR": Self.describe(e)]
        } catch {
            return ["SUCCESS": "FALSE", "ERROR": "\(error)"]
        }
    }

    static func describe(_ e: SigningFailure) -> String {
        switch e {
        case .userDenied: return "USER_DENIED"
        case .userCancelled: return "USER_CANCELLED"
        case .certExpired: return "CERT_EXPIRED"
        case .unknownSerial: return "NO_CERT"
        case .bad(let m), .card(let m): return m
        }
    }

    static func json(_ o: [String: Any]) -> String {
        String(decoding: (try? JSONSerialization.data(withJSONObject: o, options: [.sortedKeys])) ?? Data("{}".utf8), as: UTF8.self)
    }
}

/// Redacted wire log (~/Library/Logs/TokenSigner/esigner-frames.log) so portal protocol shapes can be confirmed.
/// PIN-like fields are dropped; long strings are truncated. Never logs secrets.
enum FrameLog {
    static func record(_ dir: String, origin: String, _ obj: [String: Any]) {
        let line = "\(ISO8601DateFormatter().string(from: Date())) \(dir) \(origin) \(ESignerBridge.json(redact(obj) as? [String: Any] ?? [:]))\n"
        let url = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Logs/TokenSigner/esigner-frames.log")
        try? FileManager.default.createDirectory(at: url.deletingLastPathComponent(), withIntermediateDirectories: true)
        if let h = try? FileHandle(forWritingTo: url) { h.seekToEndOfFile(); h.write(Data(line.utf8)); try? h.close() }
        else { try? Data(line.utf8).write(to: url) }
    }
    static func redact(_ v: Any) -> Any {
        if let d = v as? [String: Any] {
            var o = [String: Any]()
            for (k, x) in d { o[k] = k.uppercased().contains("PIN") || k.uppercased().contains("PASS") ? "<redacted>" : redact(x) }
            return o
        }
        if let a = v as? [Any] { return a.map(redact) }
        if let s = v as? String, s.count > 120 { return String(s.prefix(120)) + "…[\(s.count) chars]" }
        return v
    }
}
