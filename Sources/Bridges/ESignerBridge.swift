import Foundation
import Core

public enum ESignerRequestAdapter {
    /// The live eTax flow uses flat frames; accept the older nested INPUT shape too.
    public static func fields(from root: [String: Any]) -> [String: Any] {
        if let input = root["INPUT"] as? [String: Any] { return root.merging(input) { _, new in new } }
        return root
    }
}

/// eSigner flat/nested JSON handler. Pure: JSON text in, JSON text out.
public struct ESignerBridge: Sendable {
    let service: any SigningService
    let chooser: (any FileChooser)?
    let uploader: any SignedFileUploader
    let verifier: any SignedXMLVerifier
    let files = ESignerFiles()
    public static let version = "1.1.0"
    public init(service: any SigningService, chooser: (any FileChooser)? = nil, uploader: any SignedFileUploader = URLSessionUploader(),
                verifier: any SignedXMLVerifier = XMLSecVerifier()) {
        self.service = service; self.chooser = chooser; self.uploader = uploader; self.verifier = verifier
    }

    public func handle(text: String, origin: String) async -> String {
        guard text.utf8.count <= 32 << 20, let data = text.data(using: .utf8), let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
        else { return Self.json(["SUCCESS": "FALSE", "ERROR": "BAD_JSON"]) }
        let f = ESignerRequestAdapter.fields(from: root)
        let code = (f["CODE"] as? String) ?? ""
        let ctx = BridgeContext(bridge: "esigner", origin: origin)
        // PIN_CODE / file-path fields in the request are deliberately never read.
        var out: [String: Any]
        switch code {
        case "CHECK_VERSION":
            out = ["SUCCESS": "TRUE", "IS_UPDATE": "N", "VERSION": Self.version]
        case "CER_002":
            out = await certInfo(f, ctx: ctx)
        case "CER_001", "NTDT_CER_001", "ONLINE_XML_CER_001", "ONLINE_SUBMIT_SIGNING_001":
            out = await sign(code: code, f: f, ctx: ctx)
        case "CHOOSE_FILE":
            out = await chooseFile(origin: origin)
        case "OFFLINE_XML_SIGN_002":
            out = await signFile(f, ctx: ctx)
        case "OFFLINE_XML_SIGN_003":
            out = await uploadFile(f, origin: origin)
        default:
            out = ["SUCCESS": "FALSE", "ERROR": "NOT_SUPPORTED"]
        }
        out["CODE"] = code
        return Self.json(out)
    }

    private func serial(_ f: [String: Any]) -> String? {
        for k in ["SERIAL_NUMBER", "ACTIVE_CERT_SERIAL", "CHECK_CERT_SERIAL"] {
            if let s = f[k] as? String, !s.isEmpty { return s }
        }
        return nil
    }

    private func certInfo(_ f: [String: Any], ctx: BridgeContext) async -> [String: Any] {
        let c: CertInfo
        do { c = try await service.selectCertificate(ctx, serial: serial(f)) }
        catch { return ["SUCCESS": "FALSE", "ERROR": "NO_CERT"] }
        var o: [String: Any] = ["SUCCESS": "TRUE", "HEX_SERIAL": c.serialHex, "CERT_SUBJECT": c.subject,
                                "CERT_ISSUER": c.issuer, "NGAY_HLUC": c.notBefore, "NGAY_HHAN": c.notAfter,
                                "CERT_CHAIN": c.derB64, "CERT": c.derB64]
        if let r = c.subject.range(of: #"MST[:=]\s*([0-9][0-9-]*)"#, options: .regularExpression) {
            o["MST"] = c.subject[r].drop { !$0.isNumber }.description
        }
        return o
    }

    // MARK: eTax "Nộp tờ khai XML": CHOOSE_FILE → OFFLINE_XML_SIGN_002 (sign) → OFFLINE_XML_SIGN_003 (upload)

    private func chooseFile(origin: String) async -> [String: Any] {
        guard let chooser else { return ["SUCCESS": "FALSE", "ERROR": "NOT_SUPPORTED"] }
        guard let url = await chooser.chooseXML() else {
            return ["SUCCESS": "FALSE", "ERROR": "USER_CANCELLED", "TKHAI_FORMAT": "0", "FULL_PATH_URL": "", "FILE_NAME": ""]
        }
        guard let data = try? Data(contentsOf: url), data.count <= ESignerFiles.maxBytes
        else { return ["SUCCESS": "FALSE", "ERROR": "BAD_FILE"] }
        await files.issue(url.path, origin: origin)
        return ["SUCCESS": "TRUE", "TKHAI_FORMAT": ESignerFileOps.tkhaiFormat(data), "FULL_PATH_URL": url.path, "FILE_NAME": url.lastPathComponent]
    }

    private func signFile(_ f: [String: Any], ctx: BridgeContext) async -> [String: Any] {
        guard let path = f["URL_FILE_NAME"] as? String, await files.isIssued(path, origin: ctx.origin), let xml = try? Data(contentsOf: URL(fileURLWithPath: path)), xml.count <= ESignerFiles.maxBytes
        else { return ["SUCCESS": "FALSE", "ERROR": "BAD_INPUT"] }
        await files.clearSigned(for: path, origin: ctx.origin)
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
            try await verifier.verify(signed)
            await files.setSigned(signed, for: path, origin: ctx.origin)
            return ["SUCCESS": "TRUE"]
        } catch let e as SigningFailure { return ["SUCCESS": "FALSE", "ERROR": Self.describe(e)] }
        catch { return ["SUCCESS": "FALSE", "ERROR": "\(error)"] }
    }

    private func uploadFile(_ f: [String: Any], origin: String) async -> [String: Any] {
        guard let path = f["URL_FILE_NAME"] as? String, await files.isIssued(path, origin: origin),
              let data = await files.signedData(path, origin: origin),
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
