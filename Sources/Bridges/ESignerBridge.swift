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
    public static let version = "1.1.0"
    public init(service: any SigningService) { self.service = service }

    public func handle(text: String, origin: String) async -> String {
        guard let data = text.data(using: .utf8), let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any]
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
            out = await certInfo(f)
        case "CER_001", "NTDT_CER_001", "ONLINE_XML_CER_001", "ONLINE_SUBMIT_SIGNING_001":
            out = await sign(code: code, f: f, ctx: ctx)
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
