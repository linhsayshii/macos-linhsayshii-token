import Foundation
import Core

/// Native file picker (NSOpenPanel in the App target). Returns nil when cancelled.
public protocol FileChooser: Sendable {
    func chooseXML() async -> URL?
}

/// Uploads the signed declaration to the portal. The original eSigner does this itself with the Java JFileUpload client.
public protocol SignedFileUploader: Sendable {
    func upload(to url: URL, cookieName: String, cookieValue: String, uploadedFileName: String, fileName: String, data: Data) async throws
}

/// Multipart POST in JFileUpload's shape (fields `todo=upload`, `uploadedFileName`, `filename`; file part `uploadfile`).
/// shortcut: reconstructed statically from the eSigner jar (no live capture, single chunk — tờ khai are far below CHUNKSIZE);
/// confirm against the portal and adjust.
public struct URLSessionUploader: SignedFileUploader {
    public init() {}
    public func upload(to url: URL, cookieName: String, cookieValue: String, uploadedFileName: String, fileName: String, data: Data) async throws {
        let boundary = "----TokenSigner\(UUID().uuidString)"
        var body = Data()
        func field(_ k: String, _ v: String) {
            body.append(Data("--\(boundary)\r\nContent-Disposition: form-data; name=\"\(k)\"\r\n\r\n\(v)\r\n".utf8))
        }
        field("todo", "upload"); field("uploadedFileName", uploadedFileName); field("cookiename", cookieName); field("cookievalue", cookieValue); field("filename", fileName)
        body.append(Data("--\(boundary)\r\nContent-Disposition: form-data; name=\"uploadfile\"; filename=\"\(fileName)\"\r\nContent-Type: text/xml\r\n\r\n".utf8))
        body.append(data); body.append(Data("\r\n--\(boundary)--\r\n".utf8))
        var req = URLRequest(url: url, timeoutInterval: 60)
        req.httpMethod = "POST"; req.httpBody = body
        req.setValue("multipart/form-data; boundary=\(boundary)", forHTTPHeaderField: "Content-Type")
        req.setValue("\(cookieName)=\(cookieValue)", forHTTPHeaderField: "Cookie")
        req.setValue("JFileUpload", forHTTPHeaderField: "User-Agent")   // the portal routes by User-Agent (btt.xml device types)
        req.httpShouldHandleCookies = false
        let (respBody, resp) = try await URLSession.shared.data(for: req)
        try? respBody.write(to: FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Logs/TokenSigner/upload-response.html"))
        FrameLog.note("UPLOAD \((resp as? HTTPURLResponse)?.statusCode ?? 0) \(respBody.count)B \(String(decoding: respBody.prefix(400), as: UTF8.self).replacingOccurrences(of: "\n", with: " "))")
        guard let code = (resp as? HTTPURLResponse)?.statusCode, (200..<300).contains(code) else { throw SigningFailure.bad("UPLOAD_FAILED") }
    }
}

/// Files handed out by CHOOSE_FILE and their signed content. Later codes only accept paths issued here, so a
/// web page cannot make the bridge read arbitrary local files. The user's file on disk is never modified.
actor ESignerFiles {
    private var chosen = Set<String>()
    private var signed: [String: Data] = [:]
    static let maxBytes = 20 << 20

    func issue(_ path: String) { chosen.insert(path); signed[path] = nil }
    func isIssued(_ path: String) -> Bool { chosen.contains(path) }
    func setSigned(_ d: Data, for path: String) { signed[path] = d }
    func signedData(_ path: String) -> Data? { signed[path] }
}

enum ESignerFileOps {
    /// eTax `TKHAI_FORMAT`: 9 = XML, 0 = unrecognised.
    static func tkhaiFormat(_ data: Data) -> String {
        guard let doc = try? XMLDocument(data: data, options: []), doc.rootElement() != nil else { return "0" }
        return "9"
    }

    /// `"/HSoThueDTu/HSoKhaiThue"` → `"HSoKhaiThue"`; `"/HSoThueDTu/CKyDTu"` → `"HSoThueDTu/CKyDTu"`.
    static func signOptions(xpathData: String, xpathSign: String, signingTime: Date?) -> XMLSignOptions {
        var o = XMLSignOptions()
        let sign = xpathSign.split(separator: "/").joined(separator: "/")
        if !sign.isEmpty { o.kind = .custom(parentXPath: sign) } else { o.kind = .underElement(nil) }
        if let last = xpathData.split(separator: "/").last { o.signElements = [String(last)] }
        if let t = signingTime { o.signingTime = t }
        return o
    }

    /// "22/10/2026 01:13:34" in the given IANA zone.
    static func parseSigningTime(_ s: String?, zone: String?) -> Date? {
        guard let s, !s.isEmpty else { return nil }
        let f = DateFormatter(); f.locale = Locale(identifier: "en_US_POSIX"); f.dateFormat = "dd/MM/yyyy HH:mm:ss"
        f.timeZone = zone.flatMap(TimeZone.init(identifier:)) ?? .current
        return f.date(from: s)
    }

    /// Decimal certificate serial → upper-case hex without leading zeros.
    static func decimalToHex(_ dec: String) -> String? {
        guard !dec.isEmpty, dec.allSatisfy(\.isASCII), dec.allSatisfy(\.isNumber) else { return nil }
        var digits = dec.compactMap { $0.wholeNumberValue }
        var out = ""
        while !(digits.isEmpty || digits == [0]) {
            var rem = 0, next: [Int] = []
            for d in digits { let cur = rem * 10 + d; let q = cur / 16; rem = cur % 16; if !next.isEmpty || q > 0 { next.append(q) } }
            out = String(rem, radix: 16, uppercase: true) + out
            digits = next
        }
        return out.isEmpty ? "0" : out
    }

    static func sameSerial(_ a: String, _ b: String) -> Bool {
        func norm(_ s: String) -> String { let t = s.uppercased().drop { $0 == "0" }; return t.isEmpty ? "0" : String(t) }
        return norm(a) == norm(b)
    }

    /// `maTKhai` text, else `MSo` (what the original returns as PIN_CODE after upload; the portal reads it as the declaration code).
    static func maTKhai(_ data: Data) -> String {
        guard let doc = try? XMLDocument(data: data, options: []) else { return "" }
        for name in ["maTKhai", "MSo"] {
            if let n = (try? doc.nodes(forXPath: "//*[local-name()='\(name)']"))?.first, let v = n.stringValue { return v }
        }
        return ""
    }
}
