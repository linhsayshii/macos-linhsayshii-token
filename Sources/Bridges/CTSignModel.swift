import Foundation
import Core

public enum CTSignError: Error, Equatable {
    case unknownSerial(String)
    /// SignHash hands a pre-built hash; these Feitian tokens sign only the raw
    /// message on-card (CKM_SHA256_RSA_PKCS). No precomputed-hash mechanism works.
    case precomputedHashUnsupported
}

struct HashItem: Codable {
    let Ma: String?
    let DLieuHash: String
    var CKy: String?
}

struct SignHashRequest: Codable {
    let requestId: String?
    let serinumber: String
    var hash: [HashItem]
}

struct CertificateInfo: Codable {
    let serinumber: String
    let subjectDN: String
    let issuedDN: String
    let pemCert: String
    let valid: Bool
    let validFrom: String
    let validTo: String
    let error: String?
}

/// Parses POST /api/HubClient/signxml. Shape confirmed from the GDT tax portal (2026-10-22):
/// `{requestId, base64Cert, cks, dataBV[], dataFile, serinumber}` where `cks` is the signature placement path
/// ("HSoThueDTu/CKyDTu": root/element that holds the signature) and `dataBV` the element names to sign by `#id`
/// (["HSoKhaiThue"]). `filePath` is never read.
/// shortcut: the request carries no hash algorithm, so SHA-256 is assumed (GDT used SHA-1 historically); confirm with a portal that verifies.
enum SignXmlRequestAdapter {
    struct Parsed { let serial: String; let xml: Data; let options: XMLSignOptions }
    static func parse(_ body: Data) -> Parsed? {
        guard let o = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              let b64 = o["dataFile"] as? String, let xml = Data(base64Encoded: b64), !xml.isEmpty
        else { return nil }
        var opt = XMLSignOptions()
        if let cks = o["cks"] as? String, !cks.isEmpty { opt.kind = .custom(parentXPath: cks) }
        opt.signElements = (o["dataBV"] as? [String]) ?? []
        return Parsed(serial: o["serinumber"] as? String ?? "", xml: xml, options: opt)
    }
}
