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

/// Parses POST /api/HubClient/signxml. Isolates the (verify) wire shape.
/// shortcut: shape is `SignXmlRequest {dataFile, filePath, base64Cert, cks, dataBV, serinumber, requestId}` from
/// static RE only; `cks`/`dataBV` meaning (placement / signing type) is unknown, so placement defaults to
/// hoaDon. Confirm against a captured e-invoice signxml call. `filePath` is never read.
enum SignXmlRequestAdapter {
    struct Parsed { let serial: String; let xml: Data; let options: XMLSignOptions }
    static func parse(_ body: Data) -> Parsed? {
        guard let o = try? JSONSerialization.jsonObject(with: body) as? [String: Any],
              let b64 = o["dataFile"] as? String, let xml = Data(base64Encoded: b64), !xml.isEmpty
        else { return nil }
        return Parsed(serial: o["serinumber"] as? String ?? "", xml: xml, options: XMLSignOptions())
    }
}
