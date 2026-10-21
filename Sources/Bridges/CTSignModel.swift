import Foundation

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
