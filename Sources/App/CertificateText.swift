import Foundation
import X509
import SwiftASN1
import Core

enum CertificateText {
    /// Summary only: retain every certificate and explicit selection for signing.
    static func latestExpiry(in certificates: [CertInfo]) -> CertInfo? {
        certificates.reduce(nil) { current, candidate in
            guard let current else { return candidate }
            let currentExpiry = date(current.notAfter) ?? .distantPast
            let candidateExpiry = date(candidate.notAfter) ?? .distantPast
            return candidateExpiry > currentExpiry ? candidate : current
        }
    }

    static func name(derB64: String, fallback: String) -> String {
        guard let bytes = Data(base64Encoded: derB64), let cert = try? Certificate(derEncoded: Array(bytes)) else { return fallback }
        let attributes = cert.subject.flatMap { Array($0) }
        for type in [ASN1ObjectIdentifier.RDNAttributeType.commonName, .RDNAttributeType.organizationName] {
            if let value = attributes.first(where: { $0.type == type }).flatMap({ String($0.value) }), !value.isEmpty { return value }
        }
        return fallback
    }
    static func date(_ raw: String) -> Date? {
        if let value = ISO8601DateFormatter().date(from: raw) { return value }
        let parser = DateFormatter(); parser.locale = Locale(identifier: "en_US_POSIX"); parser.timeZone = TimeZone(secondsFromGMT: 0)
        for format in ["yyyy-MM-dd HH:mm:ss", "yyyy-MM-dd"] {
            parser.dateFormat = format
            if let value = parser.date(from: raw) { return value }
        }
        return nil
    }
    static func localDate(_ raw: String, withTime: Bool = false) -> String {
        guard let date = date(raw) else { return raw }
        let formatter = DateFormatter(); formatter.locale = Locale(identifier: "vi_VN")
        formatter.dateFormat = withTime ? "HH:mm:ss · dd/MM/yyyy" : "dd/MM/yyyy"
        return formatter.string(from: date)
    }
}
