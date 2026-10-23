import Foundation
import CryptoKit
import X509

/// Picker identity binds the physical token, module, CKA_ID and certificate.
/// A certificate serial alone cannot distinguish copies on two USB tokens.
public struct SigningCertificateChoice: Identifiable, Sendable {
    public let target: SigningTarget
    public let id: String
    public let warning: String?
    public let unavailableReason: String?
    public var canSelect: Bool { unavailableReason == nil }

    public init(target: SigningTarget, requestedSerial: String? = nil, tokenSerial: String? = nil,
                requireValid: Bool = false, now: Date = Date(), duplicated: Bool = false) {
        self.target = target
        id = Self.identity(target)
        let parsed = Data(base64Encoded: target.cert.derB64).flatMap { try? Certificate(derEncoded: Array($0)) }
        if let parsed, now < parsed.notValidBefore { warning = "Chứng thư chưa có hiệu lực" }
        else if let parsed, now > parsed.notValidAfter { warning = "Chứng thư đã hết hạn" }
        else { warning = nil }

        if let serial = requestedSerial, !serial.isEmpty,
           serial.caseInsensitiveCompare(target.cert.serialHex) != .orderedSame {
            unavailableReason = "Khác CKS trang đang yêu cầu"
        } else if let tokenSerial, tokenSerial != target.tokenSerial {
            unavailableReason = "Thuộc token khác"
        } else if duplicated {
            unavailableReason = "Không phân biệt được token trùng định danh"
        } else if !TokenCompatibility.permitsSigning(flags: target.flags) {
            unavailableReason = "Đã đọc chứng thư; chưa xác minh giao thức ký của dòng token này"
        } else if parsed == nil {
            unavailableReason = "Không đọc được chứng thư"
        } else if target.flags.contains("USER_PIN_LOCKED") {
            unavailableReason = "PIN token đã bị khóa"
        } else if requireValid, let warning {
            unavailableReason = warning
        } else { unavailableReason = nil }
    }

    public static func identity(_ target: SigningTarget) -> String {
        let parts = [target.tokenSerial, target.module.ca, target.module.moduleName,
                     String(describing: target.module.backend), target.cert.id, target.cert.derB64]
        // Length-delimited components avoid collisions from separators in labels.
        let bytes = parts.map { "\($0.utf8.count):\($0)" }.joined()
        return SHA256.hash(data: Data(bytes.utf8)).map { String(format: "%02x", $0) }.joined()
    }

    public static func list(_ targets: [SigningTarget], requestedSerial: String? = nil,
                            tokenSerial: String? = nil, requireValid: Bool = false, now: Date = Date()) -> [Self] {
        let groups = Dictionary(grouping: targets, by: identity)
        return groups.keys.sorted().compactMap { key in
            guard let entries = groups[key], let target = entries.first else { return nil }
            return Self(target: target, requestedSerial: requestedSerial, tokenSerial: tokenSerial,
                        requireValid: requireValid, now: now, duplicated: entries.count > 1)
        }.sorted {
            if $0.canSelect != $1.canSelect { return $0.canSelect }
            if $0.target.module.ca != $1.target.module.ca { return $0.target.module.ca < $1.target.module.ca }
            return $0.id < $1.id
        }
    }
}
