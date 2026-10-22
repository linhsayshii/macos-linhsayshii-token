import Foundation

public enum SigningTargetError: Error, Equatable { case unknownCertificate, ambiguousCertificate }

public struct SigningTarget: Sendable {
    public let tokenSerial: String
    public let module: ModuleInfo
    public let cert: CertInfo
    public let flags: [String]
    public init(tokenSerial: String, module: ModuleInfo, cert: CertInfo, flags: [String]) {
        self.tokenSerial = tokenSerial; self.module = module; self.cert = cert; self.flags = flags
    }

    /// GetCert/SignHash use certificate serials; helpers route by physical token
    /// serial. Never guess when multiple attached tokens share a certificate.
    public static func forCertificate(serial: String, in targets: [Self]) throws -> Self {
        let matches = targets.filter { $0.cert.serialHex.caseInsensitiveCompare(serial) == .orderedSame }
        guard !matches.isEmpty else { throw SigningTargetError.unknownCertificate }
        guard matches.count == 1 else { throw SigningTargetError.ambiguousCertificate }
        return matches[0]
    }
}
