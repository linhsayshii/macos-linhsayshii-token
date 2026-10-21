public enum HashAlg: Sendable { case sha256, sha1 }

public struct DigestInfoError: Error, Sendable { public let message: String }

public enum DigestInfo {
    private static let sha256Prefix: [UInt8] =
        [0x30,0x31,0x30,0x0d,0x06,0x09,0x60,0x86,0x48,0x01,0x65,0x03,0x04,0x02,0x01,0x05,0x00,0x04,0x20]
    private static let sha1Prefix: [UInt8] =
        [0x30,0x21,0x30,0x09,0x06,0x05,0x2b,0x0e,0x03,0x02,0x1a,0x05,0x00,0x04,0x14]

    public static func wrap(_ digest: [UInt8], _ alg: HashAlg) throws -> [UInt8] {
        switch alg {
        case .sha256:
            guard digest.count == 32 else { throw DigestInfoError(message: "SHA-256 digest must be 32 bytes") }
            return sha256Prefix + digest
        case .sha1:
            guard digest.count == 20 else { throw DigestInfoError(message: "SHA-1 digest must be 20 bytes") }
            return sha1Prefix + digest
        }
    }
}
