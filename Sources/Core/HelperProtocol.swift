import Foundation

public struct TokenInfo: Codable, Equatable, Sendable {
    public let slot: UInt; public let reader, serial, label: String; public let flags: [String]
    public init(slot: UInt, reader: String, serial: String, label: String, flags: [String]) {
        self.slot = slot; self.reader = reader; self.serial = serial; self.label = label; self.flags = flags
    }
}

public struct CertInfo: Codable, Equatable, Sendable {
    public let id, derB64, subject, issuer, serialHex, notBefore, notAfter: String
    public init(id: String, derB64: String, subject: String, issuer: String,
                serialHex: String, notBefore: String, notAfter: String) {
        self.id = id; self.derB64 = derB64; self.subject = subject; self.issuer = issuer
        self.serialHex = serialHex; self.notBefore = notBefore; self.notAfter = notAfter
    }
}

public enum SignMech: String, Codable, Sendable {
    case sha256RSA = "SHA256_RSA_PKCS"   // token hashes the raw message, then signs
    case rsaPKCS = "RSA_PKCS"            // sign a caller-built DigestInfo (PKCS#1 v1.5 pad on-card)
    case rsaX509 = "RSA_X_509"           // raw RSA; caller pads the full modulus-sized block
}

public enum LoginResult: Codable, Equatable, Sendable {
    case ok
    case pinIncorrect(retriesLeft: Int?)
    case pinLocked
}

public enum HelperRequest: Codable, Equatable, Sendable {
    case listTokens
    case listCerts(serial: String)
    case login(serial: String, pin: String)
    case sign(serial: String, certId: String, mech: SignMech, dataB64: String)
    case logout(serial: String)
}

public enum HelperResponse: Codable, Equatable, Sendable {
    case tokens([TokenInfo])
    case certs([CertInfo])
    case loginResult(LoginResult)
    case signature(String)
    case ok
    case error(String)
}
