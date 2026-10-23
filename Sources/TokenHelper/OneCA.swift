import Foundation
import Core

/// Native arm64/x86_64 Longmai PC/SC backend; no Feitian APDU shim.
final class OneCA: TokenBackend {
    private let pkcs11: PKCS11
    private var loggedSerial: String?
    init(modulePath: String) { pkcs11 = PKCS11(modulePath: modulePath, oneCA: true) }

    func listTokens() throws -> [TokenInfo] {
        let readers = ReaderScanner().readers()
        guard readers.filter({ OneCAProfile.matches(reader: $0.reader) }).count == 1,
              readers.contains(where: { OneCAProfile.matches(reader: $0.reader) && $0.atr == OneCAProfile.atr }) else {
            throw PKCS11Error("OneCA: cần đúng một reader OneCAV3 để ghép token an toàn")
        }
        let tokens = OneCAProfile.bind(readers: readers, tokens: try pkcs11.listTokens())
        guard tokens.count == 1 else { throw PKCS11Error("OneCA: không ghép được token với reader") }
        return tokens
    }

    private func require(serial: String) throws {
        guard try listTokens().contains(where: { $0.serial == serial }) else {
            throw PKCS11Error("OneCA: token đã thay đổi hoặc không còn kết nối")
        }
    }
    func certs(serial: String) throws -> [CertInfo] {
        try require(serial: serial)
        return try pkcs11.certs(serial: serial)
    }
    func login(serial: String, pin: String) throws -> LoginResult {
        try require(serial: serial)
        let result = try pkcs11.login(serial: serial, pin: pin)
        if result == .ok { loggedSerial = serial }
        return result
    }
    func sign(serial: String, certId: String, mech: SignMech, data: [UInt8]) throws -> [UInt8] {
        // Keep the logged-in vendor session intact: a discovery refresh may
        // recreate objects. PC/SC identity remains checked before dispatch.
        let readers = ReaderScanner().readers().filter { OneCAProfile.matches(reader: $0.reader) }
        guard loggedSerial == serial, readers.count == 1, readers[0].atr == OneCAProfile.atr else {
            throw PKCS11Error("OneCA: phiên đăng nhập hoặc reader đã thay đổi")
        }
        guard !certId.isEmpty else { throw PKCS11Error("OneCA: chứng thư thiếu CKA_ID") }
        return try pkcs11.sign(serial: serial, certId: certId, mech: mech, data: data)
    }
    func logout(serial: String) {
        pkcs11.logout(serial: serial)
        if loggedSerial == serial { loggedSerial = nil }
    }
}
