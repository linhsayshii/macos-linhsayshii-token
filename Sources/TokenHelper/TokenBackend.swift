import Core

protocol TokenBackend {
    func listTokens() throws -> [TokenInfo]
    func certs(serial: String) throws -> [CertInfo]
    func login(serial: String, pin: String) throws -> LoginResult
    func sign(serial: String, certId: String, mech: SignMech, data: [UInt8]) throws -> [UInt8]
    func logout(serial: String)
}

extension PKCS11: TokenBackend {}
