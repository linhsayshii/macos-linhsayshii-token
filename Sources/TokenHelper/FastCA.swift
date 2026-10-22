import Foundation
import CryptoKit
import Core
import CFastCA

struct FastCAError: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}

/// OpenSC handles CCID/secure messaging. ESPK metadata and commands belong to
/// this backend; no generic PKCS#11 module or injected shim is used.
final class FastCA: TokenBackend {
    private final class Connection {
        let pointer: OpaquePointer
        init(runtime: OpaquePointer, reader: String) throws {
            var pointer: OpaquePointer?
            let rv = fca_card_open(runtime, reader, &pointer)
            guard rv == 0, let pointer else { throw FastCAError("FastCA kết nối thất bại (\(rv))") }
            self.pointer = pointer
        }
        deinit { fca_card_close(pointer) }

        func read(_ fid: UInt16) throws -> Data {
            var bytes = [UInt8](repeating: 0, count: 65_536)
            var length = 0
            let rv = fca_read_file(pointer, fid, &bytes, bytes.count, &length)
            guard rv == 0 else { throw FastCAError(String(format: "FastCA đọc metadata %04X thất bại (%d)", fid, rv)) }
            return Data(bytes.prefix(length))
        }
    }

    private struct Snapshot {
        let serial: String
        let identities: [ESPKSigningIdentity]
    }
    private struct Session {
        let connection: Connection
        let snapshot: Snapshot
    }

    private var runtime: OpaquePointer?
    private var sessions: [String: Session] = [:]
    deinit {
        sessions.removeAll() // Connections must close/reset before the runtime.
        if let runtime { fca_runtime_close(runtime) }
    }

    private func context() throws -> OpaquePointer {
        if let runtime { return runtime }
        let paths = ["/opt/homebrew/lib/libopensc.13.dylib", "/usr/local/lib/libopensc.13.dylib",
                     "/Library/OpenSC/lib/libopensc.13.dylib"]
        guard let path = paths.first(where: { FileManager.default.fileExists(atPath: $0) }) else {
            throw FastCAError("FastCA cần OpenSC 0.27.1; chưa tìm thấy libopensc.13.dylib")
        }
        var pointer: OpaquePointer?
        var message = [CChar](repeating: 0, count: 512)
        let rv = fca_runtime_open(path, &pointer, &message, message.count)
        guard rv == 0, let pointer else {
            let bytes = message.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }
            throw FastCAError(String(decoding: bytes, as: UTF8.self))
        }
        runtime = pointer
        return pointer
    }

    private func readers() -> [(reader: String, atr: [UInt8])] {
        ReaderScanner().readers().filter { $0.atr == FastCAProfile.atr }
    }

    private func snapshot(_ connection: Connection) throws -> Snapshot {
        let files = try ESPKCatalog.parse(connection.read(0x6f01))
        guard let cardIDFile = files.first(where: { $0.directory.isEmpty && $0.name == "cardid" }) else {
            throw FastCAError("FastCA thiếu cardid trong catalog")
        }
        let cardID = try connection.read(cardIDFile.id)
        // Stable across reader numbering/hotplug; independent of certificate renewal.
        let serial = "FASTCA-" + SHA256.hash(data: cardID).prefix(8).map { String(format: "%02X", $0) }.joined()
        var certificates: [ESPKAttributes] = [], keys: [ESPKAttributes] = []
        for file in files where file.directory == "pkcs11" {
            if file.name.hasPrefix("cert") {
                certificates.append(try ESPKAttributes(data: connection.read(file.id)))
            } else if file.name.hasPrefix("prvk") {
                keys.append(try ESPKAttributes(data: connection.read(file.id)))
            }
        }
        let identities = try ESPKSigningIdentity.resolve(certificates: certificates, keys: keys)
        guard !identities.isEmpty, identities.allSatisfy(RSAPKCS1v15.certificateMatches) else {
            throw FastCAError("FastCA không có chứng thư/khóa RSA tương thích khớp nhau")
        }
        return Snapshot(serial: serial, identities: identities)
    }

    private func open(serial: String) throws -> Session {
        let runtime = try context()
        for reader in readers() {
            let connection = try Connection(runtime: runtime, reader: reader.reader)
            let metadata = try snapshot(connection)
            if metadata.serial == serial { return Session(connection: connection, snapshot: metadata) }
        }
        throw FastCAError("Không tìm thấy đúng token FastCA; hãy kiểm tra USB")
    }

    func listTokens() throws -> [TokenInfo] {
        let runtime = try context()
        return try readers().enumerated().map { index, reader in
            let connection = try Connection(runtime: runtime, reader: reader.reader)
            let metadata = try snapshot(connection)
            return TokenInfo(slot: UInt(index), reader: reader.reader, serial: metadata.serial,
                             label: "FastCA", flags: ["PIN_RETRIES_UNKNOWN"])
        }
    }

    func certs(serial: String) throws -> [CertInfo] {
        let session = try open(serial: serial)
        return try session.snapshot.identities.map {
            guard let info = PKCS11.makeCertInfo(id: Array($0.id), der: Array($0.certificateDER)) else {
                throw FastCAError("Chứng thư FastCA không hợp lệ")
            }
            return info
        }
    }

    func login(serial: String, pin: String) throws -> LoginResult {
        guard sessions[serial] == nil else { throw FastCAError("FastCA đã có phiên xác thực") }
        var bytes = Array(pin.utf8)
        defer { bytes.withUnsafeMutableBytes { fca_wipe($0.baseAddress, $0.count) } }
        guard (1...64).contains(bytes.count), bytes.allSatisfy({ $0 >= 0x20 && $0 <= 0x7e }) else {
            throw FastCAError("PIN FastCA phải có 1–64 ký tự ASCII; chưa gửi xác thực")
        }
        let session = try open(serial: serial)
        var status: UInt16 = 0
        let rv = fca_login(session.connection.pointer, &bytes, bytes.count, &status)
        switch rv {
        case 0:
            sessions[serial] = session
            return .ok
        case Int32(FCA_PIN_INCORRECT): return .pinIncorrect(retriesLeft: Int(status & 15))
        case Int32(FCA_PIN_LOCKED): return .pinLocked
        default: throw FastCAError(String(format: "FastCA xác thực thất bại (%d, SW=%04X); không tự thử lại", rv, status))
        }
    }

    func sign(serial: String, certId: String, mech: SignMech, data: [UInt8]) throws -> [UInt8] {
        guard let session = sessions[serial] else { throw FastCAError("FastCA chưa đăng nhập") }
        defer { logout(serial: serial) }
        guard let identity = session.snapshot.identities.first(where: {
            $0.id.map { String(format: "%02x", $0) }.joined() == certId.lowercased()
        }) else { throw FastCAError("Không tìm thấy đúng khóa của chứng thư FastCA") }
        let payload: Data
        switch mech {
        case .rsaPKCS: payload = Data(data)
        case .sha256RSA: payload = Data(try DigestInfo.sha256Block(Data(data)))
        case .rsaX509: throw FastCAError("FastCA chưa hỗ trợ yêu cầu RSA_X_509")
        }
        var block = Array(try RSAPKCS1v15.encode(payload, modulusBytes: identity.modulus.count))
        defer { block.withUnsafeMutableBytes { fca_wipe($0.baseAddress, $0.count) } }
        var signature = [UInt8](repeating: 0, count: 256)
        var length = 0
        var status: UInt16 = 0
        let rv = fca_sign(session.connection.pointer, identity.keyReference, &block, block.count,
                          &signature, signature.count, &length, &status)
        guard rv == 0 else { throw FastCAError(String(format: "FastCA ký thất bại (%d, SW=%04X)", rv, status)) }
        let output = Data(signature.prefix(length))
        guard RSAPKCS1v15.verify(signature: output, payload: payload, certificateDER: identity.certificateDER) else {
            throw FastCAError("Chữ ký FastCA không khớp chứng thư/dữ liệu; đã từ chối kết quả")
        }
        return Array(output)
    }

    func logout(serial: String) { sessions.removeValue(forKey: serial) }
}
