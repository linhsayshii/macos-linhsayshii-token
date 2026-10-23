import Foundation
import CryptoKit
import Core
import CFastCA

struct ESPKError: Error, CustomStringConvertible {
    let description: String
    init(_ description: String) { self.description = description }
}

/// OpenSC handles CCID/secure messaging. ESPK metadata and commands belong to
/// this backend; no generic PKCS#11 module or injected shim is used.
enum NativeESPKProfile {
    case fastca, efy
    var atr: [UInt8] { self == .efy ? EfyProfile.atr : FastCAProfile.atr }
    var label: String { self == .efy ? "EFY-CA" : "FastCA" }
    var serialPrefix: String { self == .efy ? "EFY-" : "FASTCA-" }
    var transport: fca_profile { self == .efy ? FCA_PROFILE_EFY : FCA_PROFILE_FASTCA }
}

/// The injectable boundary covers the actual connection lifetime, including
/// metadata validation before PIN and reset on every attempted authentication.
protocol ESPKCardConnection: AnyObject {
    func read(_ fid: UInt16) throws -> Data
    func login(_ bytes: [UInt8]) throws -> LoginResult
    func sign(key: UInt16, block: [UInt8]) throws -> Data
    func close()
}

final class ESPKBackend: TokenBackend {
    private final class Connection: ESPKCardConnection {
        private var pointer: OpaquePointer?
        private let label: String
        init(runtime: OpaquePointer, reader: String, profile: NativeESPKProfile) throws {
            label = profile.label
            var pointer: OpaquePointer?
            let rv = fca_card_open_profile(runtime, reader, profile.transport, &pointer)
            guard rv == 0, let pointer else { throw ESPKError("\(label) kết nối thất bại (\(rv))") }
            self.pointer = pointer
        }
        deinit { close() }
        func close() { if let pointer { self.pointer = nil; fca_card_close(pointer) } }

        func read(_ fid: UInt16) throws -> Data {
            guard let pointer else { throw ESPKError("\(label) phiên đã đóng") }
            var bytes = [UInt8](repeating: 0, count: 65_536)
            var length = 0
            let rv = fca_read_file(pointer, fid, &bytes, bytes.count, &length)
            guard rv == 0 else { throw ESPKError(String(format: "\(label) đọc metadata %04X thất bại (%d)", fid, rv)) }
            return Data(bytes.prefix(length))
        }

        func login(_ input: [UInt8]) throws -> LoginResult {
            guard let pointer else { throw ESPKError("\(label) phiên đã đóng") }
            var bytes = input
            defer { bytes.withUnsafeMutableBytes { fca_wipe($0.baseAddress, $0.count) } }
            var status: UInt16 = 0
            let rv = fca_login(pointer, &bytes, bytes.count, &status)
            switch rv {
            case 0: return .ok
            case Int32(FCA_PIN_INCORRECT): return .pinIncorrect(retriesLeft: Int(status & 15))
            case Int32(FCA_PIN_LOCKED): return .pinLocked
            default: throw ESPKError(String(format: "\(label) xác thực thất bại (%d, SW=%04X); không tự thử lại", rv, status))
            }
        }

        func sign(key: UInt16, block input: [UInt8]) throws -> Data {
            guard let pointer else { throw ESPKError("\(label) phiên đã đóng") }
            var block = input
            defer { block.withUnsafeMutableBytes { fca_wipe($0.baseAddress, $0.count) } }
            var signature = [UInt8](repeating: 0, count: 256)
            var length = 0
            var status: UInt16 = 0
            let rv = fca_sign(pointer, key, &block, block.count, &signature, signature.count, &length, &status)
            guard rv == 0 else { throw ESPKError(String(format: "\(label) ký thất bại (%d, SW=%04X)", rv, status)) }
            return Data(signature.prefix(length))
        }
    }

    private struct Snapshot {
        let serial: String
        let identities: [ESPKSigningIdentity]
    }
    private struct Session {
        let connection: any ESPKCardConnection
        let snapshot: Snapshot
    }

    private var runtime: OpaquePointer?
    private var sessions: [String: Session] = [:]
    private let profile: NativeESPKProfile
    private let scan: () -> [(reader: String, atr: [UInt8])]
    private let connect: ((String) throws -> any ESPKCardConnection)?
    init(profile: NativeESPKProfile, scan: @escaping () -> [(reader: String, atr: [UInt8])] = { ReaderScanner().readers() },
         connect: ((String) throws -> any ESPKCardConnection)? = nil) {
        self.profile = profile; self.scan = scan; self.connect = connect
    }
    deinit {
        for session in sessions.values { session.connection.close() }
        sessions.removeAll() // Connections must close/reset before the runtime.
        if let runtime { fca_runtime_close(runtime) }
    }

    private func context() throws -> OpaquePointer {
        if let runtime { return runtime }
        let embedded = URL(fileURLWithPath: CommandLine.arguments[0]).standardizedFileURL
            .deletingLastPathComponent().appendingPathComponent("../Frameworks/ESPK/libopensc.13.dylib").standardizedFileURL.path
        let paths = [embedded, "/opt/homebrew/lib/libopensc.13.dylib", "/usr/local/lib/libopensc.13.dylib",
                     "/Library/OpenSC/lib/libopensc.13.dylib"]
        guard let path = paths.first(where: { FileManager.default.fileExists(atPath: $0) }) else {
            throw ESPKError("\(profile.label) cần OpenSC 0.27.1; chưa tìm thấy libopensc.13.dylib")
        }
        var pointer: OpaquePointer?
        var message = [CChar](repeating: 0, count: 512)
        let rv = fca_runtime_open(path, &pointer, &message, message.count)
        guard rv == 0, let pointer else {
            let bytes = message.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) }
            throw ESPKError(String(decoding: bytes, as: UTF8.self))
        }
        runtime = pointer
        return pointer
    }

    private func readers() -> [(reader: String, atr: [UInt8])] {
        scan().filter { $0.atr == profile.atr }
    }

    private func connection(reader: String) throws -> any ESPKCardConnection {
        if let connect { return try connect(reader) }
        return try Connection(runtime: context(), reader: reader, profile: profile)
    }

    private func snapshot(_ connection: any ESPKCardConnection) throws -> Snapshot {
        let files = try ESPKCatalog.parse(connection.read(0x6f01))
        guard let cardIDFile = files.first(where: { $0.directory.isEmpty && $0.name == "cardid" }) else {
            throw ESPKError("\(profile.label) thiếu cardid trong catalog")
        }
        let cardID = try connection.read(cardIDFile.id)
        guard !cardID.isEmpty else { throw ESPKError("\(profile.label) cardid rỗng") }
        // Stable across reader numbering/hotplug; independent of certificate renewal.
        let serial = profile.serialPrefix + SHA256.hash(data: cardID).prefix(8).map { String(format: "%02X", $0) }.joined()
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
            throw ESPKError("\(profile.label) không có chứng thư/khóa RSA tương thích khớp nhau")
        }
        return Snapshot(serial: serial, identities: identities)
    }

    private func open(serial: String) throws -> Session {
        var match: Session?
        var accepted = false
        defer { if !accepted { match?.connection.close() } }
        for reader in readers() {
            let connection = try connection(reader: reader.reader)
            var keep = false
            defer { if !keep { connection.close() } }
            let metadata = try snapshot(connection)
            if metadata.serial == serial {
                guard match == nil else { throw ESPKError("\(profile.label) có nhiều token trùng cardid; chưa gửi PIN") }
                match = Session(connection: connection, snapshot: metadata); keep = true
            }
        }
        guard let match else { throw ESPKError("Không tìm thấy đúng token \(profile.label); hãy kiểm tra USB") }
        accepted = true
        return match
    }

    func listTokens() throws -> [TokenInfo] {
        var serials = Set<String>()
        return try readers().enumerated().map { index, reader in
            let connection = try connection(reader: reader.reader)
            defer { connection.close() }
            let metadata = try snapshot(connection)
            guard serials.insert(metadata.serial).inserted else { throw ESPKError("\(profile.label) có nhiều token trùng cardid") }
            return TokenInfo(slot: UInt(index), reader: reader.reader, serial: metadata.serial,
                             label: profile.label, flags: ["PIN_RETRIES_UNKNOWN"])
        }
    }

    func certs(serial: String) throws -> [CertInfo] {
        let session = try open(serial: serial)
        defer { session.connection.close() }
        return try session.snapshot.identities.map {
            guard let info = PKCS11.makeCertInfo(id: Array($0.id), der: Array($0.certificateDER)) else {
                throw ESPKError("Chứng thư \(profile.label) không hợp lệ")
            }
            return info
        }
    }

    func login(serial: String, pin: String) throws -> LoginResult {
        guard sessions[serial] == nil else { throw ESPKError("\(profile.label) đã có phiên xác thực") }
        var bytes = Array(pin.utf8)
        defer { bytes.withUnsafeMutableBytes { fca_wipe($0.baseAddress, $0.count) } }
        guard (1...64).contains(bytes.count), bytes.allSatisfy({ $0 >= 0x20 && $0 <= 0x7e }) else {
            throw ESPKError("PIN \(profile.label) phải có 1–64 ký tự ASCII; chưa gửi xác thực")
        }
        let session = try open(serial: serial)
        var keep = false
        defer { if !keep { session.connection.close() } }
        let result = try session.connection.login(bytes)
        if result == .ok {
            sessions[serial] = session
            keep = true
        }
        return result
    }

    func sign(serial: String, certId: String, mech: SignMech, data: [UInt8]) throws -> [UInt8] {
        guard let session = sessions[serial] else { throw ESPKError("\(profile.label) chưa đăng nhập") }
        defer { logout(serial: serial) }
        guard let identity = session.snapshot.identities.first(where: {
            $0.id.map { String(format: "%02x", $0) }.joined() == certId.lowercased()
        }) else { throw ESPKError("Không tìm thấy đúng khóa của chứng thư \(profile.label)") }
        let payload: Data
        switch mech {
        case .rsaPKCS: payload = Data(data)
        case .sha256RSA: payload = Data(try DigestInfo.sha256Block(Data(data)))
        case .rsaX509: throw ESPKError("\(profile.label) chưa hỗ trợ yêu cầu RSA_X_509")
        }
        var block = Array(try RSAPKCS1v15.encode(payload, modulusBytes: identity.modulus.count))
        defer { block.withUnsafeMutableBytes { fca_wipe($0.baseAddress, $0.count) } }
        let output = try session.connection.sign(key: identity.keyReference, block: block)
        guard output.count == 256, RSAPKCS1v15.verify(signature: output, payload: payload, certificateDER: identity.certificateDER) else {
            throw ESPKError("Chữ ký \(profile.label) không khớp chứng thư/dữ liệu; đã từ chối kết quả")
        }
        return Array(output)
    }

    func logout(serial: String) { sessions.removeValue(forKey: serial)?.connection.close() }
}
