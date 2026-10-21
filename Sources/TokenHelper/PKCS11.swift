// Minimal Cryptoki access: dlopen the vendor module, get C_GetFunctionList, and
// expose the read-only calls token-helper needs. Every call goes through the
// function list so the SCardTransmit interpose in libTSShim.dylib applies
// underneath. P1 scope: listTokens and certs only (no login/sign).
import Foundation
import Core
import CPKCS11
import X509
import SwiftASN1

struct PKCS11Error: Error, CustomStringConvertible {
    let description: String
    init(_ m: String) { description = m }
}

final class PKCS11 {
    private let modulePath: String
    private var handle: UnsafeMutableRawPointer?
    private var fl: CK_FUNCTION_LIST_PTR?
    private var loadError: Error?

    init(modulePath: String) { self.modulePath = modulePath }

    func listTokens() throws -> [TokenInfo] {
        let fl = try functions()
        var out: [TokenInfo] = []
        for slot in try slotList(fl) {
            var ti = CK_TOKEN_INFO()
            guard fl.pointee.C_GetTokenInfo(slot, &ti) == CKR_OK else { continue }
            var si = CK_SLOT_INFO()
            let reader = fl.pointee.C_GetSlotInfo(slot, &si) == CKR_OK ? Self.trimmed(si.slotDescription) : ""
            var flags: [String] = []
            let f = ti.flags
            if f & CK_FLAGS(CKF_USER_PIN_COUNT_LOW) != 0 { flags.append("USER_PIN_COUNT_LOW") }
            if f & CK_FLAGS(CKF_USER_PIN_FINAL_TRY) != 0 { flags.append("USER_PIN_FINAL_TRY") }
            if f & CK_FLAGS(CKF_USER_PIN_LOCKED) != 0 { flags.append("USER_PIN_LOCKED") }
            out.append(TokenInfo(slot: UInt(slot), reader: reader,
                                 serial: Self.trimmed(ti.serialNumber),
                                 label: Self.trimmed(ti.label), flags: flags))
        }
        return out
    }

    func certs(serial: String) throws -> [CertInfo] {
        let fl = try functions()
        guard let slot = try findSlot(serial: serial, fl) else {
            throw PKCS11Error("no token with serial \(serial)")
        }
        var session: CK_SESSION_HANDLE = 0
        let rv = fl.pointee.C_OpenSession(slot, CK_FLAGS(CKF_SERIAL_SESSION), nil, nil, &session)
        guard rv == CKR_OK else { throw PKCS11Error("C_OpenSession rv=\(rv)") }
        defer { _ = fl.pointee.C_CloseSession(session) }

        var certClass = CK_OBJECT_CLASS(CKO_CERTIFICATE)
        var result: [CertInfo] = []
        try withUnsafeMutablePointer(to: &certClass) { cp in
            var tmpl = CK_ATTRIBUTE(type: CK_ATTRIBUTE_TYPE(CKA_CLASS),
                                    pValue: UnsafeMutableRawPointer(cp),
                                    ulValueLen: CK_ULONG(MemoryLayout<CK_OBJECT_CLASS>.size))
            guard fl.pointee.C_FindObjectsInit(session, &tmpl, 1) == CKR_OK else {
                throw PKCS11Error("C_FindObjectsInit failed")
            }
            defer { _ = fl.pointee.C_FindObjectsFinal(session) }
            while true {
                var obj: CK_OBJECT_HANDLE = 0
                var found: CK_ULONG = 0
                guard fl.pointee.C_FindObjects(session, &obj, 1, &found) == CKR_OK, found > 0 else { break }
                guard let der = readAttr(fl, session, obj, CK_ATTRIBUTE_TYPE(CKA_VALUE)), !der.isEmpty else { continue }
                let id = readAttr(fl, session, obj, CK_ATTRIBUTE_TYPE(CKA_ID)) ?? []
                if let info = Self.makeCertInfo(id: id, der: der) { result.append(info) }
            }
        }
        return result
    }

    // MARK: - module load

    private func functions() throws -> CK_FUNCTION_LIST_PTR {
        if let fl { return fl }
        if let loadError { throw loadError }
        do { let loaded = try load(); fl = loaded; return loaded }
        catch { loadError = error; throw error }
    }

    private func load() throws -> CK_FUNCTION_LIST_PTR {
        guard let h = dlopen(modulePath, RTLD_NOW) else {
            throw PKCS11Error("dlopen failed: \(String(cString: dlerror()))")
        }
        handle = h
        guard let sym = dlsym(h, "C_GetFunctionList") else {
            throw PKCS11Error("C_GetFunctionList not found in \(modulePath)")
        }
        typealias GetFL = @convention(c) (CK_FUNCTION_LIST_PTR_PTR?) -> CK_RV
        let getFL = unsafeBitCast(sym, to: GetFL.self)
        var listPtr: CK_FUNCTION_LIST_PTR?
        let rv = getFL(&listPtr)
        guard rv == CKR_OK, let fl = listPtr else { throw PKCS11Error("C_GetFunctionList rv=\(rv)") }
        try initialize(fl)
        return fl
    }

    private func initialize(_ fl: CK_FUNCTION_LIST_PTR) throws {
        var args = CK_C_INITIALIZE_ARGS()
        args.flags = CK_FLAGS(CKF_OS_LOCKING_OK)
        var rv = withUnsafeMutablePointer(to: &args) {
            fl.pointee.C_Initialize(UnsafeMutableRawPointer($0))
        }
        if rv == CKR_CRYPTOKI_ALREADY_INITIALIZED { return }
        if rv != CKR_OK {
            // Locking-mode rejected: retry with NULL args (single-threaded).
            rv = fl.pointee.C_Initialize(nil)
            guard rv == CKR_OK || rv == CKR_CRYPTOKI_ALREADY_INITIALIZED else {
                throw PKCS11Error("C_Initialize rv=\(rv)")
            }
        }
    }

    // MARK: - helpers

    private func slotList(_ fl: CK_FUNCTION_LIST_PTR) throws -> [CK_SLOT_ID] {
        var count: CK_ULONG = 0
        guard fl.pointee.C_GetSlotList(CK_BBOOL(CK_TRUE), nil, &count) == CKR_OK else {
            throw PKCS11Error("C_GetSlotList (count) failed")
        }
        if count == 0 { return [] }
        var slots = [CK_SLOT_ID](repeating: 0, count: Int(count))
        guard fl.pointee.C_GetSlotList(CK_BBOOL(CK_TRUE), &slots, &count) == CKR_OK else {
            throw PKCS11Error("C_GetSlotList failed")
        }
        return Array(slots.prefix(Int(count)))
    }

    private func findSlot(serial: String, _ fl: CK_FUNCTION_LIST_PTR) throws -> CK_SLOT_ID? {
        for slot in try slotList(fl) {
            var ti = CK_TOKEN_INFO()
            guard fl.pointee.C_GetTokenInfo(slot, &ti) == CKR_OK else { continue }
            if Self.trimmed(ti.serialNumber) == serial { return slot }
        }
        return nil
    }

    private func readAttr(_ fl: CK_FUNCTION_LIST_PTR, _ session: CK_SESSION_HANDLE,
                          _ obj: CK_OBJECT_HANDLE, _ type: CK_ATTRIBUTE_TYPE) -> [UInt8]? {
        var attr = CK_ATTRIBUTE(type: type, pValue: nil, ulValueLen: 0)
        guard fl.pointee.C_GetAttributeValue(session, obj, &attr, 1) == CKR_OK else { return nil }
        let len = Int(attr.ulValueLen)
        guard len > 0, len < 1_000_000 else { return len == 0 ? [] : nil }
        var buf = [UInt8](repeating: 0, count: len)
        let rv = buf.withUnsafeMutableBytes { p -> CK_RV in
            attr.pValue = p.baseAddress
            attr.ulValueLen = CK_ULONG(len)
            return fl.pointee.C_GetAttributeValue(session, obj, &attr, 1)
        }
        return rv == CKR_OK ? buf : nil
    }

    /// Fixed-size CK_UTF8CHAR arrays are space-padded; trim trailing spaces/nulls.
    private static func trimmed<T>(_ tuple: T) -> String {
        withUnsafeBytes(of: tuple) { raw in
            var bytes = Array(raw.bindMemory(to: UInt8.self))
            while let last = bytes.last, last == 0x20 || last == 0x00 { bytes.removeLast() }
            return String(decoding: bytes, as: UTF8.self)
        }
    }

    private static let dateFmt: DateFormatter = {
        let f = DateFormatter()
        f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(identifier: "UTC")
        f.dateFormat = "yyyy-MM-dd HH:mm:ss"
        return f
    }()

    private static func makeCertInfo(id: [UInt8], der: [UInt8]) -> CertInfo? {
        guard let cert = try? Certificate(derEncoded: der) else { return nil }
        return CertInfo(
            id: id.map { String(format: "%02x", $0) }.joined(),
            derB64: Data(der).base64EncodedString(),
            subject: String(describing: cert.subject),
            issuer: String(describing: cert.issuer),
            serialHex: cert.serialNumber.bytes.map { String(format: "%02X", $0) }.joined(),
            notBefore: dateFmt.string(from: cert.notValidBefore),
            notAfter: dateFmt.string(from: cert.notValidAfter))
    }
}
