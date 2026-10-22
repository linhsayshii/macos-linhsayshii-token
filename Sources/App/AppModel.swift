import Foundation
import Core
import Bridges

/// Ties ReaderScanner + ModuleRegistry + TokenBroker + CTSignBridge together and
/// drives the menu bar: lists tokens and certs, serves the CTSigningHub bridge,
/// and runs the raw-data sign path (approval → PIN sheet → broker login/sign/logout).
/// CTSigningHub SignHash wraps the precomputed hash in a DigestInfo and signs it
/// on-card with CKM_RSA_PKCS — see Backend.sign.
@MainActor
public final class AppModel: ObservableObject {
    /// Prompt state for the PIN sheet. Non-nil presents the sheet; a sign call
    /// awaits the user's answer via `pinCont`.
    struct PINPrompt: Identifiable { let id = UUID(); let ca, serial: String; let warning: String?; let locked: Bool }
    struct ApprovalPrompt: Identifiable { let id = UUID(); let origin, subject, ca, notAfter, operation: String; let docCount: Int }
    enum ApprovalChoice: Sendable { case session, once, deny }

    private struct SignTarget { let module: ModuleInfo; let cert: CertInfo; let flags: [String] }

    public struct TokenRow: Identifiable, Sendable {
        public var id: String { serial.isEmpty ? reader : serial }
        public let ca: String
        public let supported: Bool
        public let reader: String
        public var serial: String
        public var label: String
        public var certSubject: String?
        public var notAfter: String?
    }

    public enum BridgeStatus: Sendable, Equatable { case starting, up, portInUse, failed(String) }

    @Published public private(set) var tokens: [TokenRow] = []
    @Published public private(set) var bridgeStatus: BridgeStatus = .starting
    @Published private(set) var lastSignResult: String?
    // Non-nil while a sign is running (login→sign→logout, ~10s on some tokens);
    // the menu shows it so the user isn't left guessing after submitting the PIN.
    @Published private(set) var signingStatus: String?
    @Published var pinPrompt: PINPrompt?
    @Published var approvalPrompt: ApprovalPrompt?
    // SecureField binds here (toolchain lacks the SwiftUI @State macro). Cleared on submit.
    @Published var pinDraft = ""

    private let scanner = ReaderScanner()
    private let broker: TokenBroker
    private let approval = ApprovalCenter()
    private var server: HTTPServer?
    private var scanTask: Task<Void, Never>?

    // Sign targets by serial from the last scan: module, chosen cert, token flags.
    private var signTargets: [String: SignTarget] = [:]
    private var signing = false   // vendor PC/SC lock: pause the scan during a sign
    private var pinCont: CheckedContinuation<String?, Never>?
    private var approvalCont: CheckedContinuation<ApprovalChoice, Never>?

    public init() {
        // Helper + shim live next to the app binary (bundle Contents/Helpers in a
        // packaged build; the build dir during development).
        let binDir = URL(fileURLWithPath: CommandLine.arguments[0]).deletingLastPathComponent()
        let helper = binDir.appendingPathComponent("TokenHelper")
        let shim = binDir.appendingPathComponent("libTSShim.dylib")
        let appModules = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("TokenSigner/modules", isDirectory: true)
        try? FileManager.default.createDirectory(at: appModules, withIntermediateDirectories: true)
        let moduleDirs = [URL(fileURLWithPath: "/usr/local/lib"), appModules]
        self.broker = TokenBroker(helperURL: helper, shimURL: shim, moduleDirs: moduleDirs)
    }

    private var started = false

    public func start() {
        guard !started else { return }   // MenuBarExtra onAppear can fire repeatedly
        started = true
        startServer()
        scanTask = Task { [weak self] in
            while !Task.isCancelled {
                await self?.scanTick()
                try? await Task.sleep(for: .milliseconds(500))
            }
        }
    }

    private var lastReaderSig = ""

    // Listing readers is a cheap PC/SC call; the full refresh (helper spawns for
    // listTokens/listCerts) is not. Poll readers fast so plug/unplug shows up
    // quickly, but only run the full refresh when the reader set actually changes.
    private func scanTick() async {
        if signing { return }   // a sign holds the vendor lock
        let sig = scanner.readers()
            .map { "\($0.reader):\(Data($0.atr).base64EncodedString())" }
            .joined(separator: "|")
        guard sig != lastReaderSig else { return }
        lastReaderSig = sig
        await refreshTokens()
    }

    private func startServer() {
        let bridge = CTSignBridge(backend: Backend(model: self))
        let server = HTTPServer(bridge: bridge, port: 32001, allowlist: .defaults)
        self.server = server
        Task {
            do { try await server.start(); self.bridgeStatus = .up }
            catch HTTPServer.StartError.portInUse { self.bridgeStatus = .portInUse }
            catch { self.bridgeStatus = .failed("\(error)") }
        }
    }

    // Certs cached by the scan loop. The bridge reads this instead of spawning
    // its own helpers, so token access stays serialized in one place (vendor libs
    // hold an exclusive PC/SC lock; concurrent helpers on one token deadlock).
    private var cachedCerts: [CertInfo] = []

    private func refreshTokens() async {
        if signing { return }   // a sign holds the vendor lock; scanning would deadlock
        var rows: [TokenRow] = []
        var certCache: [CertInfo] = []
        var targets: [String: SignTarget] = [:]
        // One module per CA: dedupe so two readers of the same CA don't spawn
        // two concurrent helpers against the vendor lib.
        var seenModules = Set<String>()
        for r in scanner.readers() {
            guard let module = ModuleRegistry.lookup(atr: r.atr) else {
                rows.append(TokenRow(ca: "Chưa hỗ trợ", supported: false, reader: r.reader,
                                     serial: "", label: "", certSubject: nil, notAfter: nil))
                continue
            }
            var row = TokenRow(ca: module.ca, supported: true, reader: r.reader,
                               serial: "", label: "", certSubject: nil, notAfter: nil)
            if !seenModules.contains(module.moduleName),
               case let .tokens(list) = (try? await broker.request(.listTokens, module: module)) ?? .error("") {
                seenModules.insert(module.moduleName)
                for t in list {
                    if case let .certs(certs) = (try? await broker.request(.listCerts(serial: t.serial), module: module)) ?? .error("") {
                        certCache.append(contentsOf: certs)
                        if let c = certs.first {
                            targets[t.serial] = SignTarget(module: module, cert: c, flags: t.flags)
                        }
                        if t.reader == r.reader || list.count == 1 {
                            row.serial = t.serial; row.label = t.label
                            if let c = certs.first { row.certSubject = c.subject; row.notAfter = c.notAfter }
                        }
                    }
                }
            }
            rows.append(row)
        }
        self.tokens = rows
        self.cachedCerts = certCache
        self.signTargets = targets
    }

    // MARK: - Sign path (raw data)

    /// Approval → PIN → one login/sign/logout spawn. Returns the base64 signature.
    /// `dataB64` is the raw message: hashed SHA-256 in software, wrapped in a PKCS#1
    /// v1.5 DigestInfo, then signed on-card with CKM_RSA_PKCS (on-card hashing fails
    /// for data ≥240B on these tokens).
    func sign(origin: String, serial: String, dataB64: String, operation: String, docCount: Int) async throws -> String {
        guard let raw = Data(base64Encoded: dataB64) else { throw TokenBroker.SignError.card("dữ liệu ký không hợp lệ") }
        let block = try DigestInfo.sha256Block(raw)
        return try await signPreparedBlock(origin: origin, serial: serial,
                                           blockB64: Data(block).base64EncodedString(),
                                           operation: operation, docCount: docCount)
    }

    /// Approval → PIN → one login/sign/logout spawn. `blockB64` is the already-built
    /// RSA PKCS#1 v1.5 DigestInfo block (base64), signed on-card with CKM_RSA_PKCS.
    fileprivate func signPreparedBlock(origin: String, serial: String, blockB64: String, operation: String, docCount: Int) async throws -> String {
        guard let target = signTargets[serial] else { throw CTSignError.unknownSerial(serial) }
        signing = true
        defer { signing = false }

        if await approval.decide(origin: origin, certSerial: target.cert.serialHex) != .allowedSession {
            approvalPrompt = ApprovalPrompt(origin: origin, subject: target.cert.subject, ca: target.module.ca,
                                            notAfter: target.cert.notAfter, operation: operation, docCount: docCount)
            switch await withCheckedContinuation({ approvalCont = $0 }) {
            case .deny: throw TokenBroker.SignError.card("Người dùng từ chối ký")
            case .session: await approval.allow(origin: origin, certSerial: target.cert.serialHex, minutes: 10)
            case .once: break
            }
        }

        let w = pinWarning(target.flags)
        pinPrompt = PINPrompt(ca: target.module.ca, serial: serial, warning: w.text, locked: w.locked)
        guard let pin = await withCheckedContinuation({ (c: CheckedContinuation<String?, Never>) in pinCont = c }),
              !pin.isEmpty else { throw TokenBroker.SignError.card("Đã huỷ nhập PIN") }

        signingStatus = "Đang ký…"
        defer { signingStatus = nil }
        return try await broker.sign(module: target.module, serial: serial, certId: target.cert.id,
                                     mech: .rsaPKCS, dataB64: blockB64, pin: pin)
    }

    /// Sign a fixed test string so the login/sign path can be exercised from the
    /// menu to exercise the login/sign path without a web request.
    func testSign(serial: String) async {
        let data = Data("TokenSigner ký thử \(Date())".utf8)
        do {
            let sig = try await sign(origin: "TokenSigner (ký thử)", serial: serial,
                                     dataB64: data.base64EncodedString(), operation: "Ký thử", docCount: 1)
            lastSignResult = "Ký OK — chữ ký \(Data(base64Encoded: sig)?.count ?? 0) byte"
        } catch {
            lastSignResult = "Lỗi ký: \(signErrorText(error))"
        }
    }

    /// Human-readable Vietnamese for a sign failure. pinIncorrect surfaces the
    /// remaining try count — the number that matters before a lockout.
    private func signErrorText(_ error: Error) -> String {
        guard let e = error as? TokenBroker.SignError else { return "\(error)" }
        switch e {
        case .loginFailed(.pinIncorrect(let n)):
            return n.map { "sai PIN, còn \($0) lần thử" } ?? "sai PIN"
        case .loginFailed(.pinLocked): return "token đã bị khoá PIN"
        case .loginFailed(.ok): return "đăng nhập không thành công"
        case .card(let m): return m
        case .noSignature: return "thẻ không trả về chữ ký"
        }
    }

    func submitPIN(_ pin: String?) { pinDraft = ""; pinPrompt = nil; pinCont?.resume(returning: pin); pinCont = nil }
    func submitApproval(_ choice: ApprovalChoice) { approvalPrompt = nil; approvalCont?.resume(returning: choice); approvalCont = nil }

    private func pinWarning(_ flags: [String]) -> (text: String?, locked: Bool) {
        if flags.contains("USER_PIN_LOCKED") { return ("PIN đã bị khoá", true) }
        if flags.contains("USER_PIN_FINAL_TRY") { return ("Còn 1 lần thử — sai là khoá token", false) }
        if flags.contains("USER_PIN_COUNT_LOW") { return ("Token sắp bị khoá — nhập PIN cẩn thận", false) }
        return (nil, false)
    }

    // Certificates for the bridge: the last scan's cache, no fresh spawning.
    func certificates() async -> [CertInfo] { cachedCerts }
}

/// Bridge backend. Serves certificates and SignHash: CTSigningHub sends a
/// precomputed SHA-256 hash, which we wrap in a PKCS#1 v1.5 DigestInfo and sign
/// on-card with CKM_RSA_PKCS — the same path document signing uses.
struct Backend: SigningBackend {
    let model: AppModel
    func certificates() async -> [CertInfo] { await model.certificates() }
    func sign(serial: String, digestB64: String) async throws -> String {
        // DLieuHash is a precomputed SHA-256 (32 bytes), base64 — or hex. Decode,
        // do NOT re-hash, wrap in DigestInfo, sign RSA_PKCS. shortcut: one PIN/spawn
        // per hash item (fine for single-doc SignHash; batch later for multi-hash).
        guard let digest = decodeSHA256(digestB64) else { throw CTSignError.precomputedHashUnsupported }
        let block = try DigestInfo.wrap(Array(digest), .sha256)
        return try await model.signPreparedBlock(origin: "CTSigningHub", serial: serial,
                                                 blockB64: Data(block).base64EncodedString(),
                                                 operation: "Ký", docCount: 1)
    }

    /// Accept a 32-byte SHA-256 as base64 (CTSigningHub default) or hex.
    private func decodeSHA256(_ s: String) -> Data? {
        if let d = Data(base64Encoded: s), d.count == 32 { return d }
        let hex = s.count == 64 ? s : ""
        var out = Data(); var i = hex.startIndex
        while i < hex.endIndex {
            let j = hex.index(i, offsetBy: 2)
            guard let b = UInt8(hex[i..<j], radix: 16) else { return nil }
            out.append(b); i = j
        }
        return out.count == 32 ? out : nil
    }
}
