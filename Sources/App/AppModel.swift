import Foundation
import Core
import Bridges

/// Ties ReaderScanner + ModuleRegistry + TokenBroker + CTSignBridge together and
/// drives the menu bar: lists tokens and certs, serves the CTSigningHub bridge,
/// and runs the raw-data sign path (approval → PIN sheet → broker login/sign/logout).
/// CTSigningHub SignHash is stubbed — see Backend.sign — because these tokens
/// cannot sign the precomputed hash it sends.
@MainActor
public final class AppModel: ObservableObject, SigningService {
    /// Prompt state for the PIN sheet. Non-nil presents the sheet; a sign call
    /// awaits the user's answer via `pinCont`.
    struct PINPrompt: Identifiable { let id = UUID(); let ca, serial: String; let warning: String?; let locked: Bool }
    struct ApprovalPrompt: Identifiable { let id = UUID(); let origin, subject, ca, notAfter, operation: String; let docCount: Int }
    enum ApprovalChoice: Sendable { case session, once, deny }

    private struct SignTarget { let tokenSerial: String; let module: ModuleInfo; let cert: CertInfo; let flags: [String] }

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
    public struct BridgeRow: Identifiable, Sendable, Equatable {
        public var id: String { name }
        public let name: String
        public var port: Int
        public var status: BridgeStatus
    }

    @Published public private(set) var tokens: [TokenRow] = []
    @Published public private(set) var bridges: [BridgeRow] = [
        BridgeRow(name: "CTSigningHub", port: 32001, status: .starting),
        BridgeRow(name: "eSigner", port: 8768, status: .starting),
        BridgeRow(name: "VNPT-CA Plugin", port: 4433, status: .starting),
        BridgeRow(name: "VNPT-CA Plugin (DVC)", port: 4434, status: .starting),
    ]
    @Published public private(set) var recentAudit: [AuditEntry] = []
    @Published public private(set) var activeSigns = 0
    @Published public private(set) var localhostTrusted = true
    // First unknown origin waiting for the user's allow/deny.
    @Published var originPrompt: String?
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
    private let audit = AuditLog(fileURL: AppModel.supportDir.appendingPathComponent("audit.jsonl"))
    let localCA = LocalCA(directory: AppModel.supportDir.appendingPathComponent("tls", isDirectory: true))
    private var wsServers: [WSServer] = []
    private var pendingOrigins: [String] = []
    let originStore = OriginStore(fileURL: AppModel.supportDir.appendingPathComponent("origins.json"))
    static let supportDir = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
        .appendingPathComponent("TokenSigner", isDirectory: true)
    private var server: HTTPServer?
    private var scanTask: Task<Void, Never>?

    // Sign targets by serial from the last scan: module, chosen cert, token flags.
    private var signTargets: [SignTarget] = []   // one per certificate, latest expiry first
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
        startServers()
        refreshAudit()
        Task { [weak self] in
            while !Task.isCancelled {
                await self?.pollOrigins()
                try? await Task.sleep(for: .seconds(1))
            }
        }
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

    private func setBridge(_ name: String, port: Int? = nil, _ status: BridgeStatus) {
        guard let i = bridges.firstIndex(where: { $0.name == name }) else { return }
        bridges[i].status = status
        if let port { bridges[i].port = port }
    }

    private func startServers() {
        // Dev only: shift every port so a second instance can run next to an installed one.
        let off = Int(ProcessInfo.processInfo.environment["TOKENSIGNER_PORT_OFFSET"] ?? "") ?? 0
        let ct = CTSignBridge(backend: Backend(model: self), service: self)
        let http = HTTPServer(bridge: ct, port: 32001 + off, store: originStore)
        self.server = http
        Task {
            do { try await http.start(); setBridge("CTSigningHub", .up) }
            catch HTTPServer.StartError.portInUse { setBridge("CTSigningHub", .portInUse) }
            catch { setBridge("CTSigningHub", .failed("\(error)")) }
        }

        let es = ESignerBridge(service: self)
        let esServer = WSServer(ports: [8768 + off, 8769 + off], pathPrefix: "/plugin/sign", store: originStore) { t, o in await es.handle(text: t, origin: o) }
        let vn = VNPTBridge(service: self)
        let tlsContext = try? localCA.sslContext()
        let vnServer = WSServer(ports: [4433 + off], pathPrefix: "/plugin", store: originStore, tls: tlsContext) { t, o in await vn.handle(text: t, origin: o) }
        // The DVC portal connects to wss://localhost:4434/plugin (seen in browser DevTools), so serve the same bridge there too.
        let dvcServer = WSServer(ports: [4434 + off], pathPrefix: "/plugin", store: originStore, tls: tlsContext) { t, o in await vn.handle(text: t, origin: o) }
        wsServers = [esServer, vnServer, dvcServer]
        Task {
            do { setBridge("eSigner", port: try await esServer.start(), .up) }
            catch WSServer.StartError.portInUse { setBridge("eSigner", .portInUse) }
            catch { setBridge("eSigner", .failed("\(error)")) }
        }
        Task {
            guard tlsContext != nil else { return setBridge("VNPT-CA Plugin", .failed("không tạo được chứng chỉ localhost")) }
            do { setBridge("VNPT-CA Plugin", port: try await vnServer.start(), .up) }
            catch WSServer.StartError.portInUse { setBridge("VNPT-CA Plugin", .portInUse) }
            catch { setBridge("VNPT-CA Plugin", .failed("\(error)")) }
        }
        Task {
            guard tlsContext != nil else { return setBridge("VNPT-CA Plugin (DVC)", .failed("không tạo được chứng chỉ localhost")) }
            do { setBridge("VNPT-CA Plugin (DVC)", port: try await dvcServer.start(), .up) }
            catch WSServer.StartError.portInUse { setBridge("VNPT-CA Plugin (DVC)", .portInUse) }
            catch { setBridge("VNPT-CA Plugin (DVC)", .failed("\(error)")) }
        }
        Task.detached { [localCA] in
            let ok = localCA.isTrusted()
            await MainActor.run { self.localhostTrusted = ok }
        }
    }

    /// Settings action: user-initiated, macOS asks for their password.
    func trustLocalhostCertificate() {
        let cmd = localCA.trustCommand()
        Task.detached { [localCA] in
            let p = Process()
            p.executableURL = URL(fileURLWithPath: cmd[0]); p.arguments = Array(cmd.dropFirst())
            try? p.run(); p.waitUntilExit()
            let ok = localCA.isTrusted()
            await MainActor.run { self.localhostTrusted = ok }
        }
    }

    private func pollOrigins() async {
        pendingOrigins.append(contentsOf: await originStore.takePending().filter { !pendingOrigins.contains($0) })
        if originPrompt == nil, !pendingOrigins.isEmpty { originPrompt = pendingOrigins.removeFirst() }
    }

    func answerOrigin(allow: Bool) {
        guard let o = originPrompt else { return }
        originPrompt = nil
        guard allow, let host = OriginAllowlist.host(of: o) else { return }
        Task { try? await originStore.add(host) }
    }

    private func refreshAudit() { Task { recentAudit = await audit.recent(10).reversed() } }

    // Certs cached by the scan loop. The bridge reads this instead of spawning
    // its own helpers, so token access stays serialized in one place (vendor libs
    // hold an exclusive PC/SC lock; concurrent helpers on one token deadlock).
    private var cachedCerts: [CertInfo] = []

    private func refreshTokens() async {
        if signing { return }   // a sign holds the vendor lock; scanning would deadlock
        var rows: [TokenRow] = []
        var certCache: [CertInfo] = []
        var targets: [SignTarget] = []
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
                        let sorted = certs.sorted { $0.notAfter > $1.notAfter }   // same-format dates sort as strings
                        certCache.append(contentsOf: sorted)
                        for c in sorted { targets.append(SignTarget(tokenSerial: t.serial, module: module, cert: c, flags: t.flags)) }
                        if t.reader == r.reader || list.count == 1 {
                            row.serial = t.serial; row.label = t.label
                            if let c = sorted.first { row.certSubject = c.subject; row.notAfter = c.notAfter }
                        }
                    }
                }
            }
            rows.append(row)
        }
        self.tokens = rows
        self.signTargets = targets.sorted { $0.cert.notAfter > $1.cert.notAfter }
        self.cachedCerts = self.signTargets.map(\.cert)
    }

    // MARK: - Sign path

    private var busy = false
    private var waiters: [CheckedContinuation<Void, Never>] = []
    /// Signs run one at a time: one PIN sheet, one vendor PC/SC lock.
    private func acquire() async {
        if busy { await withCheckedContinuation { waiters.append($0) } } else { busy = true }
    }
    private func release() { if waiters.isEmpty { busy = false } else { waiters.removeFirst().resume() } }

    private static let certDate: DateFormatter = {
        let f = DateFormatter(); f.locale = Locale(identifier: "en_US_POSIX"); f.dateFormat = "yyyy-MM-dd HH:mm:ss"; return f
    }()

    /// Certificate serial (bridges send this) or token serial; nil picks the still-valid certificate that expires last.
    private func resolve(_ serial: String?) throws -> (tokenSerial: String, target: SignTarget) {
        let valid = signTargets.filter { Self.certDate.date(from: $0.cert.notAfter).map { $0 > Date() } ?? true }
        let pick: SignTarget?
        if let s = serial, !s.isEmpty {
            pick = signTargets.first { $0.cert.serialHex.caseInsensitiveCompare(s) == .orderedSame }
                ?? valid.first { $0.tokenSerial == s } ?? signTargets.first { $0.tokenSerial == s }
            guard let pick else { throw SigningFailure.unknownSerial(s) }
            return (pick.tokenSerial, pick)
        }
        guard let pick = valid.first ?? signTargets.first else { throw SigningFailure.unknownSerial("") }
        return (pick.tokenSerial, pick)
    }

    /// Approval sheet unless an (origin, cert) session is active. Throws on deny.
    private func authorize(origin: String, target: SignTarget, operation: String, docCount: Int) async throws {
        if let exp = Self.certDate.date(from: target.cert.notAfter), exp < Date() { throw SigningFailure.certExpired }
        if await approval.decide(origin: origin, certSerial: target.cert.serialHex) == .allowedSession { return }
        approvalPrompt = ApprovalPrompt(origin: origin, subject: target.cert.subject, ca: target.module.ca,
                                        notAfter: target.cert.notAfter, operation: operation, docCount: docCount)
        switch await withCheckedContinuation({ approvalCont = $0 }) {
        case .deny: throw SigningFailure.userDenied
        case .session: await approval.allow(origin: origin, certSerial: target.cert.serialHex, minutes: 10)
        case .once: break
        }
    }

    private func askPIN(tokenSerial: String, target: SignTarget) async throws -> String {
        let w = pinWarning(target.flags)
        pinPrompt = PINPrompt(ca: target.module.ca, serial: tokenSerial, warning: w.text, locked: w.locked)
        guard let pin = await withCheckedContinuation({ (c: CheckedContinuation<String?, Never>) in pinCont = c }),
              !pin.isEmpty else { throw SigningFailure.userCancelled }
        signingStatus = "Đang ký…"
        return pin
    }

    private func failure(_ e: Error) -> SigningFailure {
        if let f = e as? SigningFailure { return f }
        return .card(signErrorText(e))
    }

    /// Shared flow for every bridge operation: queue → resolve → approve → sign → audit.
    private func perform(_ ctx: BridgeContext, serial: String?, operation: String, input: Data,
                         _ body: @escaping (MessageSigner) async throws -> Data) async throws -> Data {
        activeSigns += 1
        await acquire()
        signing = true
        var certSerial = serial ?? ""
        var result = "ok"
        defer {
            signing = false; signingStatus = nil; activeSigns -= 1; release()
        }
        do {
            let (tokenSerial, target) = try resolve(serial)
            certSerial = target.cert.serialHex
            try await authorize(origin: ctx.origin, target: target, operation: operation, docCount: 1)
            let signer = BrokerSigner(broker: broker, module: target.module, serial: tokenSerial, cert: target.cert) { [self] in
                try await askPIN(tokenSerial: tokenSerial, target: target)
            }
            let out = try await body(signer)
            await audit.append(origin: ctx.origin, bridge: ctx.bridge, certSerial: certSerial, operation: operation, input: input, result: result)
            refreshAudit()
            return out
        } catch {
            let f = failure(error)
            result = "error:\(f)"
            await audit.append(origin: ctx.origin, bridge: ctx.bridge, certSerial: certSerial, operation: operation, input: input, result: result)
            refreshAudit()
            throw f
        }
    }

    public func signXML(_ ctx: BridgeContext, serial: String?, xml: Data, options: XMLSignOptions) async throws -> Data {
        try await perform(ctx, serial: serial, operation: "Ký XML", input: xml) {
            try await XMLDSigSigner.signEnveloped(xml: xml, signer: $0, options: options)
        }
    }

    public func signCMS(_ ctx: BridgeContext, serial: String?, content: Data, hash: HashAlg) async throws -> Data {
        try await perform(ctx, serial: serial, operation: "Ký CMS", input: content) {
            try await CMSSigner.signDetached(content: content, signer: $0, hash: hash)
        }
    }

    public func signMessage(_ ctx: BridgeContext, serial: String?, message: Data, hash: HashAlg) async throws -> (signature: Data, certDER: Data) {
        var cert = Data()
        let sig = try await perform(ctx, serial: serial, operation: "Ký dữ liệu", input: message) {
            cert = $0.certificateDER
            return try await $0.sign(message: message, hash: hash)
        }
        return (sig, cert)
    }

    public func signDigest(_ ctx: BridgeContext, serial: String?, digest: Data, hash: HashAlg) async throws -> Data {
        try await perform(ctx, serial: serial, operation: "Ký hash", input: digest) { try await $0.signDigest(digest, hash: hash) }
    }

    /// Sign a fixed test string so the login/sign path can be exercised from the menu.
    func testSign(serial: String) async {
        let data = Data("TokenSigner ký thử \(Date())".utf8)
        do {
            let sig = try await signMessage(BridgeContext(bridge: "menu", origin: "TokenSigner (ký thử)"),
                                            serial: serial, message: data, hash: .sha256).signature
            lastSignResult = "Ký OK — chữ ký \(sig.count) byte"
        } catch {
            lastSignResult = "Lỗi ký: \(signErrorText(error))"
        }
    }

    /// Human-readable Vietnamese for a sign failure. pinIncorrect surfaces the
    /// remaining try count — the number that matters before a lockout.
    private func signErrorText(_ error: Error) -> String {
        if let f = error as? SigningFailure {
            switch f {
            case .userDenied: return "người dùng từ chối ký"
            case .userCancelled: return "đã huỷ nhập PIN"
            case .certExpired: return "chứng thư số đã hết hạn"
            case .unknownSerial(let s): return "không tìm thấy chứng thư \(s)"
            case .bad(let m), .card(let m): return m
            }
        }
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
    public func certificates() async -> [CertInfo] { cachedCerts }
}

/// Bridge backend. Serves certificates; SignHash signing is stubbed because the
/// tokens cannot sign the precomputed hash CTSigningHub sends (raw-document
/// signing via AppModel.sign lands with the P2 bridges).
struct Backend: SigningBackend {
    let model: AppModel
    func certificates() async -> [CertInfo] { await model.certificates() }
    /// CTSigningHub SignHash: `digestB64` is a SHA-256 (32B) or SHA-1 (20B) digest; the card signs its DigestInfo.
    func sign(serial: String, digestB64: String, origin: String) async throws -> String {
        guard let d = Data(base64Encoded: digestB64), d.count == 32 || d.count == 20 else { throw SigningFailure.bad("DLieuHash phải là SHA-256 (32 byte) hoặc SHA-1 (20 byte)") }
        let sig = try await model.signDigest(BridgeContext(bridge: "ctsigninghub", origin: origin),
                                             serial: serial, digest: d, hash: d.count == 32 ? .sha256 : .sha1)
        return sig.base64EncodedString()
    }
}
