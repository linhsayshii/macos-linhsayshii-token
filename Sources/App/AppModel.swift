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
    /// Prompt state for the dedicated signing window; a sign call
    /// awaits the user's answer via `pinCont`.
    struct PINPrompt: Identifiable { let id = UUID(); let ca, serial: String; let warning: String?; let locked: Bool }
    struct ApprovalPrompt: Identifiable { let id = UUID(); let origin, subject, ca, notAfter, operation: String; let docCount: Int }
    struct CertificatePrompt {
        let origin, operation: String
        let requestedSerial: String?
        let tokenSerial: String?
        let requireValid: Bool
        var choices: [SigningCertificateChoice]
        var message: String?
    }
    enum ApprovalChoice: Sendable { case session, once, deny }

    private typealias SignTarget = SigningTarget

    public struct TokenRow: Identifiable, Sendable {
        public var id: String { serial.isEmpty ? reader : serial }
        public let ca: String
        public let supported: Bool
        public var experimental: Bool = false
        public let reader: String
        public var serial: String
        public var label: String
        public var certSubject: String?
        public var notAfter: String?
        public var readError: String? = nil
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
    @Published private(set) var certificatePrompt: CertificatePrompt?
    @Published var selectedCertificateID: String?

    private let scanner = ReaderScanner()
    private let broker: TokenBroker
    private let approval = ApprovalCenter()
    private var server: HTTPServer?
    private var scanTask: Task<Void, Never>?
    private var minvoiceServer: SignalRServer?
    private var activeRequestID: UUID?
    @Published private(set) var minvoiceStatus = "Minvoice đang khởi động…"

    // Every certificate from the last scan, bound to its physical token and module.
    private var certificateTargets: [SignTarget] = []
    private var signing = false   // serialize requests; scan only while choosing a certificate
    @Published private(set) var refreshingCertificates = false
    private var pinCont: CheckedContinuation<String?, Never>?
    private var approvalCont: CheckedContinuation<ApprovalChoice, Never>?
    private let promptWindow: any SigningPromptPresenting
    private var certificateCont: CheckedContinuation<SigningTarget?, Never>?
    private var rememberedCertificates: [String: String] = [:]

    public convenience init() {
        // Helper + shim live next to the app binary (bundle Contents/Helpers in a
        // packaged build; the build dir during development).
        let binDir = URL(fileURLWithPath: CommandLine.arguments[0]).deletingLastPathComponent()
        let helper = binDir.appendingPathComponent("TokenHelper")
        let shim = binDir.appendingPathComponent("libTSShim.dylib")
        let appModules = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("TokenSigner/modules", isDirectory: true)
        try? FileManager.default.createDirectory(at: appModules, withIntermediateDirectories: true)
        let moduleDirs = [URL(fileURLWithPath: "/usr/local/lib"), appModules]
        self.init(broker: TokenBroker(helperURL: helper, shimURL: shim, moduleDirs: moduleDirs),
                  promptWindow: SigningPromptWindow())
    }

    init(broker: TokenBroker, promptWindow: any SigningPromptPresenting, targets: [SigningTarget] = []) {
        self.broker = broker
        self.promptWindow = promptWindow
        updateCertificateTargets(targets)
    }

    private var started = false

    public func start() {
        guard !started else { return }   // MenuBarExtra onAppear can fire repeatedly
        started = true
        startServer()
        startMinvoiceServer()
        scanTask = Task { [weak self] in
            while !Task.isCancelled {
                await self?.scanTick()
                try? await Task.sleep(for: .milliseconds(175))
            }
        }
    }

    private var lastReaderSig = ""

    // Apple's PC/SC reports SCARD_STATE_UNKNOWN for \\?PnP?\Notification, so
    // use short, cancellable polling rather than a blocking PnP wait here.
    // Listing readers is a cheap PC/SC call; the full refresh (helper spawns for
    // listTokens/listCerts) is not. Poll readers fast so plug/unplug shows up
    // quickly, but only run the full refresh when the reader set actually changes.
    private func scanTick() async {
        if signing && certificatePrompt == nil { return }   // a sign holds the vendor lock
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

    private func startMinvoiceServer() {
        let file = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask)[0]
            .appendingPathComponent("TokenSigner/origins.json")
        let bridge = MinvoiceBridge(backend: MinvoiceBackend(model: self))
        let server = SignalRServer(store: OriginStore(fileURL: file), hub: SignalRHub(handler: bridge.handler))
        minvoiceServer = server
        Task {
            do { _ = try await server.start(); minvoiceStatus = "Minvoice 16080 sẵn sàng · cash đơn" }
            catch SignalRServer.StartError.portInUse { minvoiceStatus = "Minvoice: cổng 16080 đã bị chiếm" }
            catch { minvoiceStatus = "Minvoice: không mở được cổng 16080" }
        }
    }

    // Certs cached by the scan loop. The bridge reads this instead of spawning
    // its own helpers, so token access stays serialized in one place (vendor libs
    // hold an exclusive PC/SC lock; concurrent helpers on one token deadlock).
    private var cachedCerts: [CertInfo] = []

    private func refreshTokens() async {
        if signing && certificatePrompt == nil { return }   // a sign holds the vendor lock; scanning would deadlock
        refreshingCertificates = true
        defer { refreshingCertificates = false }
        var rows: [TokenRow] = []
        var allTargets: [SignTarget] = []
        // Per-CA modules need one enumeration. Generic candidates are scoped
        // separately to each PC/SC reader before accepting signing targets.
        var seenModules = Set<String>()
        for r in scanner.readers() {
            guard let module = ModuleRegistry.lookup(atr: r.atr) else {
                rows.append(TokenRow(ca: "Chưa hỗ trợ", supported: false, reader: r.reader,
                                     serial: "", label: "", certSubject: nil, notAfter: nil))
                continue
            }
            var row = TokenRow(ca: module.ca, supported: true, reader: r.reader,
                               serial: "", label: "", certSubject: nil, notAfter: nil)
            row.experimental = module.isExperimental
            if module.tokenScope == .reader || !seenModules.contains(module.moduleName) {
                let response: HelperResponse
                do { response = try await broker.request(.listTokens, module: module) }
                catch { response = .error("\(error)") }
                guard case let .tokens(list) = response else {
                    if case let .error(message) = response { row.readError = message }
                    rows.append(row)
                    continue
                }
                seenModules.insert(module.moduleName)
                let scopedTokens = module.tokensForReader(r.reader, from: list)
                for t in scopedTokens {
                    let certResponse = (try? await broker.request(.listCerts(serial: t.serial), module: module)) ?? .error("Không đọc được chứng thư")
                    if case let .certs(certs) = certResponse {
                        allTargets.append(contentsOf: certs.map {
                            SignTarget(tokenSerial: t.serial, module: module, cert: $0, flags: t.flags)
                        })
                        if t.reader == r.reader || scopedTokens.count == 1 {
                            row.serial = t.serial; row.label = t.label
                            if let c = certs.first { row.certSubject = c.subject; row.notAfter = c.notAfter }
                        }
                    } else if case let .error(message) = certResponse {
                        row.readError = message
                    }
                }
            }
            rows.append(row)
        }
        self.tokens = rows
        updateCertificateTargets(allTargets)
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
    fileprivate func signPreparedBlock(origin: String, serial: String, blockB64: String, operation: String,
                                       docCount: Int, byCertificateSerial: Bool = false) async throws -> String {
        try await withSigningRequest {
            let target = try await chooseCertificate(origin: origin, operation: operation,
                requestedSerial: byCertificateSerial ? serial : nil,
                tokenSerial: !byCertificateSerial && !serial.isEmpty ? serial : nil)
            try await requestApproval(target: target, origin: origin, operation: operation, docCount: docCount)
            return try await signApproved(target: target, blockB64: blockB64)
        }
    }

    private func withSigningRequest<T: Sendable>(_ body: @MainActor () async throws -> T) async throws -> T {
        guard !signing else { throw MinvoiceError.busy }
        try Task.checkCancellation()
        signing = true
        let id = UUID()
        activeRequestID = id
        defer { signing = false; activeRequestID = nil; signingStatus = nil }
        return try await withTaskCancellationHandler {
            try await body()
        } onCancel: {
            Task { @MainActor [weak self] in
                guard let self, self.activeRequestID == id else { return }
                if self.certificateCont != nil { self.submitCertificate(nil) }
                if self.approvalCont != nil { self.submitApproval(.deny) }
                if self.pinCont != nil { self.submitPIN(nil) }
            }
        }
    }

    /// Refresh the open chooser from the latest scan; a removed choice cannot be submitted.
    func updateCertificateTargets(_ targets: [SigningTarget]) {
        certificateTargets = targets
        cachedCerts = targets.map(\.cert)
        if var prompt = certificatePrompt {
            prompt.choices = SigningCertificateChoice.list(targets, requestedSerial: prompt.requestedSerial,
                tokenSerial: prompt.tokenSerial, requireValid: prompt.requireValid)
            if let id = selectedCertificateID, !prompt.choices.contains(where: { $0.id == id && $0.canSelect }) {
                selectedCertificateID = nil
                prompt.message = "CKS đã thay đổi hoặc bị rút. Hãy chọn lại."
            }
            certificatePrompt = prompt
        }
    }

    private func chooseCertificate(origin: String, operation: String, requestedSerial: String? = nil,
                                   tokenSerial: String? = nil, requireValid: Bool = false) async throws -> SigningTarget {
        try Task.checkCancellation()
        selectedCertificateID = nil
        let prompt = CertificatePrompt(origin: origin, operation: operation, requestedSerial: requestedSerial,
            tokenSerial: tokenSerial, requireValid: requireValid,
            choices: SigningCertificateChoice.list(certificateTargets, requestedSerial: requestedSerial,
                                                   tokenSerial: tokenSerial, requireValid: requireValid))
        guard let target = await withCheckedContinuation({ (continuation: CheckedContinuation<SigningTarget?, Never>) in
            certificateCont = continuation
            certificatePrompt = prompt
            promptWindow.present(title: "Chọn chữ ký số", content: CertificatePicker(model: self)) { [weak self] in
                self?.submitCertificate(nil)
            }
        }) else { throw CancellationError() }
        try Task.checkCancellation()
        return target
    }

    func submitCertificate(_ id: String?) {
        guard let prompt = certificatePrompt, let continuation = certificateCont else { return }
        var target: SigningTarget?
        if let id {
            guard !refreshingCertificates else {
                certificatePrompt?.message = "Đang đọc token. Vui lòng chờ danh sách cập nhật."
                return
            }
            // Recheck current inventory and DER validity at the moment of confirmation.
            guard let choice = SigningCertificateChoice.list(certificateTargets,
                requestedSerial: prompt.requestedSerial, tokenSerial: prompt.tokenSerial,
                requireValid: prompt.requireValid).first(where: { $0.id == id && $0.canSelect }) else {
                selectedCertificateID = nil
                certificatePrompt?.message = "CKS không còn sẵn sàng. Hãy chọn lại."
                return
            }
            target = choice.target
        }
        certificateCont = nil
        certificatePrompt = nil
        selectedCertificateID = nil
        promptWindow.dismiss()
        continuation.resume(returning: target)
    }

    func selectCertificate(origin: String, serial: String?) async throws -> CertInfo {
        try await withSigningRequest {
            if let remembered = rememberedCertificates[origin],
               let choice = SigningCertificateChoice.list(certificateTargets, requestedSerial: serial)
                .first(where: { $0.id == remembered && $0.canSelect }) { return choice.target.cert }
            let target = try await chooseCertificate(origin: origin, operation: "Đọc thông tin chứng thư cho Minvoice",
                                                      requestedSerial: serial)
            rememberedCertificates[origin] = SigningCertificateChoice.identity(target)
            return target.cert
        }
    }

    private func requestApproval(target: SignTarget, origin: String, operation: String, docCount: Int) async throws {
        try Task.checkCancellation()
        if await approval.decide(origin: origin, certSerial: target.cert.serialHex) != .allowedSession {
            let prompt = ApprovalPrompt(origin: origin, subject: target.cert.subject, ca: target.module.ca,
                                        notAfter: target.cert.notAfter, operation: operation, docCount: docCount)
            switch await withCheckedContinuation({
                approvalCont = $0
                approvalPrompt = prompt
                promptWindow.present(title: "Yêu cầu ký số", content: ApprovalSheet(prompt: prompt, model: self)) { [weak self] in
                    self?.submitApproval(.deny)
                }
            }) {
            case .deny: throw TokenBroker.SignError.card("Người dùng từ chối ký")
            case .session: await approval.allow(origin: origin, certSerial: target.cert.serialHex, minutes: 10)
            case .once: break
            }
        }

        try Task.checkCancellation()
    }

    private func signApproved(target: SignTarget, blockB64: String) async throws -> String {
        try Task.checkCancellation()
        let w = pinWarning(target.flags)
        let prompt = PINPrompt(ca: target.module.ca, serial: target.tokenSerial, warning: w.text, locked: w.locked)
        guard let pin = await withCheckedContinuation({ (c: CheckedContinuation<String?, Never>) in
            pinCont = c
            pinPrompt = prompt
            promptWindow.present(title: "Đăng nhập token", content: PINSheet(prompt: prompt, model: self)) { [weak self] in
                self?.submitPIN(nil)
            }
        }),
              !pin.isEmpty else { throw TokenBroker.SignError.card("Đã huỷ nhập PIN") }

        try Task.checkCancellation()
        let previousStatus = signingStatus
        signingStatus = "Đang ký…"
        defer { signingStatus = previousStatus }
        let signature = try await broker.sign(module: target.module, serial: target.tokenSerial, certId: target.cert.id,
                                             mech: .rsaPKCS, dataB64: blockB64, pin: pin)
        guard let bytes = Data(base64Encoded: signature), let payload = Data(base64Encoded: blockB64),
              let der = Data(base64Encoded: target.cert.derB64),
              RSAPKCS1v15.verify(signature: bytes, payload: payload, certificateDER: der) else {
            throw TokenBroker.SignError.card("Chữ ký không khớp chứng thư/dữ liệu đã duyệt")
        }
        return signature
    }

    fileprivate func withMinvoiceApproval(origin: String, serial: String, operation: @escaping MinvoiceOperation) async throws {
        try await withSigningRequest {
            let target = try await chooseCertificate(origin: origin, operation: "Ký hóa đơn Minvoice cash",
                                                      requestedSerial: serial, requireValid: true)
            try MinvoiceCashXML.validateCertificate(target.cert)
            try await requestApproval(target: target, origin: origin, operation: "Đăng nhập và ký hóa đơn Minvoice cash", docCount: 1)
            signingStatus = "Đang xử lý hóa đơn Minvoice…"
            try await operation(target.cert, { message in
                let block = Data(try DigestInfo.sha256Block(message)).base64EncodedString()
                let signature = try await self.signApproved(target: target, blockB64: block)
                guard let bytes = Data(base64Encoded: signature) else { throw MinvoiceError.invalidSignature }
                return bytes
            })
        }
    }

    /// Sign a fixed test string so the login/sign path can be exercised from the
    /// menu to exercise the login/sign path without a web request.
    func testSign(serial: String) async {
        let data = Data("TokenSigner ký thử \(Date())".utf8)
        do {
            let sig = try await sign(origin: "TokenSigner (ký thử)", serial: serial,
                                     dataB64: data.base64EncodedString(), operation: "Ký thử", docCount: 1)
            lastSignResult = "Ký và xác minh OK — chữ ký \(Data(base64Encoded: sig)?.count ?? 0) byte"
        } catch {
            lastSignResult = "Lỗi ký: \(signErrorText(error))"
        }
    }

    /// Human-readable Vietnamese for a sign failure. pinIncorrect surfaces the
    /// remaining try count — the number that matters before a lockout.
    private func signErrorText(_ error: Error) -> String {
        if error is CancellationError { return "Đã huỷ yêu cầu ký" }
        if case MinvoiceError.busy = error { return "Đang có yêu cầu khác, vui lòng thử lại sau" }
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

    func submitPIN(_ pin: String?) {
        pinDraft = ""; pinPrompt = nil
        promptWindow.dismiss()
        let continuation = pinCont; pinCont = nil
        continuation?.resume(returning: pin)
    }

    func submitApproval(_ choice: ApprovalChoice) {
        approvalPrompt = nil
        promptWindow.dismiss()
        let continuation = approvalCont; approvalCont = nil
        continuation?.resume(returning: choice)
    }

    private func pinWarning(_ flags: [String]) -> (text: String?, locked: Bool) {
        if flags.contains("USER_PIN_LOCKED") { return ("PIN đã bị khoá", true) }
        if flags.contains("USER_PIN_FINAL_TRY") { return ("Còn 1 lần thử — sai là khoá token", false) }
        if flags.contains("USER_PIN_COUNT_LOW") { return ("Token sắp bị khoá — nhập PIN cẩn thận", false) }
        if flags.contains("PIN_RETRIES_UNKNOWN") { return ("Chưa biết số lần thử PIN còn lại; chỉ xác thực một lần, không tự thử lại", false) }
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
                                                 operation: "Ký", docCount: 1, byCertificateSerial: true)
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

struct MinvoiceBackend: MinvoiceSigningBackend {
    let model: AppModel
    func certificates() async -> [CertInfo] { await model.certificates() }
    func selectCertificate(origin: String, serial: String?) async throws -> CertInfo {
        try await model.selectCertificate(origin: origin, serial: serial)
    }
    func withApproval(origin: String, serial: String, operation: @escaping MinvoiceOperation) async throws {
        try await model.withMinvoiceApproval(origin: origin, serial: serial, operation: operation)
    }
}
