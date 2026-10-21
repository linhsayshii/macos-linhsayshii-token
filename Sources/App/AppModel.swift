import Foundation
import Core
import Bridges

/// Ties ReaderScanner + ModuleRegistry + TokenBroker + CTSignBridge together and
/// drives the menu bar. P1: lists tokens and certs and serves the CTSigningHub
/// bridge. Login/PIN and the actual sign path land in Task 11.
@MainActor
public final class AppModel: ObservableObject {
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

    private let scanner = ReaderScanner()
    private let broker: TokenBroker
    private var server: HTTPServer?
    private var scanTask: Task<Void, Never>?

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
                await self?.refreshTokens()
                try? await Task.sleep(for: .seconds(2))
            }
        }
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
        var rows: [TokenRow] = []
        var certCache: [CertInfo] = []
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
    }

    // Certificates for the bridge: the last scan's cache, no fresh spawning.
    func certificates() async -> [CertInfo] { cachedCerts }
}

/// Bridge backend. P1 serves certificates; signing requires login (Task 11), so
/// it throws for now.
struct Backend: SigningBackend {
    let model: AppModel
    func certificates() async -> [CertInfo] { await model.certificates() }
    func sign(serial: String, digestB64: String) async throws -> String {
        throw CTSignError.unknownSerial(serial)   // replaced by the real path in Task 11
    }
}
