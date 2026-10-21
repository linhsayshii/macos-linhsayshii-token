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
        let moduleDir = URL(fileURLWithPath: "/usr/local/lib")
        self.broker = TokenBroker(helperURL: helper, shimURL: shim, moduleDir: moduleDir)
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

    private func refreshTokens() async {
        var rows: [TokenRow] = []
        for r in scanner.readers() {
            guard let module = ModuleRegistry.lookup(atr: r.atr) else {
                rows.append(TokenRow(ca: "Chưa hỗ trợ", supported: false, reader: r.reader,
                                     serial: "", label: "", certSubject: nil, notAfter: nil))
                continue
            }
            var row = TokenRow(ca: module.ca, supported: true, reader: r.reader,
                               serial: "", label: "", certSubject: nil, notAfter: nil)
            if case let .tokens(list) = (try? await broker.request(.listTokens, module: module)) ?? .error(""),
               let t = list.first(where: { $0.reader == r.reader }) ?? list.first {
                row.serial = t.serial; row.label = t.label
                if case let .certs(certs) = (try? await broker.request(.listCerts(serial: t.serial), module: module)) ?? .error(""),
                   let c = certs.first {
                    row.certSubject = c.subject; row.notAfter = c.notAfter
                }
            }
            rows.append(row)
        }
        self.tokens = rows
    }

    // Certificates for the bridge: every supported token's certs.
    func certificates() async -> [CertInfo] {
        var out: [CertInfo] = []
        for r in scanner.readers() {
            guard let module = ModuleRegistry.lookup(atr: r.atr) else { continue }
            if case let .tokens(list) = (try? await broker.request(.listTokens, module: module)) ?? .error(""),
               let t = list.first {
                if case let .certs(certs) = (try? await broker.request(.listCerts(serial: t.serial), module: module)) ?? .error("") {
                    out.append(contentsOf: certs)
                }
            }
        }
        return out
    }
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
