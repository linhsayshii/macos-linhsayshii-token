import Foundation

public actor TokenBroker {
    private let helperURL: URL
    private let shimURL: URL
    private let moduleDirs: [URL]

    public init(helperURL: URL, shimURL: URL, moduleDirs: [URL]) {
        self.helperURL = helperURL; self.shimURL = shimURL; self.moduleDirs = moduleDirs
    }

    public enum BrokerError: Error { case moduleNotFound(String) }
    public enum SignError: Error, Equatable { case loginFailed(LoginResult), card(String), noSignature }

    /// First existing path for the module across the search dirs.
    private func resolve(_ name: String) throws -> String {
        for dir in moduleDirs {
            let p = dir.appendingPathComponent(name).path
            if FileManager.default.fileExists(atPath: p) { return p }
        }
        throw BrokerError.moduleNotFound(name)
    }

    public func request(_ r: HelperRequest, module: ModuleInfo, reader: String? = nil) async throws -> HelperResponse {
        try run([r], module: module, reader: reader).first ?? .error("no response")
    }

    /// Login, sign and log out in one helper process. The PKCS#11 login state the
    /// helper keeps per serial lives only inside a single process, so the three
    /// steps must share one spawn. The PIN travels only in the piped login JSON.
    public func sign(module: ModuleInfo, serial: String, certId: String,
                     mech: SignMech, dataB64: String, pin: String) async throws -> String {
        let resp = try run([
            .login(serial: serial, pin: pin),
            .sign(serial: serial, certId: certId, mech: mech, dataB64: dataB64),
            .logout(serial: serial),
        ], module: module)
        guard case let .loginResult(lr) = resp.first, lr == .ok else {
            if case let .loginResult(lr) = resp.first { throw SignError.loginFailed(lr) }
            if case let .error(message) = resp.first { throw SignError.card(message) }
            if case let .failure(failure) = resp.first { throw SignError.card(failure.message) }
            throw SignError.card("helper không trả kết quả đăng nhập")
        }
        switch resp.count > 1 ? resp[1] : .error("no sign response") {
        case .signature(let b64): return b64
        case .error(let m): throw SignError.card(m)
        case .failure(let failure): throw SignError.card(failure.message)
        default: throw SignError.noSignature
        }
    }

    /// Spawn one helper, send each request on its own line, return the responses
    /// in order (one per line read back).
    private func run(_ reqs: [HelperRequest], module: ModuleInfo, reader: String? = nil) throws -> [HelperResponse] {
        let proc = Process()
        let nativeESPK = [.fastca, .efy, .espkDiscovery].contains(module.backend)
        if nativeESPK {
            proc.executableURL = helperURL
            let backend = module.backend == .espkDiscovery ? "espk-discovery" : (module.backend == .efy ? "efy" : "fastca")
            proc.arguments = ["--backend", backend]
            if let reader { proc.arguments! += ["--reader", reader] }
        } else if module.backend == .oneca {
            proc.executableURL = helperURL
            proc.arguments = ["--backend", "oneca", "--module", try resolve(module.moduleName)]
        } else if module.arch == .x86_64 {
            let modulePath = try resolve(module.moduleName)
            proc.executableURL = URL(fileURLWithPath: "/usr/bin/arch")
            proc.arguments = ["-x86_64", helperURL.path, "--module", modulePath]
        } else {
            let modulePath = try resolve(module.moduleName)
            proc.executableURL = helperURL
            proc.arguments = ["--module", modulePath]
        }
        var env = ProcessInfo.processInfo.environment
        if nativeESPK {
            // Native OpenSC emits standard APDUs and needs no vendor shim.
            // Never permit inherited APDU/key debug settings in a PIN process.
            for key in ["DYLD_INSERT_LIBRARIES", "OPENSC_DEBUG_FILE", "OPENSC_CONF", "TSSHIM_LOG"] {
                env.removeValue(forKey: key)
            }
            env["OPENSC_DEBUG"] = "0"
        } else if module.backend == .oneca {
            env.removeValue(forKey: "DYLD_INSERT_LIBRARIES")
            env.removeValue(forKey: "TSSHIM_LOG")
        } else { env["DYLD_INSERT_LIBRARIES"] = shimURL.path }
        proc.environment = env

        let stdinPipe = Pipe(), stdoutPipe = Pipe()
        proc.standardInput = stdinPipe
        proc.standardOutput = stdoutPipe
        try proc.run()
        let enc = JSONEncoder()
        for r in reqs {
            stdinPipe.fileHandleForWriting.write(try enc.encode(r))
            stdinPipe.fileHandleForWriting.write(Data([0x0a]))
        }
        try? stdinPipe.fileHandleForWriting.close()

        let out = stdoutPipe.fileHandleForReading.readDataToEndOfFile()
        proc.waitUntilExit()
        guard proc.terminationStatus == 0 else { return [.error("TokenHelper đã dừng (\(proc.terminationStatus))")] }
        let dec = JSONDecoder()
        return out.split(separator: 0x0a).map {
            (try? dec.decode(HelperResponse.self, from: Data($0))) ?? .error("decode failed")
        }
    }
}
