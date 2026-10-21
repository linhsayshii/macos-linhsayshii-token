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

    public func request(_ r: HelperRequest, module: ModuleInfo) async throws -> HelperResponse {
        try run([r], module: module).first ?? .error("no response")
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
            throw SignError.loginFailed(.pinIncorrect(retriesLeft: nil))
        }
        switch resp.count > 1 ? resp[1] : .error("no sign response") {
        case .signature(let b64): return b64
        case .error(let m): throw SignError.card(m)
        default: throw SignError.noSignature
        }
    }

    /// Spawn one helper, send each request on its own line, return the responses
    /// in order (one per line read back).
    private func run(_ reqs: [HelperRequest], module: ModuleInfo) throws -> [HelperResponse] {
        let modulePath = try resolve(module.moduleName)
        let proc = Process()
        if module.arch == .x86_64 {
            proc.executableURL = URL(fileURLWithPath: "/usr/bin/arch")
            proc.arguments = ["-x86_64", helperURL.path, "--module", modulePath]
        } else {
            proc.executableURL = helperURL
            proc.arguments = ["--module", modulePath]
        }
        var env = ProcessInfo.processInfo.environment
        env["DYLD_INSERT_LIBRARIES"] = shimURL.path
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
        let dec = JSONDecoder()
        return out.split(separator: 0x0a).map {
            (try? dec.decode(HelperResponse.self, from: Data($0))) ?? .error("decode failed")
        }
    }
}
