import Foundation

public actor TokenBroker {
    private let helperURL: URL
    private let shimURL: URL
    private let moduleDir: URL

    public init(helperURL: URL, shimURL: URL, moduleDir: URL) {
        self.helperURL = helperURL; self.shimURL = shimURL; self.moduleDir = moduleDir
    }

    public func request(_ r: HelperRequest, module: ModuleInfo) async throws -> HelperResponse {
        let modulePath = moduleDir.appendingPathComponent(module.moduleName).path
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
        stdinPipe.fileHandleForWriting.write(try JSONEncoder().encode(r))
        stdinPipe.fileHandleForWriting.write(Data([0x0a]))
        try? stdinPipe.fileHandleForWriting.close()

        let out = stdoutPipe.fileHandleForReading.readDataToEndOfFile()
        proc.waitUntilExit()
        let firstLine = out.split(separator: 0x0a).first ?? Data()
        return try JSONDecoder().decode(HelperResponse.self, from: Data(firstLine))
    }
}
