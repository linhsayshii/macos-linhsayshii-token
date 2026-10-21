import Testing
import Foundation
@testable import Bridges

private func tmp() -> URL { FileManager.default.temporaryDirectory.appendingPathComponent("ca-\(UUID())") }
private func openssl() -> String? { ["/opt/homebrew/bin/openssl", "/usr/bin/openssl"].first { FileManager.default.isExecutableFile(atPath: $0) } }

@Test func ensureIsStableAndKeysArePrivate() throws {
    let ca = LocalCA(directory: tmp())
    let a = try ca.ensure(), b = try ca.ensure()
    #expect(a.caCertPEM == b.caCertPEM && a.leafCertPEM == b.leafCertPEM && a.leafKeyPEM == b.leafKeyPEM)
    for n in ["ca.key", "leaf.key"] {
        let perm = try FileManager.default.attributesOfItem(atPath: ca.directory.appendingPathComponent(n).path)[.posixPermissions] as? Int
        #expect(perm == 0o600)
    }
    _ = try ca.sslContext()
}

@Test(.enabled(if: openssl() != nil))
func leafHasSANAndVerifiesAgainstCA() throws {
    let ca = LocalCA(directory: tmp())
    _ = try ca.ensure()
    func run(_ args: [String]) throws -> (Int32, String) {
        let p = Process(); p.executableURL = URL(fileURLWithPath: openssl()!); p.arguments = args
        let o = Pipe(); p.standardOutput = o; p.standardError = o
        try p.run(); let d = o.fileHandleForReading.readDataToEndOfFile(); p.waitUntilExit()
        return (p.terminationStatus, String(decoding: d, as: UTF8.self))
    }
    let v = try run(["verify", "-CAfile", ca.caCertPath, ca.leafCertPath])
    #expect(v.0 == 0, "\(v.1)")
    let t = try run(["x509", "-in", ca.leafCertPath, "-noout", "-ext", "subjectAltName"])
    #expect(t.1.contains("DNS:localhost") && t.1.contains("IP Address:127.0.0.1"), "\(t.1)")
}

@Test func trustCommandTargetsLoginKeychain() throws {
    let ca = LocalCA(directory: tmp())
    let c = ca.trustCommand()
    #expect(c.prefix(4) == ["/usr/bin/security", "add-trusted-cert", "-r", "trustRoot"])
    #expect(c.contains { $0.hasSuffix("login.keychain-db") })
}
