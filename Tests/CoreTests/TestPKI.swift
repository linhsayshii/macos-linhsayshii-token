import Foundation
import Security
import X509
import SwiftASN1
@testable import Core

enum Tool {
    static func path(_ name: String) -> String? {
        ["/opt/homebrew/bin/\(name)", "/usr/local/bin/\(name)", "/usr/bin/\(name)"]
            .first { FileManager.default.isExecutableFile(atPath: $0) }
    }
    static func exists(_ name: String) -> Bool { path(name) != nil }
    static func run(_ name: String, _ args: [String]) throws -> (status: Int32, stderr: String) {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: path(name)!)
        p.arguments = args
        let err = Pipe()
        p.standardError = err; p.standardOutput = Pipe()
        try p.run()
        let data = err.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return (p.terminationStatus, String(decoding: data, as: UTF8.self))
    }
}

struct TempDir {
    let url: URL
    init() throws {
        url = FileManager.default.temporaryDirectory.appendingPathComponent("ts-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: url, withIntermediateDirectories: true)
    }
    subscript(_ n: String) -> URL { url.appendingPathComponent(n) }
}

struct TestPKI {
    let key: SecKey
    let certDER: Data
    let certPEMPath: String
    var signer: SoftwareSigner { SoftwareSigner(key: key, certificateDER: certDER) }

    static func make() throws -> TestPKI {
        let key = try makeTestKey()
        let priv = try Certificate.PrivateKey(key)
        let name = try DistinguishedName { CommonName("TokenSigner Test") }
        let now = Date()
        let cert = try Certificate(
            version: .v3, serialNumber: Certificate.SerialNumber(),
            publicKey: priv.publicKey,
            notValidBefore: now.addingTimeInterval(-3600), notValidAfter: now.addingTimeInterval(86400),
            issuer: name, subject: name,
            signatureAlgorithm: .sha256WithRSAEncryption,
            extensions: try Certificate.Extensions {
                Critical(BasicConstraints.isCertificateAuthority(maxPathLength: nil))
                Critical(KeyUsage(digitalSignature: true, keyCertSign: true))
            },
            issuerPrivateKey: priv)
        var ser = DER.Serializer()
        try ser.serialize(cert)
        let der = Data(ser.serializedBytes)
        let d = try TempDir()
        let pem = d["cert.pem"]
        try cert.serializeAsPEM().pemString.write(to: pem, atomically: true, encoding: .utf8)
        return TestPKI(key: key, certDER: der, certPEMPath: pem.path)
    }
}
