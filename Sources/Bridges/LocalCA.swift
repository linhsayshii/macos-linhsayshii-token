import Foundation
import Crypto
import X509
import SwiftASN1
import NIOSSL

/// Our own local CA plus a `localhost` / `127.0.0.1` leaf for the VNPT WSS bridge.
/// Never touches the vendor's key. The user trusts the CA once in the login keychain.
public struct LocalCA: Sendable {
    public let directory: URL
    public init(directory: URL) { self.directory = directory }

    public struct Material: Sendable { public let caCertPEM, leafCertPEM, leafKeyPEM: String }
    var caPath: URL { directory.appendingPathComponent("ca.pem") }
    var leafPath: URL { directory.appendingPathComponent("leaf.pem") }
    public var caCertPath: String { caPath.path }
    public var leafCertPath: String { leafPath.path }

    private func read(_ name: String) -> String? { try? String(contentsOf: directory.appendingPathComponent(name), encoding: .utf8) }
    private func write(_ name: String, _ s: String, secret: Bool) throws {
        let u = directory.appendingPathComponent(name)
        try s.write(to: u, atomically: true, encoding: .utf8)
        try FileManager.default.setAttributes([.posixPermissions: secret ? 0o600 : 0o644], ofItemAtPath: u.path)
    }

    /// Generates on first use and reuses afterwards. The leaf is reissued when it
    /// has under 30 days left.
    public func ensure() throws -> Material {
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let caKey: P256.Signing.PrivateKey, caCert: Certificate
        if let kp = read("ca.key"), let cp = read("ca.pem"),
           let k = try? P256.Signing.PrivateKey(pemRepresentation: kp), let c = try? Certificate(pemEncoded: cp) {
            caKey = k; caCert = c
        } else {
            caKey = P256.Signing.PrivateKey()
            let name = try DistinguishedName { CommonName("TokenSigner Local CA"); OrganizationName("TokenSigner") }
            let now = Date()
            caCert = try Certificate(
                version: .v3, serialNumber: Certificate.SerialNumber(), publicKey: .init(caKey.publicKey),
                notValidBefore: now.addingTimeInterval(-3600), notValidAfter: now.addingTimeInterval(10 * 365 * 86400),
                issuer: name, subject: name, signatureAlgorithm: .ecdsaWithSHA256,
                extensions: try Certificate.Extensions {
                    Critical(BasicConstraints.isCertificateAuthority(maxPathLength: 0))
                    Critical(KeyUsage(keyCertSign: true, cRLSign: true))
                },
                issuerPrivateKey: .init(caKey))
            try write("ca.key", caKey.pemRepresentation, secret: true)
            try write("ca.pem", try caCert.serializeAsPEM().pemString, secret: false)
            try? FileManager.default.removeItem(at: leafPath)
        }
        if let lp = read("leaf.pem"), let lk = read("leaf.key"), let c = try? Certificate(pemEncoded: lp),
           c.notValidAfter > Date().addingTimeInterval(30 * 86400) {
            return Material(caCertPEM: try caCert.serializeAsPEM().pemString, leafCertPEM: lp, leafKeyPEM: lk)
        }
        let leafKey = P256.Signing.PrivateKey()
        let subject = try DistinguishedName { CommonName("localhost") }
        let now = Date()
        let leaf = try Certificate(
            version: .v3, serialNumber: Certificate.SerialNumber(), publicKey: .init(leafKey.publicKey),
            notValidBefore: now.addingTimeInterval(-3600), notValidAfter: now.addingTimeInterval(365 * 86400),
            issuer: caCert.subject, subject: subject, signatureAlgorithm: .ecdsaWithSHA256,
            extensions: try Certificate.Extensions {
                Critical(BasicConstraints.notCertificateAuthority)
                Critical(KeyUsage(digitalSignature: true))
                try ExtendedKeyUsage([.serverAuth])
                SubjectAlternativeNames([.dnsName("localhost"), .ipAddress(ASN1OctetString(contentBytes: [127, 0, 0, 1]))])
            },
            issuerPrivateKey: .init(caKey))
        let leafPEM = try leaf.serializeAsPEM().pemString
        try write("leaf.key", leafKey.pemRepresentation, secret: true)
        try write("leaf.pem", leafPEM, secret: false)
        return Material(caCertPEM: try caCert.serializeAsPEM().pemString, leafCertPEM: leafPEM, leafKeyPEM: leafKey.pemRepresentation)
    }

    public func sslContext() throws -> NIOSSLContext {
        let m = try ensure()
        let cert = try NIOSSLCertificate(bytes: Array(m.leafCertPEM.utf8), format: .pem)
        let key = try NIOSSLPrivateKey(bytes: Array(m.leafKeyPEM.utf8), format: .pem)
        return try NIOSSLContext(configuration: .makeServerConfiguration(certificateChain: [.certificate(cert)], privateKey: .privateKey(key)))
    }

    /// True when the system already trusts the leaf for SSL on `localhost`.
    public func isTrusted() -> Bool {
        guard FileManager.default.fileExists(atPath: leafPath.path) else { return false }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: "/usr/bin/security")
        p.arguments = ["verify-cert", "-c", leafPath.path, "-p", "ssl", "-s", "localhost"]
        p.standardOutput = Pipe(); p.standardError = Pipe()
        guard (try? p.run()) != nil else { return false }
        p.waitUntilExit()
        return p.terminationStatus == 0
    }

    /// Run by the user's click in Settings; macOS asks for their password.
    public func trustCommand() -> [String] {
        let kc = FileManager.default.homeDirectoryForCurrentUser.appendingPathComponent("Library/Keychains/login.keychain-db").path
        return ["/usr/bin/security", "add-trusted-cert", "-r", "trustRoot", "-k", kc, caPath.path]
    }
}
