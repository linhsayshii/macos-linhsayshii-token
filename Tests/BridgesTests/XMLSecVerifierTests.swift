import Testing
import Foundation
import Security
import X509
import SwiftASN1
import Core
@testable import Bridges

private func verificationTempDirectory() throws -> URL {
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent("verify-test-\(UUID().uuidString)")
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: false)
    return dir
}

@Test func missingXMLSecSkipsWithoutCreatingTemporaryFiles() async throws {
    let dir = try verificationTempDirectory()
    defer { try? FileManager.default.removeItem(at: dir) }
    try await XMLSecVerifier(executableURL: nil, temporaryDirectory: dir).verify(Data("<unsigned/>".utf8))
    #expect(try FileManager.default.contentsOfDirectory(atPath: dir.path).isEmpty)
}

@Test(arguments: ["/usr/bin/true", "/usr/bin/false", "/nonexistent/xmlsec1"])
func verifierCleansTemporaryFilesOnSuccessAndFailure(binary: String) async throws {
    let dir = try verificationTempDirectory()
    defer { try? FileManager.default.removeItem(at: dir) }
    let verifier = XMLSecVerifier(executableURL: URL(fileURLWithPath: binary), temporaryDirectory: dir)
    if binary == "/usr/bin/true" {
        try await verifier.verify(Data("<signed/>".utf8))
    } else {
        await #expect(throws: SigningFailure.self) { try await verifier.verify(Data("<signed/>".utf8)) }
    }
    #expect(try FileManager.default.contentsOfDirectory(atPath: dir.path).isEmpty)
}

// An ephemeral software key exercises the real XML signer and xmlsec1 without
// a token, a PIN, or any private key material written to disk.
private func signedDeclaration(attribute: String, namespaced: Bool) async throws -> Data {
    let key = try #require(SecKeyCreateRandomKey([kSecAttrKeyType: kSecAttrKeyTypeRSA,
                                                kSecAttrKeySizeInBits: 2048] as CFDictionary, nil))
    let privateKey = try Certificate.PrivateKey(key)
    let name = try DistinguishedName { CommonName("XML verification test") }
    let certificate = try Certificate(version: .v3, serialNumber: Certificate.SerialNumber(), publicKey: privateKey.publicKey,
                                      notValidBefore: Date().addingTimeInterval(-3600), notValidAfter: Date().addingTimeInterval(3600),
                                      issuer: name, subject: name, signatureAlgorithm: .sha256WithRSAEncryption,
                                      extensions: Certificate.Extensions {}, issuerPrivateKey: privateKey)
    var serializer = DER.Serializer()
    try serializer.serialize(certificate)
    let namespace = namespaced ? " xmlns=\"http://kekhaithue.gdt.gov.vn/TKhaiThue\"" : ""
    let xml = Data("<HSoThueDTu\(namespace)><HSoKhaiThue \(attribute)=\"ID_1\"><maTKhai>842</maTKhai></HSoKhaiThue></HSoThueDTu>".utf8)
    var options = XMLSignOptions()
    options.kind = .custom(parentXPath: "HSoThueDTu/CKyDTu")
    options.signElements = ["HSoKhaiThue"]
    return try await XMLDSigSigner.signEnveloped(xml: xml,
        signer: SoftwareSigner(key: key, certificateDER: Data(serializer.serializedBytes)), options: options)
}

@Test(.enabled(if: XMLSecVerifier().executableURL != nil), arguments: ["id", "Id", "ID"], [true, false])
func realXMLSecAcceptsSignatureAndRejectsTampering(attribute: String, namespaced: Bool) async throws {
    let dir = try verificationTempDirectory()
    defer { try? FileManager.default.removeItem(at: dir) }
    let verifier = XMLSecVerifier(executableURL: XMLSecVerifier().executableURL, temporaryDirectory: dir)
    let signed = try await signedDeclaration(attribute: attribute, namespaced: namespaced)
    try await verifier.verify(signed)
    let tampered = Data(String(decoding: signed, as: UTF8.self).replacingOccurrences(of: "<maTKhai>842<", with: "<maTKhai>843<").utf8)
    await #expect(throws: SigningFailure.self) { try await verifier.verify(tampered) }
    #expect(try FileManager.default.contentsOfDirectory(atPath: dir.path).isEmpty)
}
