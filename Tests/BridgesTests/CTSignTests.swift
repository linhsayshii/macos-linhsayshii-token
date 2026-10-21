import Testing
import Foundation
@testable import Bridges
import Core

struct FakeBackend: SigningBackend {
    func certificates() async -> [CertInfo] {
        [CertInfo(id: "01", derB64: "AAE=", subject: "CN=Test", issuer: "CN=VNPT-CA SHA2",
                  serialHex: "54010101", notBefore: "2024-01-01 00:00:00", notAfter: "2027-01-01 00:00:00")]
    }
    func sign(serial: String, digestB64: String) async throws -> String { "U0lH" }
}

@Test func versionReturnsString() async {
    let b = CTSignBridge(backend: FakeBackend())
    let (status, json) = await b.handle(method: "GET", path: "/api/SignHash/Version", body: Data())
    #expect(status == 200)
    #expect(String(decoding: json, as: UTF8.self) == "\"1.2.0.0\"")
}

@Test func getInfoCertReturnsOne() async {
    let b = CTSignBridge(backend: FakeBackend())
    let (_, json) = await b.handle(method: "GET", path: "/api/Info/GetInfoCert", body: Data())
    #expect(String(decoding: json, as: UTF8.self) == "\"1\"")
}

@Test func getCertWrapsCertificates() async throws {
    let b = CTSignBridge(backend: FakeBackend())
    let (_, json) = await b.handle(method: "GET", path: "/api/HubClient/GetCert", body: Data())
    let v = try JSONSerialization.jsonObject(with: json) as! [String: Any]
    #expect(v["status"] as? Int == 200)
    #expect(v["message"] as? String == "SUCCESS")
    let data = v["data"] as! [[String: Any]]
    #expect(data.first?["serinumber"] as? String == "54010101")
    #expect(data.first?["subjectDN"] as? String == "CN=Test")
}

@Test func signHashFillsCKy() async throws {
    let b = CTSignBridge(backend: FakeBackend())
    let digest = Data(repeating: 0xAB, count: 32).base64EncodedString()
    let body = try JSONSerialization.data(withJSONObject: [
        "serinumber": "54010101",
        "hash": [["Ma": "one", "DLieuHash": digest]],
    ])
    let (_, json) = await b.handle(method: "POST", path: "/api/HubClient/SignHash", body: body)
    let v = try JSONSerialization.jsonObject(with: json) as! [String: Any]
    #expect(v["status"] as? Int == 200)
    let out = v["data"] as! [[String: Any]]
    #expect(out.first?["CKy"] as? String == "U0lH")
}

@Test func signHashUnknownSerialIs404() async throws {
    struct NoCert: SigningBackend {
        func certificates() async -> [CertInfo] { [] }
        func sign(serial: String, digestB64: String) async throws -> String { throw CTSignError.unknownSerial("FFFF") }
    }
    let b = CTSignBridge(backend: NoCert())
    let body = try JSONSerialization.data(withJSONObject: [
        "serinumber": "FFFF", "hash": [["Ma": "x", "DLieuHash": Data(count: 32).base64EncodedString()]],
    ])
    let (_, json) = await b.handle(method: "POST", path: "/api/HubClient/SignHash", body: body)
    let v = try JSONSerialization.jsonObject(with: json) as! [String: Any]
    #expect(v["status"] as? Int == 404)
}
