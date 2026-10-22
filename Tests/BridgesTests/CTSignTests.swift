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

private func xmlBody(_ extra: [String: Any]) throws -> Data {
    try JSONSerialization.data(withJSONObject: extra)
}

@Test func signXmlReturnsBase64Signed() async throws {
    let svc = FakeSigningService()
    let b = CTSignBridge(backend: FakeBackend(), service: svc)
    let body = try xmlBody(["serinumber": "54010101", "dataFile": Data("<a/>".utf8).base64EncodedString()])
    let (_, json) = await b.handle(method: "POST", path: "/api/HubClient/signxml", body: body, origin: "https://x.gdt.gov.vn")
    let v = try JSONSerialization.jsonObject(with: json) as! [String: Any]
    #expect(v["status"] as? Int == 200)
    let out = Data(base64Encoded: v["data"] as! String)!
    #expect(String(decoding: out, as: UTF8.self).contains("<ds:Signature"))
    #expect(svc.calls == [.init(kind: "xml", origin: "https://x.gdt.gov.vn", serial: "54010101", input: Data("<a/>".utf8))])
}

@Test func signXmlIgnoresFilePath() async throws {
    let svc = FakeSigningService()
    let b = CTSignBridge(backend: FakeBackend(), service: svc)
    let (_, json) = await b.handle(method: "POST", path: "/api/HubClient/signxml",
                                   body: try xmlBody(["serinumber": "1", "filePath": "/etc/hosts"]))
    let v = try JSONSerialization.jsonObject(with: json) as! [String: Any]
    #expect(v["status"] as? Int == 500)
    #expect(svc.calls.isEmpty)
}

@Test func signXmlUnknownSerialIs404() async throws {
    let svc = FakeSigningService(); svc.failure = .unknownSerial("FF")
    let b = CTSignBridge(backend: FakeBackend(), service: svc)
    let (_, json) = await b.handle(method: "POST", path: "/api/HubClient/signxml",
                                   body: try xmlBody(["serinumber": "FF", "dataFile": Data("<a/>".utf8).base64EncodedString()]))
    #expect((try JSONSerialization.jsonObject(with: json) as! [String: Any])["status"] as? Int == 404)
}

@Test func expiredCertReportedInvalid() {
    #expect(CTSignBridge.notExpired("2099-01-01 00:00:00"))
    #expect(!CTSignBridge.notExpired("2025-07-28 11:09:47"))
}

@Test func caseInsensitiveRoutesAndPostGetCert() async throws {
    let b = CTSignBridge(backend: FakeBackend())
    for m in ["GET", "POST"] {
        let (st, json) = await b.handle(method: m, path: "/api/hubclient/GetCert", body: Data())
        #expect(st == 200)
        let v = try JSONSerialization.jsonObject(with: json) as! [String: Any]
        #expect((v["data"] as! [[String: Any]]).first?["serinumber"] as? String == "54010101")
        let (_, j2) = await b.handle(method: m, path: "/api/HubClient/getcert", body: Data())
        let v2 = try JSONSerialization.jsonObject(with: j2) as! [String: Any]
        #expect((v2["data"] as! [[String: Any]]).first?["serinumber"] as? String == "54010101")
        let (_, ver) = await b.handle(method: m, path: "/api/signhash/version", body: Data())
        #expect(String(decoding: ver, as: UTF8.self) == "\"1.2.0.0\"")
        let (_, info) = await b.handle(method: m, path: "/api/info/getinfocert", body: Data())
        #expect(String(decoding: info, as: UTF8.self) == "\"1\"")
    }
    let digest = Data(repeating: 0xAB, count: 32).base64EncodedString()
    let body = try JSONSerialization.data(withJSONObject: ["serinumber": "54010101", "hash": [["Ma": "one", "DLieuHash": digest]]])
    let (_, sh) = await b.handle(method: "POST", path: "/api/hubclient/signhash", body: body)
    #expect(((try JSONSerialization.jsonObject(with: sh) as! [String: Any])["status"] as? Int) == 200)
    let (st, _) = await b.handle(method: "GET", path: "/api/hubclient/signhash", body: body)
    #expect(st == 404)
    let xb = try xmlBody(["serinumber": "54010101", "dataFile": Data("<a/>".utf8).base64EncodedString()])
    let sx = CTSignBridge(backend: FakeBackend(), service: FakeSigningService())
    let (_, xj) = await sx.handle(method: "POST", path: "/API/HUBCLIENT/SIGNXML", body: xb)
    #expect(((try JSONSerialization.jsonObject(with: xj) as! [String: Any])["status"] as? Int) == 200)
    let (nf, nj) = await b.handle(method: "GET", path: "/api/nope", body: Data())
    #expect(nf == 404)
    #expect(String(decoding: nj, as: UTF8.self) == "{}")
}

@Test func signXmlAdapterReadsCksAndDataBV() throws {
    let body = try JSONSerialization.data(withJSONObject: [
        "serinumber": "54", "cks": "HSoThueDTu/CKyDTu", "dataBV": ["HSoKhaiThue"], "requestId": "x",
        "dataFile": Data("<a/>".utf8).base64EncodedString()])
    let p = try #require(SignXmlRequestAdapter.parse(body))
    #expect(p.options.signElements == ["HSoKhaiThue"])
    if case .custom(let path) = p.options.kind { #expect(path == "HSoThueDTu/CKyDTu") } else { Issue.record("kind not custom") }
}

@Test func signXmlReturnsActionableXMLDiagnosticsWithoutDocumentContents() async throws {
    let cases: [(XMLDSigError, String)] = [
        (.badXML, "XML_PARSE"), (.badPlacement("PRIVATE_PATH"), "XML_PLACEMENT"),
        (.badCertificate, "XML_CERTIFICATE"), (.rejected(.encoding), "XML_ENCODING"),
        (.rejected(.declarations), "XML_DTD_ENTITY"), (.rejected(.invalidID), "XML_INVALID_ID"),
        (.rejected(.duplicateID), "XML_DUPLICATE_ID"), (.rejected(.existingSignature), "XML_EXISTING_SIGNATURE"),
        (.rejected(.options), "XML_OPTIONS"), (.rejected(.reservedID), "XML_SIGNATURE_ID_COLLISION"),
        (.rejected(.referencePlacement), "XML_REFERENCE_PLACEMENT"), (.rejected(.tooLarge), "XML_TOO_LARGE"),
    ]
    for (error, code) in cases {
        let service = FakeSigningService(); service.xmlFailure = error
        let bridge = CTSignBridge(backend: FakeBackend(), service: service)
        let body = try xmlBody(["dataFile": Data("<a>PRIVATE_DOCUMENT_CONTENT</a>".utf8).base64EncodedString()])
        let (httpStatus, json) = await bridge.handle(method: "POST", path: "/api/HubClient/signxml", body: body)
        let response = try #require(JSONSerialization.jsonObject(with: json) as? [String: Any])
        #expect(httpStatus == 200 && response["status"] as? Int == 500)
        #expect((response["message"] as? String)?.contains("[\(code)]") == true)
        #expect(response["data"] == nil)
        let text = String(decoding: json, as: UTF8.self)
        #expect(!text.contains("PRIVATE_") && !text.contains("badXML"))
    }
}
