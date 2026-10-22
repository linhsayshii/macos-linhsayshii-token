import Testing
import Foundation
import Core
@testable import Bridges

private func obj(_ s: String) -> [String: Any] { try! JSONSerialization.jsonObject(with: Data(s.utf8)) as! [String: Any] }
private let origin = "https://thuedientu.gdt.gov.vn"
private let xmlB64 = Data("<TKhai/>".utf8).base64EncodedString()

@Test func nestedAndFlatCER002Agree() async {
    let b = ESignerBridge(service: FakeSigningService())
    for req in [#"{"CODE":"CER_002","INPUT":{"CHECK_CERT_SERIAL":""}}"#, #"{"CODE":"CER_002","CHECK_CERT_SERIAL":""}"#] {
        let r = obj(await b.handle(text: req, origin: origin))
        #expect(r["SUCCESS"] as? String == "TRUE")
        #expect(r["HEX_SERIAL"] as? String == "54010101")
        #expect(r["MST"] as? String == "0101")
        #expect(r["CODE"] as? String == "CER_002")
    }
}

@Test func checkVersion() async {
    let r = obj(await ESignerBridge(service: FakeSigningService()).handle(text: #"{"CODE":"CHECK_VERSION"}"#, origin: origin))
    #expect(r["IS_UPDATE"] as? String == "N")
}

@Test func valueSignsWholeXmlAndNeverForwardsPIN() async {
    let svc = FakeSigningService()
    let r = obj(await ESignerBridge(service: svc).handle(
        text: #"{"CODE":"CER_001","INPUT":{"VALUE":"\#(xmlB64)","SERIAL_NUMBER":"54010101","PIN_CODE":"123456"}}"#, origin: origin))
    #expect(r["SUCCESS"] as? String == "TRUE")
    #expect(Data(base64Encoded: r["SIGNED_CONTENT"] as! String).map { String(decoding: $0, as: UTF8.self) }!.contains("Signature"))
    #expect(svc.calls == [.init(kind: "xml", origin: origin, serial: "54010101", input: Data("<TKhai/>".utf8))])
    #expect(!"\(svc.calls)".contains("123456"))
}

@Test func base64ValueSignsPreparedBytesWithSHA1ForCER001() async {
    let svc = FakeSigningService()
    let r = obj(await ESignerBridge(service: svc).handle(text: #"{"CODE":"CER_001","BASE64_VALUE":"\#(xmlB64)"}"#, origin: origin))
    #expect(r["SUCCESS"] as? String == "TRUE")
    #expect(svc.calls.first?.kind == "msg-sha1")
    #expect(r["PIN_CODE"] as? String == "")
}

@Test func unsupportedBadJsonAndDenial() async {
    let svc = FakeSigningService()
    let b = ESignerBridge(service: svc)
    #expect(obj(await b.handle(text: #"{"CODE":"JFU_001"}"#, origin: origin))["ERROR"] as? String == "NOT_SUPPORTED")
    #expect(obj(await b.handle(text: "nope", origin: origin))["ERROR"] as? String == "BAD_JSON")
    svc.failure = .userDenied
    #expect(obj(await b.handle(text: #"{"CODE":"CER_001","VALUE":"\#(xmlB64)"}"#, origin: origin))["ERROR"] as? String == "USER_DENIED")
}

// MARK: eTax XML-khai flow (CHOOSE_FILE → OFFLINE_XML_SIGN_002 → OFFLINE_XML_SIGN_003)

private struct StubChooser: FileChooser { let url: URL?; func chooseXML() async -> URL? { url } }
private actor StubXMLVerifier: SignedXMLVerifier {
    var failure: SigningFailure?
    var verified: [Data] = []
    func fail() { failure = .bad("Chữ ký XML không hợp lệ") }
    func verify(_ data: Data) async throws {
        verified.append(data)
        if let failure { throw failure }
    }
}
private final class StubUploader: SignedFileUploader, @unchecked Sendable {
    var sent: (URL, String, String, String, Data)?
    func upload(to url: URL, cookieName: String, cookieValue: String, uploadedFileName: String, fileName: String, data: Data) async throws {
        sent = (url, cookieName + "=" + cookieValue, uploadedFileName, fileName, data)
    }
}
private func tempXML() throws -> URL {
    let u = FileManager.default.temporaryDirectory.appendingPathComponent("tk-\(UUID().uuidString).xml")
    try Data("<HSoThueDTu><HSoKhaiThue id=\"ID_1\"><maTKhai>842</maTKhai></HSoKhaiThue><CKyDTu/></HSoThueDTu>".utf8).write(to: u)
    return u
}

@Test func chooseFileReturnsPortalShapeAndCancelFails() async throws {
    let url = try tempXML()
    let r = obj(await ESignerBridge(service: FakeSigningService(), chooser: StubChooser(url: url)).handle(text: #"{"CODE":"CHOOSE_FILE"}"#, origin: origin))
    #expect(r["SUCCESS"] as? String == "TRUE")
    #expect(r["TKHAI_FORMAT"] as? String == "9")
    #expect(r["FULL_PATH_URL"] as? String == url.path)
    #expect(r["FILE_NAME"] as? String == url.lastPathComponent)
    let c = obj(await ESignerBridge(service: FakeSigningService(), chooser: StubChooser(url: nil)).handle(text: #"{"CODE":"CHOOSE_FILE"}"#, origin: origin))
    #expect(c["SUCCESS"] as? String == "FALSE")
    #expect(c["FILE_NAME"] as? String == "")
    #expect(obj(await ESignerBridge(service: FakeSigningService()).handle(text: #"{"CODE":"CHOOSE_FILE"}"#, origin: origin))["ERROR"] as? String == "NOT_SUPPORTED")
}

@Test func signThenUploadOnlyIssuedPaths() async throws {
    let url = try tempXML(), svc = FakeSigningService(), up = StubUploader()
    let verifier = StubXMLVerifier()
    let b = ESignerBridge(service: svc, chooser: StubChooser(url: url), uploader: up, verifier: verifier)
    let sign = #"{"CODE":"OFFLINE_XML_SIGN_002","URL_FILE_NAME":"\#(url.path)","XPATH_DATA":"/HSoThueDTu/HSoKhaiThue","XPATH_SIGN":"/HSoThueDTu/CKyDTu","SERIAL_NUMBER":"1409351937","CHECK_TIN":"true","TIN_VALID":"0101","PIN_CODE":"123456"}"#
    // not issued yet → refused, nothing signed
    #expect(obj(await b.handle(text: sign, origin: origin))["ERROR"] as? String == "BAD_INPUT")
    _ = await b.handle(text: #"{"CODE":"CHOOSE_FILE"}"#, origin: origin)
    // 1409351937 decimal == 0x54010101
    let s = obj(await b.handle(text: sign, origin: origin))
    #expect(s["SUCCESS"] as? String == "TRUE")
    #expect(await verifier.verified == [Data("<signed><ds:Signature/></signed>".utf8)])
    #expect(svc.calls.last?.serial == "54010101")
    #expect(!"\(svc.calls)".contains("123456"))
    let up3 = #"{"CODE":"OFFLINE_XML_SIGN_003","URL_FILE_NAME":"\#(url.path)","REQUEST_URL_ACTION":"https://thuedientu.gdt.gov.vn/etaxnnt/Request?x=1","UPLOADED_FILE_NAME":"0101_1","COOKIE_NAME":"JSESSIONID","COOKIE_VALUE":"abc"}"#
    let r = obj(await b.handle(text: up3, origin: origin))
    #expect(r["SUCCESS"] as? String == "TRUE")
    #expect(up.sent?.4 == Data("<signed><ds:Signature/></signed>".utf8))   // signed bytes, not the file on disk
    #expect(up.sent?.1 == "JSESSIONID=abc")
    // cookie never goes to a different host
    let evil = up3.replacingOccurrences(of: "thuedientu.gdt.gov.vn", with: "evil.example")
    #expect(obj(await b.handle(text: evil, origin: origin))["ERROR"] as? String == "BAD_UPLOAD_URL")
    // a path the picker never issued is refused
    let other = up3.replacingOccurrences(of: url.path, with: "/etc/hosts")
    #expect(obj(await b.handle(text: other, origin: origin))["ERROR"] as? String == "BAD_INPUT")
    // A failed re-sign must invalidate the previous signed bytes and prevent
    // falling back to uploading the original unsigned file from disk.
    up.sent = nil
    await verifier.fail()
    let failed = obj(await b.handle(text: sign, origin: origin))
    #expect(failed["SUCCESS"] as? String == "FALSE")
    #expect((failed["ERROR"] as? String)?.contains("Chữ ký XML không hợp lệ") == true)
    #expect(obj(await b.handle(text: up3, origin: origin))["SUCCESS"] as? String == "FALSE")
    #expect(up.sent == nil)
}

@Test func signRejectsWrongSerialAndTin() async throws {
    let url = try tempXML(), svc = FakeSigningService()
    let b = ESignerBridge(service: svc, chooser: StubChooser(url: url))
    _ = await b.handle(text: #"{"CODE":"CHOOSE_FILE"}"#, origin: origin)
    func req(_ extra: String) -> String { #"{"CODE":"OFFLINE_XML_SIGN_002","URL_FILE_NAME":"\#(url.path)","XPATH_DATA":"/HSoThueDTu/HSoKhaiThue","XPATH_SIGN":"/HSoThueDTu/CKyDTu",\#(extra)}"# }
    #expect(obj(await b.handle(text: req(#""SERIAL_NUMBER":"12345""#), origin: origin))["ERROR"] as? String == "NO_CERT")
    #expect(obj(await b.handle(text: req(#""SERIAL_NUMBER":"1409351937","CHECK_TIN":"true","TIN_VALID":"9999""#), origin: origin))["ERROR"] as? String == "TIN_MISMATCH")
    #expect(svc.calls.isEmpty)
}

@Test func decimalSerialToHex() {
    #expect(ESignerFileOps.decimalToHex("1409351937") == "54010101")
    #expect(ESignerFileOps.decimalToHex("255") == "FF")
    #expect(ESignerFileOps.decimalToHex("111660627920898178847771710708736831338") == "54010E004EC042B6DCD011ABE8BBAF6A")
}
