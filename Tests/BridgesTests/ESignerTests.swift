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
