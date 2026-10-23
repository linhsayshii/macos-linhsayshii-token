import Testing
import Foundation
import Security
@testable import Core

private let prologTaxXML = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n<HSoThueDTu xmlns=\"http://kekhaithue.gdt.gov.vn/TKhaiThue\"><HSoKhaiThue id=\"ID_1\"><tenDVu>Thử tổng hợp</tenDVu></HSoKhaiThue><CKyDTu/></HSoThueDTu>"

private func prologOptions() -> XMLSignOptions {
    var options = XMLSignOptions()
    options.kind = .custom(parentXPath: "HSoThueDTu/CKyDTu")
    options.signElements = ["HSoKhaiThue"]
    options.signingTime = Date(timeIntervalSince1970: 1_792_761_600)
    return options
}

/// A legal UTF-8 BOM must not become text in the serialized prolog or alter the
/// signed declaration. Use one software key/time to compare the actual bytes.
@Test func xmlPrologUTF8BOMAndPlainProduceIdenticalSignedBytes() async throws {
    let pki = try TestPKI.make()
    let plain = Data(prologTaxXML.utf8)
    let withBOM = Data([0xef, 0xbb, 0xbf]) + plain
    let outputs = try await [plain, withBOM].asyncMapForProlog { input in
        try XMLDSigSigner.validateInput(input, options: prologOptions())
        return try await XMLDSigSigner.signEnveloped(xml: input, signer: pki.signer, options: prologOptions())
    }
    #expect(outputs[0] == outputs[1])
    for output in outputs {
        #expect(String(data: output, encoding: .utf8) != nil)
        let doc = try XMLDocument(data: output, options: [.nodePreserveAll])
        #expect(doc.rootElement()?.localName == "HSoThueDTu")
        #expect(try doc.nodes(forXPath: "//*[local-name()='tenDVu']").first?.stringValue == "Thử tổng hợp")
        #expect(try doc.nodes(forXPath: "//*[local-name()='Signature']").count == 1)
    }
}

/// Do not strip arbitrary leading bytes, or unwrap base64/JSON by guessing.
/// Reject these inputs before the signing callback can request a PIN.
@Test func xmlPrologMalformedAndWrappedDocumentsCannotReachSigner() async throws {
    let xml = Data(prologTaxXML.utf8)
    let inputs: [(Data, XMLDSigError)] = [
        (Data([0xef, 0xbb, 0xbf, 0xef, 0xbb, 0xbf]) + xml, .badXML),
        (Data(xml.base64EncodedString().utf8), .badXML),
        (try JSONSerialization.data(withJSONObject: ["data": xml.base64EncodedString()]), .badXML),
        (Data("TEST_ONLY".utf8) + xml, .badXML),
        (prologTaxXML.replacingOccurrences(of: "UTF-8", with: "UTF-16").data(using: .utf16)!, .rejected(.encoding))
    ]
    let signer = CallbackMessageSigner(certificateDER: Data()) { _, _ in
        Issue.record("Malformed XML reached the signing callback")
        return Data()
    }
    for (input, expected) in inputs {
        await #expect(throws: expected) {
            _ = try await XMLDSigSigner.signEnveloped(xml: input, signer: signer, options: prologOptions())
        }
    }
}

@Test(.enabled(if: Tool.exists("xmlsec1")))
func xmlPrologBOMSignatureVerifiesAfterSerializationAndRejectsTamper() async throws {
    let pki = try TestPKI.make()
    let output = try await XMLDSigSigner.signEnveloped(xml: Data([0xef, 0xbb, 0xbf]) + Data(prologTaxXML.utf8),
                                                     signer: pki.signer, options: prologOptions())
    let dir = try TempDir()
    defer { try? FileManager.default.removeItem(at: dir.url) }
    func verify(_ bytes: Data) throws -> Int32 {
        try bytes.write(to: dir["signed.xml"])
        return try Tool.run("xmlsec1", ["--verify", "--insecure", "--enabled-key-data", "x509",
            "--id-attr:id", "HSoKhaiThue", "--id-attr:Id", "http://www.w3.org/2000/09/xmldsig#:Object",
            dir["signed.xml"].path]).status
    }
    #expect(try verify(output) == 0)
    let tampered = Data(String(decoding: output, as: UTF8.self).replacingOccurrences(of: "Thử tổng hợp", with: "TAMPERED").utf8)
    #expect(try verify(tampered) != 0)
}

private extension Array where Element == Data {
    func asyncMapForProlog(_ transform: (Data) async throws -> Data) async rethrows -> [Data] {
        var output: [Data] = []
        for element in self { output.append(try await transform(element)) }
        return output
    }
}
