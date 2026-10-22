import Testing
import Foundation
import Security
@testable import Core

private let invoice = #"<HDon xmlns="urn:test:inv"><DLHDon><TTChung><SHDon>1</SHDon></TTChung></DLHDon><DSCKS><NBan/></DSCKS></HDon>"#

@Test func placementAndSigningTime() async throws {
    let pki = try TestPKI.make()
    let out = try await XMLDSigSigner.signEnveloped(xml: Data(invoice.utf8), signer: pki.signer, options: XMLSignOptions())
    let doc = try XMLDocument(data: out, options: [.nodePreserveAll])
    #expect(try doc.nodes(forXPath: "//*[local-name()='NBan']/*[local-name()='Signature']").count == 1)
    let t = try doc.nodes(forXPath: "//*[local-name()='SignatureProperty'][@Target='#seller']/*[local-name()='SigningTime']")
    #expect(t.count == 1)
}

@Test func missingPlacementIsCreatedAndWrongRootRejected() async throws {
    let pki = try TestPKI.make()
    let out = try await XMLDSigSigner.signEnveloped(xml: Data("<TKhai><x/></TKhai>".utf8), signer: pki.signer,
                                                    options: { var o = XMLSignOptions(); o.kind = .toKhai; return o }())
    let doc = try XMLDocument(data: out, options: [])
    #expect(try doc.nodes(forXPath: "/TKhai/DSCKS/NNT/*[local-name()='Signature']").count == 1)
    await #expect(throws: XMLDSigError.self) {
        _ = try await XMLDSigSigner.signEnveloped(xml: Data("<Other/>".utf8), signer: pki.signer, options: XMLSignOptions())
    }
}

@Test(.enabled(if: Tool.exists("xmlsec1")), arguments: [HashAlg.sha256, HashAlg.sha1])
func xmlsec1VerifiesAndDetectsTamper(h: HashAlg) async throws {
    let pki = try TestPKI.make()
    var o = XMLSignOptions(); o.hash = h
    let out = try await XMLDSigSigner.signEnveloped(xml: Data(invoice.utf8), signer: pki.signer, options: o)
    let d = try TempDir()
    func run(_ data: Data) throws -> (status: Int32, stderr: String) {
        try data.write(to: d["s.xml"])
        return try Tool.run("xmlsec1", ["--verify", "--id-attr:Id", "http://www.w3.org/2000/09/xmldsig#:Object",
                                        "--trusted-pem", pki.certPEMPath, "--enabled-key-data", "x509", d["s.xml"].path])
    }
    let ok = try run(out)
    #expect(ok.status == 0, "\(ok.stderr)")
    let tampered = Data(String(decoding: out, as: UTF8.self).replacingOccurrences(of: "<SHDon>1<", with: "<SHDon>2<").utf8)
    #expect(try run(tampered).status != 0)
}

/// Independent of xmlsec1: re-derive reference 1 and verify the SignatureValue
/// against the key, canonicalizing SignedInfo from the parsed output.
@Test func selfVerify() async throws {
    let pki = try TestPKI.make()
    let out = try await XMLDSigSigner.signEnveloped(xml: Data(invoice.utf8), signer: pki.signer, options: XMLSignOptions())
    let doc = try XMLDocument(data: out, options: [.nodePreserveAll])
    func text(_ x: String) throws -> String { try doc.nodes(forXPath: x).first?.stringValue ?? "" }
    let si = try #require(try doc.nodes(forXPath: "//*[local-name()='SignedInfo']").first)
    let sig = try #require(Data(base64Encoded: try text("//*[local-name()='SignatureValue']")))
    let msg = Data(si.canonicalXMLStringPreservingComments(false).utf8)
    let pub = try #require(SecKeyCopyPublicKey(pki.key))
    #expect(SecKeyVerifySignature(pub, .rsaSignatureMessagePKCS1v15SHA256, msg as CFData, sig as CFData, nil))
    // Reference 1: drop the Signature, canonicalize, compare with DigestValue.
    let signature = try #require(try doc.nodes(forXPath: "//*[local-name()='Signature']").first)
    signature.detach()
    let d1 = CMSSigner.digest(Data(doc.canonicalXMLStringPreservingComments(false).utf8), .sha256).base64EncodedString()
    #expect(d1 == (try XMLDocument(data: out, options: []).nodes(forXPath: "(//*[local-name()='DigestValue'])[1]").first?.stringValue))
}

private let tkhai = "<HSoThueDTu xmlns=\"http://kekhaithue.gdt.gov.vn/TKhaiThue\"><HSoKhaiThue id=\"ID_1\"><TTinChung><maDVu>HTKK</maDVu></TTinChung></HSoKhaiThue></HSoThueDTu>"

@Test func signsElementByIdAndPlacesUnderCKyDTu() async throws {
    let pki = try TestPKI.make()
    var o = XMLSignOptions()
    o.kind = .custom(parentXPath: "HSoThueDTu/CKyDTu"); o.signElements = ["HSoKhaiThue"]
    let out = try await XMLDSigSigner.signEnveloped(xml: Data(tkhai.utf8), signer: pki.signer, options: o)
    let doc = try XMLDocument(data: out, options: [.nodePreserveAll])
    #expect(try doc.nodes(forXPath: "/*[local-name()='HSoThueDTu']/*[local-name()='CKyDTu']/*[local-name()='Signature']").count == 1)
    #expect(try doc.nodes(forXPath: "//*[local-name()='Reference'][@URI='#ID_1']").count == 1)
    #expect(try doc.nodes(forXPath: "//*[local-name()='Reference'][@URI='']").isEmpty)
}

@Test(.enabled(if: Tool.exists("xmlsec1")))
func xmlsec1VerifiesElementReference() async throws {
    let pki = try TestPKI.make()
    var o = XMLSignOptions()
    o.kind = .custom(parentXPath: "HSoThueDTu/CKyDTu"); o.signElements = ["HSoKhaiThue"]
    let out = try await XMLDSigSigner.signEnveloped(xml: Data(tkhai.utf8), signer: pki.signer, options: o)
    let d = try TempDir(); try out.write(to: d["s.xml"])
    func run() throws -> (status: Int32, stderr: String) {
        try Tool.run("xmlsec1", ["--verify", "--insecure", "--id-attr:id", "http://kekhaithue.gdt.gov.vn/TKhaiThue:HSoKhaiThue",
                                 "--id-attr:Id", "http://www.w3.org/2000/09/xmldsig#:Object", "--enabled-key-data", "x509", d["s.xml"].path])
    }
    let ok = try run()
    #expect(ok.status == 0, "\(ok.stderr)")
    try Data(String(decoding: out, as: UTF8.self).replacingOccurrences(of: "<maDVu>HTKK<", with: "<maDVu>XXXX<").utf8).write(to: d["s.xml"])
    #expect(try run().status != 0)
}

@Test func signsTaxDeclarationWithXmlDeclCRLFAndVietnamese() async throws {
    let xml = "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\r\n<HSoThueDTu xmlns:xsi=\"http://www.w3.org/2001/XMLSchema-instance\" xmlns=\"http://kekhaithue.gdt.gov.vn/TKhaiThue\">\r\n  <HSoKhaiThue id=\"ID_1\">\r\n    <TTinChung><tenDVu>HỖ TRỢ KÊ KHAI THUẾ</tenDVu></TTinChung>\r\n  </HSoKhaiThue>\r\n</HSoThueDTu>"
    let pki = try TestPKI.make()
    var o = XMLSignOptions()
    o.kind = .custom(parentXPath: "HSoThueDTu/CKyDTu"); o.signElements = ["HSoKhaiThue"]
    let out = try await XMLDSigSigner.signEnveloped(xml: Data(xml.utf8), signer: pki.signer, options: o)
    #expect(!out.isEmpty)
    let s = String(decoding: out, as: UTF8.self)
    #expect(s.contains("HỖ TRỢ KÊ KHAI THUẾ") && s.contains("<CKyDTu>") || s.contains("CKyDTu"))
    #expect(s.contains("SignatureValue"))
}

@Test func rejectsUnsafeXMLAndDuplicateIDsBeforeSigning() throws {
    for xml in ["<!DOCTYPE a [<!ENTITY x SYSTEM 'file:///etc/hosts'>]><a>&x;</a>",
                "<a><b Id='same'/><c id='same'/></a>", "<a><Signature/></a>"] {
        #expect(throws: XMLDSigError.badXML) { try XMLDSigSigner.validateInput(Data(xml.utf8)) }
    }
}
