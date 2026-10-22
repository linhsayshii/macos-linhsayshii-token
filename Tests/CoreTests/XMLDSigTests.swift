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
    let cases: [(String, XMLDSigError)] = [
        ("<!DOCTYPE a [<!ENTITY x SYSTEM 'file:///etc/hosts'>]><a>&x;</a>", .rejected(.declarations)),
        ("<a><Signature/></a>", .rejected(.existingSignature)),
        ("not XML", .badXML),
    ]
    for (xml, error) in cases {
        #expect(throws: error) { try XMLDSigSigner.validateInput(Data(xml.utf8)) }
    }
    // Foundation can reject malformed/duplicate xml:id during parsing itself.
    for xml in ["<a><b xml:id='same'/><c xml:id='same'/></a>", "<a><b xml:id=''/></a>"] {
        #expect(throws: XMLDSigError.self) { try XMLDSigSigner.validateInput(Data(xml.utf8)) }
    }
}

@Test func XMLValidationDistinguishesEncodingAndSizeWithoutDisclosingInput() throws {
    #expect(throws: XMLDSigError.rejected(.encoding)) { try XMLDSigSigner.validateInput(Data([0xFF])) }
    #expect(throws: XMLDSigError.rejected(.tooLarge)) { try XMLDSigSigner.validateInput(Data(count: (20 << 20) + 1)) }
    let privateValue = "PRIVATE_DOCUMENT_ID_MUST_NOT_LEAK"
    let xml = Data("<a><b Id='\(privateValue)'/><c ID='\(privateValue)'/></a>".utf8)
    do {
        var options = XMLSignOptions(); options.signElements = ["b"]
        try XMLDSigSigner.validateInput(xml, options: options)
        Issue.record("Duplicate ID accepted")
    } catch let error as XMLDSigError {
        #expect(error.description.contains("[XML_DUPLICATE_ID]"))
        #expect(!error.description.contains(privateValue))
    }
    #expect(!XMLDSigError.badPlacement(privateValue).description.contains(privateValue))
}

@Test func XMLSigningValidationDistinguishesOptionsReservedIDsAndReferencePlacement() async throws {
    let pki = try TestPKI.make()
    var options = XMLSignOptions(); options.kind = .underElement(nil)
    options.signElements = ["a']"]
    await #expect(throws: XMLDSigError.rejected(.options)) {
        _ = try await XMLDSigSigner.signEnveloped(xml: Data("<a/>".utf8), signer: pki.signer, options: options)
    }
    options.signElements = []
    await #expect(throws: XMLDSigError.rejected(.reservedID)) {
        _ = try await XMLDSigSigner.signEnveloped(xml: Data("<a><b Id='SigningTime'/></a>".utf8), signer: pki.signer, options: options)
    }
    options.signElements = ["a"]
    await #expect(throws: XMLDSigError.rejected(.referencePlacement)) {
        _ = try await XMLDSigSigner.signEnveloped(xml: Data("<a/>".utf8), signer: pki.signer, options: options)
    }
}

/// Row keys are ordinary data, not the ID used by SignedInfo's reference resolver.
@Test(.enabled(if: Tool.exists("xmlsec1")), arguments: [false, true])
func taxDeclarationWithRepeatedBusinessIDsVerifiesWithoutChangingData(namespaced: Bool) async throws {
    let pki = try TestPKI.make()
    let data = "<HSoKhaiThue id='ID_1'><BangA><Dong id='1'>A</Dong><Dong id='2'>B</Dong></BangA><BangB><Dong id='1'>C</Dong><Dong id=''/></BangB></HSoKhaiThue>"
    let namespace = namespaced ? " xmlns='http://kekhaithue.gdt.gov.vn/TKhaiThue'" : ""
    let xml = Data("<HSoThueDTu\(namespace)>\(data)</HSoThueDTu>".utf8)
    var options = XMLSignOptions()
    options.kind = .custom(parentXPath: "HSoThueDTu/CKyDTu")
    options.signElements = ["HSoKhaiThue"]
    let out = try await XMLDSigSigner.signEnveloped(xml: xml, signer: pki.signer, options: options)
    let original = try XMLDocument(data: xml, options: [.nodePreserveAll])
    let signed = try XMLDocument(data: out, options: [.nodePreserveAll])
    let path = "//*[local-name()='HSoKhaiThue']"
    #expect(try original.nodes(forXPath: path).first?.canonicalXMLStringPreservingComments(false)
         == signed.nodes(forXPath: path).first?.canonicalXMLStringPreservingComments(false))
    let dir = try TempDir()
    func verify(_ bytes: Data) throws -> Int32 {
        try bytes.write(to: dir["signed.xml"])
        let result = try Tool.run("xmlsec1", ["--verify", "--insecure", "--enabled-key-data", "x509",
            "--id-attr:id", "HSoKhaiThue", "--id-attr:Id", "http://www.w3.org/2000/09/xmldsig#:Object", dir["signed.xml"].path])
        return result.status
    }
    #expect(try verify(out) == 0)
    #expect(try verify(Data(String(decoding: out, as: UTF8.self).replacingOccurrences(of: ">C<", with: ">TAMPER<").utf8)) != 0)
}

@Test func wholeDocumentSignatureAllowsRepeatedBusinessIDs() async throws {
    let pki = try TestPKI.make()
    var options = XMLSignOptions(); options.kind = .underElement(nil)
    let xml = Data("<a><row id='1'/><row id='1'/></a>".utf8)
    let out = try await XMLDSigSigner.signEnveloped(xml: xml, signer: pki.signer, options: options)
    let doc = try XMLDocument(data: out, options: [.nodePreserveAll])
    #expect(try doc.nodes(forXPath: "//row[@id='1']").count == 2)
}

@Test func duplicateReferenceIDCannotReachSignerEvenWhenCollisionIsOutsideTarget() async throws {
    let signer = CallbackMessageSigner(certificateDER: Data()) { _, _ in
        Issue.record("Ambiguous reference reached token signer")
        return Data()
    }
    var options = XMLSignOptions(); options.kind = .custom(parentXPath: "HSoThueDTu/CKyDTu")
    options.signElements = ["HSoKhaiThue"]
    let xml = Data("<HSoThueDTu><HSoKhaiThue id='ID_1'/><Other Id='ID_1'/></HSoThueDTu>".utf8)
    await #expect(throws: XMLDSigError.rejected(.duplicateID)) {
        _ = try await XMLDSigSigner.signEnveloped(xml: xml, signer: signer, options: options)
    }
}

@Test func referenceValidationRejectsAmbiguityAndAcceptsUnreferencedRowKeys() throws {
    var options = XMLSignOptions(); options.signElements = ["Data"]
    for xml in ["<a><Data id='unique'><Row id='1'/><Row id='1'/><Row id=''/></Data></a>",
                "<a><Data xml:id='unique'/><Row id='1'/><Row id='1'/></a>"] {
        try XMLDSigSigner.validateInput(Data(xml.utf8), options: options)
    }
    let invalid: [(String, XMLDSigError)] = [
        ("<a><Data id='same'/><Other Id='same'/></a>", .rejected(.duplicateID)),
        ("<a><Data id='same'/><Other xml:id='same'/></a>", .rejected(.duplicateID)),
        ("<a><Data xml:id='same'/><Other ID='same'/></a>", .rejected(.duplicateID)),
        ("<a><Data id=''/></a>", .rejected(.invalidID)),
        ("<a><Data id='a' Id='b'/></a>", .rejected(.invalidID)),
        ("<a><Data id='first'/><Data id='second'/></a>", .rejected(.ambiguousReference)),
    ]
    for (xml, error) in invalid {
        #expect(throws: error) { try XMLDSigSigner.validateInput(Data(xml.utf8), options: options) }
    }
}

@Test func generatedReferenceIDSkipsBusinessKeysAndXMLIDs() async throws {
    let pki = try TestPKI.make()
    var options = XMLSignOptions(); options.kind = .underElement(nil); options.signElements = ["Data"]
    let xml = Data("<a><Data/><Row id='ID_1'/><Row id='ID_1'/><Other xml:id='ID_2'/></a>".utf8)
    let out = try await XMLDSigSigner.signEnveloped(xml: xml, signer: pki.signer, options: options)
    let doc = try XMLDocument(data: out, options: [])
    #expect(try doc.nodes(forXPath: "//Data/@id").first?.stringValue == "ID_3")
    #expect(try doc.nodes(forXPath: "//*[local-name()='Reference'][@URI='#ID_3']").count == 1)
    #expect(try doc.nodes(forXPath: "//Row[@id='ID_1']").count == 2)
}
