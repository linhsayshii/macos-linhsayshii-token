import Foundation
import CryptoKit
import Security
import X509

public enum MinvoiceError: Error, Equatable, Sendable {
    case invalidInput, unsupported, invalidXML, invalidSignature, expiredCertificate
    case server(Int), transport, uploadUncertain, busy, cancelled
}

public typealias MinvoiceSign = @Sendable (Data) async throws -> Data

/// XML layout per invoice kind. Cash (series letter 5 = M) was confirmed live:
/// TDiep/DLieu + empty CKSNNT. Ordinary HDon follows installed plugin 1.0.3.0
/// statically (ExecSignXmlInvoice 0x0600039d: LoadXml, no Id insertion,
/// signature appended to //HDon/DSCKS/NBan). BKe is not handled by 1.0.3.0
/// and is rejected here.
public enum MinvoiceXMLProfile: Sendable, Equatable {
    case cash, ordinary
    var root: String { self == .cash ? "/TDiep" : "/HDon" }
    var parent: String { self == .cash ? "/TDiep/CKSNNT" : "/HDon/DSCKS/NBan" }
    /// Series like 1C26MXX → cash; any other ASCII series → ordinary HDon.
    public static func forSeries(_ serial: String) -> MinvoiceXMLProfile? {
        let bytes = Array(serial.uppercased().utf8)
        guard bytes.count >= 7, bytes.allSatisfy({ $0 < 128 }) else { return nil }
        return bytes[4] == 77 ? .cash : .ordinary
    }
}

/// Shared XMLDSig profile of the installed Windows plugin (SignXmlData).
public enum MinvoiceCashXML {
    static let ns = "http://www.w3.org/2000/09/xmldsig#"
    static let c14n = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"
    static let sha256 = "http://www.w3.org/2001/04/xmlenc#sha256"

    public static func validateCertificate(_ cert: CertInfo, now: Date = Date()) throws {
        guard let der = Data(base64Encoded: cert.derB64), let parsed = try? Certificate(derEncoded: Array(der)),
              SecCertificateCreateWithData(nil, der as CFData) != nil else { throw MinvoiceError.invalidInput }
        guard parsed.notValidBefore <= now, now <= parsed.notValidAfter else { throw MinvoiceError.expiredCertificate }
    }

    static func document(_ bytes: Data) throws -> XMLDocument {
        guard bytes.count <= 8 << 20, let text = String(data: bytes, encoding: .utf8),
              !text.uppercased().contains("<!DOCTYPE"), !text.uppercased().contains("<!ENTITY"),
              let doc = try? XMLDocument(data: bytes, options: [.nodePreserveAll]) else { throw MinvoiceError.invalidXML }
        return doc
    }

    static func canonical(_ node: XMLNode) -> Data { Data(node.canonicalXMLStringPreservingComments(false).utf8) }
    static func digest(_ node: XMLNode) -> String { Data(SHA256.hash(data: canonical(node))).base64EncodedString() }

    static func one(_ node: XMLNode, _ path: String) throws -> XMLElement {
        let nodes = try node.nodes(forXPath: path)
        guard nodes.count == 1, let element = nodes[0] as? XMLElement else { throw MinvoiceError.invalidXML }
        return element
    }

    static func target(_ doc: XMLDocument, id: UUID, profile: MinvoiceXMLProfile) throws -> XMLElement {
        let root = try one(doc, profile.root)
        guard root.uri == nil || root.uri == "" else { throw MinvoiceError.unsupported }
        let guid = id.uuidString.lowercased()
        let target: XMLElement
        switch profile {
        case .cash: target = try one(root, "./DLieu")
        // Plugin GetIdElement resolves //*[@Id=guid]; require it to be a direct
        // HDon child outside DSCKS so the signature never covers itself.
        case .ordinary:
            target = try one(root, "./*[@Id='\(guid)']")
            guard target.name != "DSCKS" else { throw MinvoiceError.invalidXML }
        }
        guard target.attribute(forName: "Id")?.stringValue == guid else { throw MinvoiceError.invalidXML }
        // Reject duplicate IDs anywhere, including unsigned metadata, before signing.
        var ids = Set<String>()
        for node in try doc.nodes(forXPath: "//@Id | //@id | //@ID") {
            guard let value = node.stringValue, !value.isEmpty, ids.insert(value).inserted else { throw MinvoiceError.invalidXML }
        }
        return target
    }

    public static func sign(xml: Data, id: UUID, signingTime: String, certificate: CertInfo,
                            profile: MinvoiceXMLProfile = .cash, signer: MinvoiceSign) async throws -> Data {
        guard validTime(signingTime) else { throw MinvoiceError.invalidInput }
        let doc = try document(xml)
        let data = try target(doc, id: id, profile: profile)
        let parent = try one(doc, profile.parent)
        guard (try doc.nodes(forXPath: "//*[local-name()='Signature']")).isEmpty,
              (try parent.nodes(forXPath: "./*")).isEmpty,
              (try doc.nodes(forXPath: "//*[@Id='signtime' or @id='signtime' or @ID='signtime']")).isEmpty,
              let der = Data(base64Encoded: certificate.derB64),
              SecCertificateCreateWithData(nil, der as CFData) != nil else { throw MinvoiceError.invalidXML }
        // User-controlled subject text is assigned through DOM, never interpolated.
        let guid = id.uuidString.lowercased()
        let signature = try XMLElement(xmlString: """
        <Signature xmlns="\(ns)"><SignedInfo><CanonicalizationMethod Algorithm="\(c14n)"/><SignatureMethod Algorithm="http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"/><Reference URI="#\(guid)"><Transforms><Transform Algorithm="\(ns)enveloped-signature"/><Transform Algorithm="\(c14n)"/></Transforms><DigestMethod Algorithm="\(sha256)"/><DigestValue/></Reference><Reference URI="#signtime"><DigestMethod Algorithm="\(sha256)"/><DigestValue/></Reference></SignedInfo><SignatureValue/><KeyInfo><X509Data><X509SubjectName/><X509Certificate/></X509Data></KeyInfo><Object Id="signtime"><SignatureProperties xmlns=""><SignatureProperty Target="#signtime"><SigningTime/></SignatureProperty></SignatureProperties></Object></Signature>
        """)
        parent.addChild(signature)
        let info = try one(signature, "./*[local-name()='SignedInfo']")
        let object = try one(signature, "./*[local-name()='Object']")
        try one(object, ".//*[local-name()='SigningTime']").stringValue = signingTime
        try one(signature, ".//*[local-name()='X509SubjectName']").stringValue = certificate.subject
        try one(signature, ".//*[local-name()='X509Certificate']").stringValue = certificate.derB64
        try one(info, "./*[local-name()='Reference'][1]/*[local-name()='DigestValue']").stringValue = digest(data)
        try one(info, "./*[local-name()='Reference'][2]/*[local-name()='DigestValue']").stringValue = digest(object)
        let signed = try await signer(canonical(info))
        try one(signature, "./*[local-name()='SignatureValue']").stringValue = signed.base64EncodedString()
        let output = doc.xmlData(options: [.nodePreserveAll])
        try verify(xml: output, id: id, certificate: certificate, profile: profile)
        return output
    }

    /// Verify the serialized bytes with the exact certificate approved for this
    /// request; no key supplied by the XML can replace it.
    public static func verify(xml: Data, id: UUID, certificate: CertInfo, profile: MinvoiceXMLProfile = .cash) throws {
        let doc = try document(xml)
        let data = try target(doc, id: id, profile: profile)
        let signature = try one(doc, profile.parent + "/*[local-name()='Signature']")
        guard signature.uri == ns, (try doc.nodes(forXPath: "//*[local-name()='Signature']")).count == 1 else { throw MinvoiceError.invalidXML }
        let info = try one(signature, "./*[local-name()='SignedInfo']")
        let object = try one(signature, "./*[local-name()='Object'][@Id='signtime']")
        let properties = try one(object, "./*[local-name()='SignatureProperties']")
        let property = try one(properties, "./*[local-name()='SignatureProperty']")
        let time = try one(property, "./*[local-name()='SigningTime']")
        guard object.uri == ns, [properties, property, time].allSatisfy({ ($0.uri ?? "").isEmpty }),
              property.attribute(forName: "Target")?.stringValue == "#signtime", validTime(time.stringValue ?? "") else { throw MinvoiceError.invalidXML }
        let refs = try info.nodes(forXPath: "./*[local-name()='Reference']")
        guard refs.count == 2,
              try one(info, "./*[local-name()='CanonicalizationMethod']").attribute(forName: "Algorithm")?.stringValue == c14n,
              try one(info, "./*[local-name()='SignatureMethod']").attribute(forName: "Algorithm")?.stringValue == "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256" else { throw MinvoiceError.invalidXML }
        for (index, node) in [data, object].enumerated() {
            guard let ref = refs[index] as? XMLElement,
                  ref.attribute(forName: "URI")?.stringValue == (index == 0 ? "#\(id.uuidString.lowercased())" : "#signtime"),
                  try one(ref, "./*[local-name()='DigestMethod']").attribute(forName: "Algorithm")?.stringValue == sha256,
                  try one(ref, "./*[local-name()='DigestValue']").stringValue == digest(node) else { throw MinvoiceError.invalidSignature }
            let transforms = try ref.nodes(forXPath: "./*[local-name()='Transforms']/*[local-name()='Transform']")
            let algorithms = transforms.compactMap { ($0 as? XMLElement)?.attribute(forName: "Algorithm")?.stringValue }
            guard algorithms == (index == 0 ? [ns + "enveloped-signature", c14n] : []) else { throw MinvoiceError.invalidXML }
        }
        guard try one(signature, ".//*[local-name()='X509Certificate']").stringValue == certificate.derB64,
              let der = Data(base64Encoded: certificate.derB64), let cert = SecCertificateCreateWithData(nil, der as CFData),
              let key = SecCertificateCopyKey(cert),
              let value = try one(signature, "./*[local-name()='SignatureValue']").stringValue,
              let bytes = Data(base64Encoded: value),
              SecKeyVerifySignature(key, .rsaSignatureMessagePKCS1v15SHA256, canonical(info) as CFData, bytes as CFData, nil)
        else { throw MinvoiceError.invalidSignature }
    }

    public static func validTime(_ text: String) -> Bool {
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX"); formatter.timeZone = TimeZone(secondsFromGMT: 0)
        formatter.dateFormat = "yyyy-MM-dd'T'HH:mm:ss"; formatter.isLenient = false
        return text.utf8.count == 19 && formatter.date(from: text).map { formatter.string(from: $0) == text } == true
    }
}
