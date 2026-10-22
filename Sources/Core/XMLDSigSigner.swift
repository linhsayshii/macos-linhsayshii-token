import Foundation
import CryptoKit
import Security

public enum XMLDocKind: Sendable {
    case hoaDon, toKhai
    case custom(parentXPath: String)
    /// Append under the first element with this local name; nil (or not found) = the root element.
    case underElement(String?)
}

public struct XMLSignOptions: Sendable {
    public var hash: HashAlg = .sha256              // .sha1 -> rsa-sha1 / sha1 variant
    public var kind: XMLDocKind = .hoaDon
    public var signingTime = Date()
    /// Local names of elements to sign by reference (`#id`); empty = sign the whole document (URI="").
    /// Tax declarations send dataBV ["HSoKhaiThue"]; the element's `id` attribute is used (set to ID_n if missing).
    public var signElements: [String] = []
    public var signatureId: String? = nil           // default per kind: hoaDon "seller", toKhai "SigningData"
    public init() {}
}

public enum XMLDSigError: Error, Equatable { case badXML, badPlacement(String), badCertificate }

/// XMLDSig enveloped signature. Inclusive C14N 1.0 (Foundation/libxml2). Two
/// references: the whole document (enveloped-signature + c14n) and the
/// TT78 `SigningTime` Object.
public enum XMLDSigSigner {
    static let ns = "http://www.w3.org/2000/09/xmldsig#"
    static let c14n = "http://www.w3.org/TR/2001/REC-xml-c14n-20010315"

    public static func placementPath(_ k: XMLDocKind) -> [String] {
        switch k {
        case .hoaDon: return ["HDon", "DSCKS", "NBan"]
        case .toKhai: return ["TKhai", "DSCKS", "NNT"]
        case .custom(let p): return p.split(separator: "/").map(String.init)
        case .underElement: return []
        }
    }

    private static func canon(_ n: XMLNode) -> Data { Data(n.canonicalXMLStringPreservingComments(false).utf8) }
    private static func b64Digest(_ d: Data, _ h: HashAlg) -> String { CMSSigner.digest(d, h).base64EncodedString() }

    /// Reject external entities and duplicate IDs before requesting a token signature.
    public static func validateInput(_ xml: Data) throws { _ = try document(xml) }
    private static func document(_ xml: Data) throws -> XMLDocument {
        guard xml.count <= 20 << 20, let text = String(data: xml, encoding: .utf8),
              !text.uppercased().contains("<!DOCTYPE"), !text.uppercased().contains("<!ENTITY"),
              let doc = try? XMLDocument(data: xml, options: [.nodePreserveAll]), doc.rootElement() != nil else { throw XMLDSigError.badXML }
        var ids = Set<String>()
        for node in try doc.nodes(forXPath: "//@Id | //@id | //@ID") {
            guard let id = node.stringValue, safeID(id), ids.insert(id).inserted else { throw XMLDSigError.badXML }
        }
        guard (try doc.nodes(forXPath: "//*[local-name()='Signature']")).isEmpty else { throw XMLDSigError.badXML }
        return doc
    }
    private static func safeID(_ value: String) -> Bool {
        !value.isEmpty && !value.contains { $0.isWhitespace || "\"'&<>#".contains($0) }
    }
    private static func safeName(_ value: String) -> Bool {
        value.range(of: "^[A-Za-z_][A-Za-z0-9_.:-]*$", options: .regularExpression) != nil
    }

    public static func signEnveloped(xml: Data, signer: MessageSigner, options o: XMLSignOptions) async throws -> Data {
        let doc = try document(xml)
        guard let root = doc.rootElement(), o.signElements.allSatisfy(safeName),
              o.signatureId.map(safeID) ?? true else { throw XMLDSigError.badXML }
        var parent = root
        if case .underElement(let name) = o.kind {
            if let name, !safeName(name) { throw XMLDSigError.badXML }
            if let name, let hit = ((try? root.nodes(forXPath: ".//*[local-name()='\(name)']")) as? [XMLElement])?.first { parent = hit }
        } else {
            let path = placementPath(o.kind)
            guard path.allSatisfy(safeName), path.first == root.name else { throw XMLDSigError.badPlacement("root phải là \(path.first ?? "?")") }
            for name in path.dropFirst() {
                if let c = parent.elements(forName: name).first { parent = c }
                else { let c = XMLElement(name: name); parent.addChild(c); parent = c }
            }
        }

        let sigId: String
        if let s = o.signatureId { sigId = s } else if case .hoaDon = o.kind { sigId = "seller" } else { sigId = "SigningData" }
        let sha1 = o.hash == .sha1
        let sigAlg = sha1 ? "http://www.w3.org/2000/09/xmldsig#rsa-sha1" : "http://www.w3.org/2001/04/xmldsig-more#rsa-sha256"
        let digAlg = sha1 ? "http://www.w3.org/2000/09/xmldsig#sha1" : "http://www.w3.org/2001/04/xmlenc#sha256"
        let f = DateFormatter(); f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(secondsFromGMT: 7 * 3600); f.dateFormat = "yyyy-MM-dd'T'HH:mm:ssxxx"
        // shortcut: signing time is fixed to +07:00 (VN); make configurable if a portal needs another zone.
        let time = f.string(from: o.signingTime)

        // Elements signed by reference; otherwise reference 1 is the whole document, digested before the Signature exists.
        var targets: [(id: String, element: XMLElement)] = []
        for (i, name) in o.signElements.enumerated() {
            guard let el = ((try? root.nodes(forXPath: "//*[local-name()='\(name)']")) as? [XMLElement])?.first
            else { throw XMLDSigError.badPlacement("không có phần tử \(name)") }
            var id = ["id", "Id", "ID"].lazy.compactMap { el.attribute(forName: $0)?.stringValue }.first
            if id == nil {
                var index = i + 1
                var candidate = "ID_\(index)"
                let existing = Set(try doc.nodes(forXPath: "//@Id | //@id | //@ID").compactMap(\.stringValue))
                while existing.contains(candidate) { index += 1; candidate = "ID_\(index)" }
                id = candidate
                el.addAttribute(XMLNode.attribute(withName: "id", stringValue: candidate) as! XMLNode)
            }
            targets.append((id!, el))
        }
        let docRef: String
        if targets.isEmpty {
            docRef = """
            <ds:Reference URI=""><ds:Transforms><ds:Transform Algorithm="\(ns)enveloped-signature"/>\
            <ds:Transform Algorithm="\(c14n)"/></ds:Transforms><ds:DigestMethod Algorithm="\(digAlg)"/>\
            <ds:DigestValue>\(b64Digest(canon(doc), o.hash))</ds:DigestValue></ds:Reference>
            """
        } else {
            docRef = targets.map { t in """
            <ds:Reference URI="#\(t.id)"><ds:Transforms><ds:Transform Algorithm="\(ns)enveloped-signature"/>\
            <ds:Transform Algorithm="\(c14n)"/></ds:Transforms><ds:DigestMethod Algorithm="\(digAlg)"/>\
            <ds:DigestValue></ds:DigestValue></ds:Reference>
            """ }.joined()
        }
        let existingIDs = Set(try doc.nodes(forXPath: "//@Id | //@id | //@ID").compactMap(\.stringValue))
        guard !existingIDs.contains("SigningTime"), !existingIDs.contains(sigId), sigId != "SigningTime",
              !targets.contains(where: { target in
                  var node: XMLNode? = parent
                  while let current = node { if current === target.element { return true }; node = current.parent }
                  return false
              }) else { throw XMLDSigError.badXML }
        let (n, e) = try rsaComponents(signer.certificateDER)

        let sigXML = """
        <ds:Signature xmlns:ds="\(ns)" Id="\(sigId)"><ds:SignedInfo>\
        <ds:CanonicalizationMethod Algorithm="\(c14n)"/><ds:SignatureMethod Algorithm="\(sigAlg)"/>\
        \(docRef)\
        <ds:Reference URI="#SigningTime"><ds:Transforms><ds:Transform Algorithm="\(c14n)"/></ds:Transforms>\
        <ds:DigestMethod Algorithm="\(digAlg)"/><ds:DigestValue></ds:DigestValue></ds:Reference></ds:SignedInfo>\
        <ds:SignatureValue></ds:SignatureValue><ds:KeyInfo><ds:X509Data><ds:X509Certificate>\
        \(signer.certificateDER.base64EncodedString())</ds:X509Certificate></ds:X509Data>\
        <ds:KeyValue><ds:RSAKeyValue><ds:Modulus>\(n)</ds:Modulus><ds:Exponent>\(e)</ds:Exponent>\
        </ds:RSAKeyValue></ds:KeyValue></ds:KeyInfo>\
        <ds:Object Id="SigningTime"><ds:SignatureProperties><ds:SignatureProperty Target="#\(sigId)">\
        <SigningTime>\(time)</SigningTime></ds:SignatureProperty></ds:SignatureProperties></ds:Object></ds:Signature>
        """
        guard let sig = try? XMLElement(xmlString: sigXML) else { throw XMLDSigError.badXML }
        parent.addChild(sig)

        func find(_ local: String, in n: XMLNode) -> XMLElement? {
            ((try? n.nodes(forXPath: ".//*[local-name()='\(local)']")) as? [XMLElement])?.first
        }
        // The Object (and any referenced elements) are digested as they sit in the final tree.
        let object = find("Object", in: sig)!
        let refs = (try? sig.nodes(forXPath: ".//*[local-name()='Reference']")) as? [XMLElement] ?? []
        for (i, t) in targets.enumerated() { refs[i].elements(forName: "ds:DigestValue").first?.stringValue = b64Digest(canon(t.element), o.hash) }
        refs[refs.count - 1].elements(forName: "ds:DigestValue").first?.stringValue = b64Digest(canon(object), o.hash)

        let signedInfo = find("SignedInfo", in: sig)!
        let sv = try await signer.sign(message: canon(signedInfo), hash: o.hash)
        find("SignatureValue", in: sig)!.stringValue = sv.base64EncodedString()
        return doc.xmlData(options: [.nodePreserveAll])
    }

    /// Modulus and exponent (base64, big-endian, no leading zero) from the cert's RSA key.
    static func rsaComponents(_ certDER: Data) throws -> (String, String) {
        guard let cert = SecCertificateCreateWithData(nil, certDER as CFData),
              let key = SecCertificateCopyKey(cert),
              SecKeyIsAlgorithmSupported(key, .verify, .rsaSignatureMessagePKCS1v15SHA256),
              let raw = SecKeyCopyExternalRepresentation(key, nil) as Data? else { throw XMLDSigError.badCertificate }
        var r = [UInt8](raw)[...]
        func readLen() -> Int {
            let b = Int(r.removeFirst()); if b < 0x80 { return b }
            var v = 0; for _ in 0..<(b & 0x7f) { v = v << 8 | Int(r.removeFirst()) }; return v
        }
        func readInt() -> Data {
            r.removeFirst(); let l = readLen(); var d = Data(r.prefix(l)); r.removeFirst(l)
            while d.count > 1, d[d.startIndex] == 0 { d.removeFirst() }
            return d
        }
        r.removeFirst(); _ = readLen()                    // SEQUENCE
        let n = readInt(), e = readInt()
        return (n.base64EncodedString(), e.base64EncodedString())
    }
}
