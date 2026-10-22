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

public enum XMLDSigError: Error, Equatable, CustomStringConvertible {
    case badXML, badPlacement(String), badCertificate
    case rejected(InputFailure)

    /// Stable diagnostics contain no XML content, attribute values or parser output.
    public enum InputFailure: String, Sendable {
        case tooLarge = "XML_TOO_LARGE"
        case encoding = "XML_ENCODING"
        case declarations = "XML_DTD_ENTITY"
        case invalidID = "XML_INVALID_ID"
        case duplicateID = "XML_DUPLICATE_ID"
        case ambiguousReference = "XML_AMBIGUOUS_REFERENCE"
        case existingSignature = "XML_EXISTING_SIGNATURE"
        case options = "XML_OPTIONS"
        case reservedID = "XML_SIGNATURE_ID_COLLISION"
        case referencePlacement = "XML_REFERENCE_PLACEMENT"
    }

    public var description: String {
        switch self {
        case .badXML: return "[XML_PARSE] Không đọc được tài liệu XML hợp lệ."
        case .badPlacement: return "[XML_PLACEMENT] cks hoặc dataBV không khớp cấu trúc XML."
        case .badCertificate: return "[XML_CERTIFICATE] Không đọc được khóa RSA từ chứng thư số."
        case .rejected(let reason):
            let message: String
            switch reason {
            case .tooLarge: message = "Tài liệu XML vượt giới hạn 20 MiB."
            case .encoding: message = "Mã hóa XML chưa được hỗ trợ; cần XML UTF-8."
            case .declarations: message = "XML chứa khai báo DTD hoặc ENTITY không được phép."
            case .invalidID: message = "ID của phần tử cần ký hoặc xml:id không hợp lệ."
            case .duplicateID: message = "ID của phần tử cần ký hoặc xml:id xuất hiện nhiều lần; không thể tham chiếu duy nhất."
            case .ambiguousReference: message = "dataBV khớp nhiều phần tử trong XML; không thể xác định duy nhất phần tử cần ký."
            case .existingSignature: message = "XML đã chứa phần tử Signature; chưa hỗ trợ ký lại tài liệu này."
            case .options: message = "Tham số phần tử hoặc ID chữ ký không hợp lệ."
            case .reservedID: message = "ID chữ ký hoặc SigningTime bị trùng với ID trong XML."
            case .referencePlacement: message = "Vị trí chèn chữ ký nằm trong phần tử dataBV cần ký; cấu trúc này chưa được hỗ trợ."
            }
            return "[\(reason.rawValue)] \(message)"
        }
    }
}

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

    /// Unqualified id/Id/ID attributes can be ordinary row keys. Only IDs used
    /// by signature references must be globally unique; xml:id is always an ID.
    /// Pass signing options to check reference ambiguity before presenting a PIN.
    public static func validateInput(_ xml: Data, options: XMLSignOptions? = nil) throws {
        let doc = try document(xml)
        if let options { _ = try referenceElements(in: doc, names: options.signElements) }
    }
    private static func document(_ xml: Data) throws -> XMLDocument {
        guard xml.count <= 20 << 20 else { throw XMLDSigError.rejected(.tooLarge) }
        guard let text = String(data: xml, encoding: .utf8) else { throw XMLDSigError.rejected(.encoding) }
        guard !text.uppercased().contains("<!DOCTYPE"), !text.uppercased().contains("<!ENTITY")
        else { throw XMLDSigError.rejected(.declarations) }
        guard let doc = try? XMLDocument(data: xml, options: [.nodePreserveAll]), doc.rootElement() != nil
        else { throw XMLDSigError.badXML }
        var ids = Set<String>()
        for node in try doc.nodes(forXPath: "//@xml:id") {
            guard let id = node.stringValue, safeID(id) else { throw XMLDSigError.rejected(.invalidID) }
            guard ids.insert(id).inserted else { throw XMLDSigError.rejected(.duplicateID) }
        }
        guard (try doc.nodes(forXPath: "//*[local-name()='Signature']")).isEmpty
        else { throw XMLDSigError.rejected(.existingSignature) }
        return doc
    }
    private static func safeID(_ value: String) -> Bool {
        !value.isEmpty && !value.contains { $0.isWhitespace || "\"'&<>#".contains($0) }
    }
    private static func safeName(_ value: String) -> Bool {
        value.range(of: "^[A-Za-z_][A-Za-z0-9_.:-]*$", options: .regularExpression) != nil
    }

    private static let idXPath = "//@Id | //@id | //@ID | //@xml:id"

    private static func referenceElements(in doc: XMLDocument, names: [String]) throws -> [(id: String?, element: XMLElement)] {
        guard names.allSatisfy(safeName), Set(names).count == names.count
        else { throw XMLDSigError.rejected(.options) }
        let allIDs = try doc.nodes(forXPath: idXPath).compactMap(\.stringValue)
        let counts = Dictionary(allIDs.map { ($0, 1) }, uniquingKeysWith: +)
        return try names.map { name in
            let matches = try doc.nodes(forXPath: "//*[local-name()='\(name)']").compactMap { $0 as? XMLElement }
            guard let element = matches.first else { throw XMLDSigError.badPlacement("không có phần tử \(name)") }
            guard matches.count == 1 else { throw XMLDSigError.rejected(.ambiguousReference) }
            let ids = (element.attributes ?? []).filter { ["id", "Id", "ID", "xml:id"].contains($0.name ?? "") }
            guard ids.count <= 1 else { throw XMLDSigError.rejected(.invalidID) }
            let id = ids.first?.stringValue
            if let id {
                guard safeID(id) else { throw XMLDSigError.rejected(.invalidID) }
                // Include collisions outside the target and across id/Id/ID/xml:id.
                guard counts[id] == 1 else { throw XMLDSigError.rejected(.duplicateID) }
            }
            return (id, element)
        }
    }

    public static func signEnveloped(xml: Data, signer: MessageSigner, options o: XMLSignOptions) async throws -> Data {
        let doc = try document(xml)
        guard let root = doc.rootElement(), o.signElements.allSatisfy(safeName),
              o.signatureId.map(safeID) ?? true else { throw XMLDSigError.rejected(.options) }
        var parent = root
        if case .underElement(let name) = o.kind {
            if let name, !safeName(name) { throw XMLDSigError.rejected(.options) }
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
        for (i, target) in try referenceElements(in: doc, names: o.signElements).enumerated() {
            let el = target.element
            var id = target.id
            if id == nil {
                var index = i + 1
                var candidate = "ID_\(index)"
                let existing = Set(try doc.nodes(forXPath: idXPath).compactMap(\.stringValue))
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
        let existingIDs = Set(try doc.nodes(forXPath: idXPath).compactMap(\.stringValue))
        guard !existingIDs.contains("SigningTime"), !existingIDs.contains(sigId), sigId != "SigningTime"
        else { throw XMLDSigError.rejected(.reservedID) }
        guard !targets.contains(where: { target in
                  var node: XMLNode? = parent
                  while let current = node { if current === target.element { return true }; node = current.parent }
                  return false
              }) else { throw XMLDSigError.rejected(.referencePlacement) }
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
