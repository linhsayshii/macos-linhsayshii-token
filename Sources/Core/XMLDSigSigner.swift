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

    public static func signEnveloped(xml: Data, signer: MessageSigner, options o: XMLSignOptions) async throws -> Data {
        guard let doc = try? XMLDocument(data: xml, options: [.nodePreserveAll]), let root = doc.rootElement()
        else { throw XMLDSigError.badXML }
        var parent = root
        if case .underElement(let name) = o.kind {
            if let name, let hit = ((try? root.nodes(forXPath: ".//*[local-name()='\(name)']")) as? [XMLElement])?.first { parent = hit }
        } else {
            let path = placementPath(o.kind)
            guard path.first == root.name else { throw XMLDSigError.badPlacement("root phải là \(path.first ?? "?")") }
            for name in path.dropFirst() {
                if let c = parent.elements(forName: name).first { parent = c }
                else { let c = XMLElement(name: name); parent.addChild(c); parent = c }
            }
        }

        let sigId: String
        if let s = o.signatureId { sigId = s } else if case .hoaDon = o.kind { sigId = "seller" } else { sigId = "SigningData" }
        let sha1 = o.hash == .sha1
        let sigAlg = "http://www.w3.org/2001/04/xmldsig-more#" + (sha1 ? "rsa-sha1" : "rsa-sha256")
        let digAlg = sha1 ? "http://www.w3.org/2000/09/xmldsig#sha1" : "http://www.w3.org/2001/04/xmlenc#sha256"
        let f = DateFormatter(); f.locale = Locale(identifier: "en_US_POSIX")
        f.timeZone = TimeZone(secondsFromGMT: 7 * 3600); f.dateFormat = "yyyy-MM-dd'T'HH:mm:ssxxx"
        // shortcut: signing time is fixed to +07:00 (VN); make configurable if a portal needs another zone.
        let time = f.string(from: o.signingTime)

        // Reference 1: whole document, before the Signature exists.
        let d1 = b64Digest(canon(doc), o.hash)
        let (n, e) = try rsaComponents(signer.certificateDER)

        let sigXML = """
        <ds:Signature xmlns:ds="\(ns)" Id="\(sigId)"><ds:SignedInfo>\
        <ds:CanonicalizationMethod Algorithm="\(c14n)"/><ds:SignatureMethod Algorithm="\(sigAlg)"/>\
        <ds:Reference URI=""><ds:Transforms><ds:Transform Algorithm="\(ns)enveloped-signature"/>\
        <ds:Transform Algorithm="\(c14n)"/></ds:Transforms><ds:DigestMethod Algorithm="\(digAlg)"/>\
        <ds:DigestValue>\(d1)</ds:DigestValue></ds:Reference>\
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
        // Reference 2 digests the Object as it sits in the final tree.
        let object = find("Object", in: sig)!
        let refs = (try? sig.nodes(forXPath: ".//*[local-name()='Reference']")) as? [XMLElement] ?? []
        refs[1].elements(forName: "ds:DigestValue").first?.stringValue = b64Digest(canon(object), o.hash)

        let signedInfo = find("SignedInfo", in: sig)!
        let sv = try await signer.sign(message: canon(signedInfo), hash: o.hash)
        find("SignatureValue", in: sig)!.stringValue = sv.base64EncodedString()
        return doc.xmlData(options: [.nodePreserveAll])
    }

    /// Modulus and exponent (base64, big-endian, no leading zero) from the cert's RSA key.
    static func rsaComponents(_ certDER: Data) throws -> (String, String) {
        guard let cert = SecCertificateCreateWithData(nil, certDER as CFData),
              let key = SecCertificateCopyKey(cert),
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
