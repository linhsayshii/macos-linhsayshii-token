import Foundation

/// Pure request construction from MinvoicePlug.exe (SHA-256 57ffb22e…bc97a2c).
/// No transport, login, signing, or bridge dispatch is enabled here.
/// See docs/re/minvoice-rest-static.md for CIL tokens and unresolved XML defaults.
enum MinvoiceRESTRequests {
    enum ConstructionError: Error {
        case invalidAPI, invalidHeader, emptyInvoices, duplicateInvoice, invalidBoundary, boundaryCollision
    }

    /// An authenticated context obtained by a future, separately reviewed login flow.
    /// Values must stay in memory and must never be logged or persisted.
    struct Session: Sendable {
        let api: URL
        let userAgent: String
        let cookie: String
        let verificationToken: String

        init(api: URL, userAgent: String, cookie: String, verificationToken: String) throws {
            guard let c = URLComponents(url: api, resolvingAgainstBaseURL: false),
                  c.scheme == "https", c.host == "api-hddt.minvoice.com.vn",
                  c.port == nil || c.port == 443,
                  c.user == nil, c.password == nil, c.query == nil, c.fragment == nil,
                  c.percentEncodedPath == "/api/app/" else { throw ConstructionError.invalidAPI }
            for value in [userAgent, cookie, verificationToken] {
                guard !value.isEmpty, !value.unicodeScalars.contains(where: { $0.value < 0x20 || $0.value == 0x7f })
                else { throw ConstructionError.invalidHeader }
            }
            self.api = api
            self.userAgent = userAgent
            self.cookie = cookie
            self.verificationToken = verificationToken
        }
    }

    struct SignedXML {
        let id: UUID
        let xml: String
    }

    /// CIL 0x0600007a: invoice/{id}/detail through RestInvoiceClient.GetAsync.
    static func invoiceInfo(session: Session, id: UUID) -> URLRequest {
        request(session: session, path: "invoice/\(id.uuidString.lowercased())/detail", method: "GET")
    }

    /// CIL 0x060003dc → 0x06000074 → 0x06000094: JSON array of GUIDs,
    /// not RequestSignInvoiceModel. The response is a ZIP, not an XML string.
    static func downloadXML(session: Session, ids: [UUID], requestID: UUID = UUID(), cash: Bool = false) throws -> URLRequest {
        try validate(ids)
        var r = request(session: session, path: cash ? "release-invoice/download-xml-invoice-cash" : "release-invoice/download-xml", method: "POST")
        r.setValue(requestID.uuidString.lowercased(), forHTTPHeaderField: "x_req_id")
        r.setValue("application/json; charset=utf-8", forHTTPHeaderField: "Content-Type")
        r.httpBody = try JSONEncoder().encode(ids.map { $0.uuidString.lowercased() })
        return r
    }

    /// CIL 0x0600041b: Guid.Empty in the URL even for a batch of named invoices.
    /// This only constructs bytes; it cannot upload or issue an invoice.
    static func uploadXML(session: Session, invoices: [SignedXML], boundary: String = UUID().uuidString.replacingOccurrences(of: "-", with: "").lowercased()) throws -> URLRequest {
        try validate(invoices.map(\.id))
        guard boundary.utf8.count == 32, boundary.utf8.allSatisfy({ (48...57).contains($0) || (97...102).contains($0) })
        else { throw ConstructionError.invalidBoundary }
        var body = ""
        for invoice in invoices {
            guard !invoice.xml.contains("\r\n--\(boundary)") else { throw ConstructionError.boundaryCollision }
            body += "--\(boundary)\r\nContent-Disposition: form-data; name=\"files\"; filename=\"\(invoice.id.uuidString.lowercased()).xml\"\r\nContent-Type: text/xml\r\n\r\n\(invoice.xml)\r\n"
        }
        body += "--\(boundary)--\r\n"
        var r = request(session: session, path: "release-invoice/00000000-0000-0000-0000-000000000000/upload-xml", method: "POST")
        r.setValue("multipart/form-data; boundary=\(boundary)", forHTTPHeaderField: "Content-Type")
        r.httpBody = Data(body.utf8)
        return r
    }

    private static func validate(_ ids: [UUID]) throws {
        guard !ids.isEmpty else { throw ConstructionError.emptyInvoices }
        guard Set(ids).count == ids.count else { throw ConstructionError.duplicateInvoice }
    }

    static func request(session: Session, path: String, method: String) -> URLRequest {
        var r = URLRequest(url: session.api.appendingPathComponent(path))
        r.httpMethod = method
        r.httpShouldHandleCookies = false
        r.timeoutInterval = 60
        r.setValue(session.userAgent, forHTTPHeaderField: "User-Agent")
        r.setValue(session.cookie, forHTTPHeaderField: "Cookie")
        r.setValue(session.verificationToken, forHTTPHeaderField: "RequestVerificationToken")
        return r
    }
}
