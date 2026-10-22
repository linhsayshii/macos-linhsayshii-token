import Foundation
import Core

public typealias MinvoiceOperation = @Sendable (CertInfo, MinvoiceSign) async throws -> Void

public protocol MinvoiceSigningBackend: Sendable {
    func certificates() async -> [CertInfo]
    /// Hold the app's signing lock and obtain user consent before REST login.
    /// The signer asks for the PIN and signs exactly the supplied SignedInfo.
    func withApproval(origin: String, serial: String, operation: @escaping MinvoiceOperation) async throws
}

public actor MinvoiceInvoices {
    private let backend: any MinvoiceSigningBackend
    private let http: any MinvoiceHTTPTransport
    private var busy = false
    public init(backend: any MinvoiceSigningBackend, http: any MinvoiceHTTPTransport = MinvoiceURLSession()) {
        self.backend = backend; self.http = http
    }

    struct Command: Decodable { let CommandName: String; let InvoiceIdArray: [UUID]; let SerialNumber: String }
    struct Envelope: Decodable { let BrowserInfo: MinvoiceBrowserInfo; let PlugCommand: Command }

    func sign(_ text: String, origin: String) async throws {
        guard !busy else { throw MinvoiceError.busy }
        busy = true; defer { busy = false }
        guard text.utf8.count <= 65536, let data = text.data(using: .utf8),
              let envelope = try? JSONDecoder().decode(Envelope.self, from: data),
              envelope.PlugCommand.CommandName == "SignInvoices",
              !envelope.PlugCommand.SerialNumber.isEmpty,
              OriginAllowlist(patterns: ["*.minvoice.com.vn", "*.minvoice.vn", "*.minvoice.net"]).contains(origin)
        else { throw MinvoiceError.invalidInput }
        guard envelope.PlugCommand.InvoiceIdArray.count == 1 else { throw MinvoiceError.unsupported }
        try envelope.BrowserInfo.validate()
        let id = envelope.PlugCommand.InvoiceIdArray[0], http = self.http
        try await backend.withApproval(origin: origin, serial: envelope.PlugCommand.SerialNumber) { cert, sign in
            try MinvoiceCashXML.validateCertificate(cert)
            let session = try await MinvoiceLogin.session(info: envelope.BrowserInfo, http: http)
            func json(_ request: URLRequest) async throws -> [String: Any] {
                let response = try await http.send(request)
                guard response.status == 200 else { throw MinvoiceError.server(response.status) }
                guard let object = try? JSONSerialization.jsonObject(with: response.body) as? [String: Any] else { throw MinvoiceError.invalidInput }
                return object
            }
            let tenant = try await json(MinvoiceRESTRequests.request(session: session, path: "tenant-company/current-tenant", method: "GET"))
            guard let time = tenant["currentDateTime"] as? String, MinvoiceCashXML.validTime(time) else { throw MinvoiceError.invalidInput }
            var tokenRequest = MinvoiceRESTRequests.request(session: session, path: "token/by-serial-number", method: "GET")
            var tokenURL = URLComponents(url: tokenRequest.url!, resolvingAgainstBaseURL: false)!
            tokenURL.queryItems = [URLQueryItem(name: "serialNumber", value: cert.serialHex)]
            tokenRequest.url = tokenURL.url
            let token = try await json(tokenRequest)
            guard let serial = token["serialNumber"] as? String,
                  serial.caseInsensitiveCompare(cert.serialHex) == .orderedSame else { throw MinvoiceError.invalidInput }
            let detail = try await json(MinvoiceRESTRequests.invoiceInfo(session: session, id: id))
            // Installed 1.0.3.0 IsInvoiceCash: length >=7, Substring(4,1) == M,
            // case-insensitive (CIL 06000285 -> 06000287 -> 06000288).
            guard let invoiceSerial = detail["invoiceSerial"] as? String,
                  invoiceSerial.utf8.count >= 7, invoiceSerial.utf8.allSatisfy({ $0 < 128 }),
                  Array(invoiceSerial.uppercased().utf8)[4] == 77 else { throw MinvoiceError.unsupported }
            let archive = try await http.send(MinvoiceRESTRequests.downloadXML(session: session, ids: [id], cash: true))
            guard archive.status == 200 else { throw MinvoiceError.server(archive.status) }
            let entry = try MinvoiceZIP.extract(archive.body)
            let signed = try await MinvoiceCashXML.sign(xml: entry.xml, id: entry.id, signingTime: time, certificate: cert, signer: sign)
            try Task.checkCancellation()
            try MinvoiceCashXML.verify(xml: signed, id: entry.id, certificate: cert)
            let request = try MinvoiceRESTRequests.uploadXML(session: session, invoices: [.init(id: entry.id, xml: String(decoding: signed, as: UTF8.self))])
            // Exactly one attempt. A timeout is an uncertain business outcome,
            // never a reason to issue the upload again automatically.
            let result: MinvoiceHTTPResponse
            do { result = try await http.send(request) }
            catch { throw MinvoiceError.uploadUncertain }
            guard result.status == 204, result.body.isEmpty else { throw MinvoiceError.server(result.status) }
        }
    }
}
