import Foundation
import Core

public typealias MinvoiceOperation = @Sendable (CertInfo, MinvoiceSign) async throws -> Void

public protocol MinvoiceSigningBackend: Sendable {
    func certificates() async -> [CertInfo]
    func selectCertificate(origin: String, serial: String?) async throws -> CertInfo
    /// Hold the app's signing lock and obtain user consent before REST login.
    /// The signer asks for the PIN and signs exactly the supplied SignedInfo.
    func withApproval(origin: String, serial: String, operation: @escaping MinvoiceOperation) async throws
    func withApproval(origin: String, serial: String, invoiceCount: Int, operation: @escaping MinvoiceOperation) async throws
    func batchProgress(_ progress: MinvoiceBatchProgress) async
}

public extension MinvoiceSigningBackend {
    func withApproval(origin: String, serial: String, invoiceCount: Int, operation: @escaping MinvoiceOperation) async throws {
        try await withApproval(origin: origin, serial: serial, operation: operation)
    }
    func batchProgress(_ progress: MinvoiceBatchProgress) async {}

    /// Noninteractive backends must never silently pick among multiple certificates.
    func selectCertificate(origin: String, serial: String?) async throws -> CertInfo {
        let certs = await certificates()
        let matches = certs.filter { cert in
            guard let serial, !serial.isEmpty else { return true }
            return cert.serialHex.caseInsensitiveCompare(serial) == .orderedSame
        }
        guard matches.count == 1, let cert = matches.first else { throw SigningTargetError.ambiguousCertificate }
        return cert
    }
}

public actor MinvoiceInvoices {
    private let backend: any MinvoiceSigningBackend
    private let http: any MinvoiceHTTPTransport
    private var busy = false
    private let groupDelay: Duration
    public init(backend: any MinvoiceSigningBackend, http: any MinvoiceHTTPTransport = MinvoiceURLSession(), groupDelay: Duration = .milliseconds(800)) {
        self.backend = backend; self.http = http; self.groupDelay = groupDelay
    }

    struct Command: Decodable { let CommandName: String; let InvoiceIdArray: [UUID]; let SerialNumber: String? }
    struct Envelope: Decodable { let BrowserInfo: MinvoiceBrowserInfo; let PlugCommand: Command }

    @discardableResult
    func sign(_ text: String, origin: String) async throws -> MinvoiceBatchProgress {
        guard !busy else { throw MinvoiceError.busy }
        busy = true; defer { busy = false }
        guard text.utf8.count <= MinvoiceBatchLimits.commandBytes, let data = text.data(using: .utf8),
              let envelope = try? JSONDecoder().decode(Envelope.self, from: data),
              envelope.PlugCommand.CommandName == "SignInvoices",
              OriginAllowlist(patterns: ["*.minvoice.com.vn", "*.minvoice.vn", "*.minvoice.net"]).contains(origin)
        else { throw MinvoiceError.invalidInput }
        let ids = envelope.PlugCommand.InvoiceIdArray
        guard (1...MinvoiceBatchLimits.maxInvoices).contains(ids.count), Set(ids).count == ids.count,
              !ids.contains(UUID(uuidString: "00000000-0000-0000-0000-000000000000")!) else { throw MinvoiceError.invalidInput }
        try envelope.BrowserInfo.validate()
        // Profile is unknown until invoice details are read after approval:
        // start with cash groups, regroup for ordinary HDon before any download.
        @Sendable func chunk(_ size: Int) -> [[UUID]] {
            stride(from: 0, to: ids.count, by: size).map { Array(ids[$0..<min($0 + size, ids.count)]) }
        }
        let http = self.http, delay = groupDelay
        let tracker = MinvoiceBatchTracker(counts: chunk(MinvoiceBatchLimits.cashGroupSize).map(\.count), backend: backend)
        do {
            try await backend.withApproval(origin: origin, serial: envelope.PlugCommand.SerialNumber ?? "", invoiceCount: ids.count) { cert, sign in
                try Task.checkCancellation()
                await tracker.update()
                try MinvoiceCashXML.validateCertificate(cert)
                let session = try await MinvoiceLogin.session(info: envelope.BrowserInfo, http: http)
                func json(_ request: URLRequest) async throws -> [String: Any] {
                    try Task.checkCancellation()
                    let response = try await http.sendDiagnosed(request)
                    guard response.status == 200 else { throw MinvoiceHTTPFailure(request: request, reason: .status, status: response.status) }
                    guard let object = try? JSONSerialization.jsonObject(with: response.body) as? [String: Any] else { throw MinvoiceHTTPFailure(request: request, reason: .json) }
                    return object
                }
                let tenant = try await json(MinvoiceRESTRequests.request(session: session, path: "tenant-company/current-tenant", method: "GET"))
                guard let time = tenant["currentDateTime"] as? String, MinvoiceCashXML.validTime(time) else {
                    throw MinvoiceHTTPFailure(request: MinvoiceRESTRequests.request(session: session, path: "tenant-company/current-tenant", method: "GET"), reason: .shape)
                }
                var tokenRequest = MinvoiceRESTRequests.request(session: session, path: "token/by-serial-number", method: "GET")
                var tokenURL = URLComponents(url: tokenRequest.url!, resolvingAgainstBaseURL: false)!
                tokenURL.queryItems = [URLQueryItem(name: "serialNumber", value: cert.serialHex)]
                tokenRequest.url = tokenURL.url
                let token = try await json(tokenRequest)
                guard let serial = token["serialNumber"] as? String,
                      serial.caseInsensitiveCompare(cert.serialHex) == .orderedSame else { throw MinvoiceHTTPFailure(request: tokenRequest, reason: .shape) }
                // Validate EVERY requested invoice before the first upload. The
                // Windows first-detail shortcut does not prove a homogeneous batch.
                var expectedSerial: String?
                var profile = MinvoiceXMLProfile.cash
                for (index, id) in ids.enumerated() {
                    let detail = try await json(MinvoiceRESTRequests.invoiceInfo(session: session, id: id))
                    guard let invoiceSerial = detail["invoiceSerial"] as? String,
                          let kind = MinvoiceXMLProfile.forSeries(invoiceSerial) else { throw MinvoiceError.unsupported }
                    profile = kind
                    if let expectedSerial {
                        guard invoiceSerial.caseInsensitiveCompare(expectedSerial) == .orderedSame else { throw MinvoiceError.unsupported }
                    } else { expectedSerial = invoiceSerial }
                    await tracker.update(checked: index + 1)
                }
                let groups = chunk(profile == .cash ? MinvoiceBatchLimits.cashGroupSize : MinvoiceBatchLimits.ordinaryGroupSize)
                if profile == .ordinary { await tracker.regroup(groups.map(\.count)) }
                for (index, group) in groups.enumerated() {
                    try Task.checkCancellation()
                    await tracker.update(index, state: .downloading)
                    let download = try MinvoiceRESTRequests.downloadXML(session: session, ids: group, cash: profile == .cash)
                    let archive = try await http.sendDiagnosed(download)
                    guard archive.status == 200 else { throw MinvoiceHTTPFailure(request: download, reason: .status, status: archive.status) }
                    let entries = try MinvoiceZIP.extractAll(archive.body)
                    // Installed 1.0.3.0 has no BKe placement; extra/missing entries
                    // (backend-generated bảng kê) are refused before signing.
                    guard profile == .cash || Set(entries.map(\.id)) == Set(group) else { throw MinvoiceError.unsupported }
                    await tracker.update(index, state: .signing, documents: entries.count)
                    var documents: [MinvoiceRESTRequests.SignedXML] = []
                    for (documentIndex, entry) in entries.enumerated() {
                        try Task.checkCancellation()
                        let signed = try await MinvoiceCashXML.sign(xml: entry.xml, id: entry.id, signingTime: time, certificate: cert, profile: profile, signer: sign)
                        try Task.checkCancellation()
                        try MinvoiceCashXML.verify(xml: signed, id: entry.id, certificate: cert, profile: profile)
                        documents.append(.init(id: entry.id, xml: String(decoding: signed, as: UTF8.self)))
                        await tracker.update(index, signed: documentIndex + 1)
                    }
                    let request = try MinvoiceRESTRequests.uploadXML(session: session, invoices: documents)
                    guard (request.httpBody?.count ?? 0) <= MinvoiceBatchLimits.uploadBytes else { throw MinvoiceError.invalidInput }
                    try Task.checkCancellation()
                    await tracker.update(index, state: .uploading)
                    // One attempt. Once upload starts, any missing/invalid ACK is
                    // uncertain; never retry or roll back acknowledged groups.
                    let result: MinvoiceHTTPResponse
                    do { result = try await http.sendDiagnosed(request) }
                    catch let error as MinvoiceHTTPFailure { throw error }
                    catch { throw MinvoiceError.uploadUncertain }
                    guard result.status == 204, result.body.isEmpty else { throw MinvoiceHTTPFailure(request: request, reason: .ack, status: result.status) }
                    await tracker.update(index, state: .acknowledged)
                    if index + 1 < groups.count { try await Task.sleep(for: delay) }
                }
            }
            await tracker.update(outcome: .completed)
            return await tracker.progress
        } catch { throw await tracker.failed(error) }
    }
}
