import Foundation
import Darwin
import Testing
import Security
import X509
import SwiftASN1
import Core
@testable import Bridges

private let invoiceID = UUID(uuidString: "12345678-90ab-cdef-1234-567890abcdef")!
private let miOrigin = "https://hddt.minvoice.com.vn"
private let unsignedCash = Data("<?xml version=\"1.0\" encoding=\"UTF-8\"?><TDiep><DLieu Id=\"12345678-90ab-cdef-1234-567890abcdef\"><Ten>Hóa đơn thử</Ten></DLieu><CKSNNT/></TDiep>".utf8)

private struct TestIdentity: @unchecked Sendable {
    let key: SecKey
    let cert: CertInfo
    init(expired: Bool = false) throws {
        key = try #require(SecKeyCreateRandomKey([kSecAttrKeyType: kSecAttrKeyTypeRSA,
            kSecAttrKeySizeInBits: 2048, kSecAttrIsPermanent: false] as CFDictionary, nil))
        let privateKey = try Certificate.PrivateKey(key)
        let name = try DistinguishedName { CommonName("TokenSigner fixture") }
        let cert = try Certificate(version: .v3, serialNumber: Certificate.SerialNumber(), publicKey: privateKey.publicKey,
            notValidBefore: Date().addingTimeInterval(-3600), notValidAfter: Date().addingTimeInterval(expired ? -60 : 3600),
            issuer: name, subject: name, signatureAlgorithm: .sha256WithRSAEncryption,
            extensions: Certificate.Extensions {}, issuerPrivateKey: privateKey)
        var serializer = DER.Serializer(); try serializer.serialize(cert)
        self.cert = CertInfo(id: "test-key-id", derB64: Data(serializer.serializedBytes).base64EncodedString(),
            subject: "CN=TokenSigner fixture", issuer: "CN=TokenSigner fixture", serialHex: "AABBCC", notBefore: "2026-10-22 00:00:00", notAfter: "2026-10-24 00:00:00")
    }
    func sign(_ data: Data) throws -> Data {
        try #require(SecKeyCreateSignature(key, .rsaSignatureMessagePKCS1v15SHA256, data as CFData, nil)) as Data
    }
}

private actor Events {
    var values: [String] = []
    func note(_ value: String) { values.append(value) }
}
private struct FixtureBackend: MinvoiceSigningBackend {
    let identity: TestIdentity
    let events: Events
    var denied = false
    var badSignature = false
    func certificates() async -> [CertInfo] { [identity.cert] }
    func withApproval(origin: String, serial: String, operation: @escaping MinvoiceOperation) async throws {
        guard serial == identity.cert.serialHex else { throw MinvoiceError.invalidInput }
        try MinvoiceCashXML.validateCertificate(identity.cert)
        await events.note("approval")
        if denied { throw MinvoiceError.cancelled }
        try await operation(identity.cert) { message in
            await events.note("pin/sign")
            return badSignature ? Data(repeating: 0, count: 256) : try identity.sign(message)
        }
    }
}
private actor FixtureHTTP: MinvoiceHTTPTransport {
    var requests: [URLRequest] = []
    let events: Events
    let archive: Data
    var status: Int
    var ordinary: Bool
    var fault: String?
    init(events: Events, archive: Data, status: Int = 204, ordinary: Bool = false, fault: String? = nil) {
        self.events = events; self.archive = archive; self.status = status; self.ordinary = ordinary; self.fault = fault
    }
    func send(_ request: URLRequest) async throws -> MinvoiceHTTPResponse {
        try Task.checkCancellation()
        requests.append(request)
        let path = request.url!.path
        await events.note(path)
        let diagnosticStep = ["diag-login": "/api/account/login", "diag-configuration": "/api/abp/application-configuration",
            "diag-tenant": "/api/app/tenant-company/current-tenant", "diag-token": "/api/app/token/by-serial-number",
            "diag-detail": "/api/app/invoice/\(invoiceID.uuidString.lowercased())/detail"]
        if let fault, path == diagnosticStep[fault] {
            throw NSError(domain: NSURLErrorDomain, code: -1009, userInfo: [NSLocalizedDescriptionKey: "PRIVATE_NEVER_EMIT", NSURLErrorFailingURLErrorKey: request.url!])
        }
        if fault == "login", path == "/api/account/login" { return .init(status: 401) }
        if fault == "no-xsrf", path == "/api/abp/application-configuration" { return .init(status: 200) }
        if fault == "upload-timeout", path.hasSuffix("/upload-xml") { throw MinvoiceError.transport }
        if fault == "upload-cancel", path.hasSuffix("/upload-xml") { throw CancellationError() }
        switch path {
        case "/api/account/login": return .init(status: 200, headers: ["Set-Cookie": ".AspNetCore.Identity.Application=fixture-auth; Path=/; Secure; HttpOnly"])
        case "/api/abp/application-configuration": return .init(status: 200, headers: ["Set-Cookie": "XSRF-TOKEN=fixture-xsrf; Path=/; Secure"])
        case "/api/app/tenant-company/current-tenant": return .init(status: 200, body: Data(#"{"currentDateTime":"2026-10-23T00:24:49"}"#.utf8))
        case "/api/app/token/by-serial-number": return .init(status: 200, body: Data(#"{"serialNumber":"AABBCC","used":true}"#.utf8))
        case "/api/app/invoice/\(invoiceID.uuidString.lowercased())/detail":
            return .init(status: 200, body: Data((ordinary ? #"{"invoiceSerial":"1C26TXX"}"# : #"{"invoiceSerial":"1C26MXX"}"#).utf8))
        case "/api/app/release-invoice/download-xml-invoice-cash": return .init(status: 200, body: archive)
        case "/api/app/release-invoice/00000000-0000-0000-0000-000000000000/upload-xml": return .init(status: status)
        default: throw MinvoiceError.invalidInput
        }
    }
}

private func zipFixture(_ xml: Data = unsignedCash, multiple: Bool = false, name: String = invoiceID.uuidString.lowercased() + ".xml") throws -> Data {
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent("minvoice-fixture-\(UUID())")
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: false)
    defer { try? FileManager.default.removeItem(at: dir) }
    let file = dir.appendingPathComponent(name)
    try xml.write(to: file)
    let process = Process(); process.executableURL = URL(fileURLWithPath: "/usr/bin/zip")
    let archive = dir.appendingPathComponent("fixture.zip")
    process.arguments = ["-q", "-j", archive.path, file.path]
    if multiple {
        let other = dir.appendingPathComponent("other.xml"); try xml.write(to: other)
        process.arguments!.append(other.path)
    }
    process.standardOutput = FileHandle.nullDevice; process.standardError = FileHandle.nullDevice
    try process.run(); process.waitUntilExit()
    #expect(process.terminationStatus == 0)
    return try Data(contentsOf: archive)
}
private func command(serial: String = "AABBCC", ids: [UUID] = [invoiceID], api: String = "https://api-hddt.minvoice.com.vn/api/app/") throws -> String {
    let object: [String: Any] = ["BrowserInfo": ["Cookie": "__tenant=fixture-tenant; browser-session=must-not-forward", "UserAgent": "Fixture", "UserName": "fixture-user", "Pass": "fixture-password", "LinkApi": api],
        "PlugCommand": ["CommandName": "SignInvoices", "InvoiceIdArray": ids.map(\.uuidString), "SerialNumber": serial]]
    return String(decoding: try JSONSerialization.data(withJSONObject: object), as: UTF8.self)
}
private func object(_ text: String) throws -> [String: Any] { try JSONSerialization.jsonObject(with: Data(text.utf8)) as! [String: Any] }

@Test func minvoiceCashEndToEndOffline() async throws {
    let identity = try TestIdentity(), events = Events()
    let http = FixtureHTTP(events: events, archive: try zipFixture())
    let bridge = MinvoiceBridge(backend: FixtureBackend(identity: identity, events: events), http: http)
    let result = try object(await bridge.dispatch(command(), origin: miOrigin))
    #expect(result["code"] as? Int == 1)
    let data = try #require(result["data"] as? [String: Any])
    #expect(data["status"] as? Bool == true && data["command"] as? String == "SignInvoices")
    let requests = await http.requests
    try #require(requests.count == 7)
    let login = try JSONSerialization.jsonObject(with: #require(requests.first?.httpBody)) as! [String: Any]
    #expect(Set(login.keys) == ["UserNameOrEmailAddress", "Password", "RememberMe"])
    #expect(requests[0].value(forHTTPHeaderField: "Cookie") == "__tenant=fixture-tenant")
    #expect(requests[2].value(forHTTPHeaderField: "Cookie")?.contains("browser-session") == false)
    #expect(requests[2].value(forHTTPHeaderField: "Cookie")?.contains("HttpOnly") == false)
    #expect(requests[2].value(forHTTPHeaderField: "RequestVerificationToken") == "fixture-xsrf")
    #expect(requests[6].value(forHTTPHeaderField: "Authorization") == nil)
    #expect(String(decoding: requests[6].httpBody!, as: UTF8.self).contains("name=\"files\"; filename=\"\(invoiceID.uuidString.lowercased()).xml\""))
    let sequence = await events.values
    #expect(sequence.first == "approval")
    #expect(sequence.firstIndex(of: "pin/sign")! < sequence.count - 1)
}

@Test func minvoiceNeverUploadsDeniedBadSignatureOrOrdinary() async throws {
    let identity = try TestIdentity()
    for mode in ["deny", "bad-signature", "ordinary", "wrong-serial", "expired"] {
        let events = Events()
        let backend = FixtureBackend(identity: mode == "expired" ? try TestIdentity(expired: true) : identity,
            events: events, denied: mode == "deny", badSignature: mode == "bad-signature")
        let http = FixtureHTTP(events: events, archive: try zipFixture(), ordinary: mode == "ordinary")
        let bridge = MinvoiceBridge(backend: backend, http: http)
        let result = try object(await bridge.dispatch(command(serial: mode == "wrong-serial" ? "UNKNOWN" : "AABBCC"), origin: miOrigin))
        #expect(result["code"] as? Int != 1)
        let requests = await http.requests
        #expect(!requests.contains { $0.url!.path.hasSuffix("/upload-xml") })
        if ["deny", "expired", "wrong-serial"].contains(mode) { #expect(requests.isEmpty) }
    }
}

@Test func minvoiceRejectsInvalidBatchAndCredentialEgressBeforeApproval() async throws {
    let events = Events(), identity = try TestIdentity()
    let http = FixtureHTTP(events: events, archive: Data())
    let bridge = MinvoiceBridge(backend: FixtureBackend(identity: identity, events: events), http: http)
    for request in [try command(ids: []), try command(ids: [invoiceID, invoiceID]),
                    try command(ids: (0...MinvoiceBatchLimits.maxInvoices).map { _ in UUID() }),
                    try command(ids: [UUID(uuidString: "00000000-0000-0000-0000-000000000000")!]), try command(api: "https://evil.invalid/api/app/")] {
        #expect(try object(await bridge.dispatch(request, origin: miOrigin))["code"] as? Int != 1)
    }
    #expect(try object(await bridge.dispatch(command(), origin: "https://evil.invalid"))["code"] as? Int != 1)
    #expect(await http.requests.isEmpty)
    #expect(await events.values.isEmpty)
}

@Test func minvoiceUploadFailureHasNoRetryOrFalseSuccess() async throws {
    let events = Events(), identity = try TestIdentity()
    let http = FixtureHTTP(events: events, archive: try zipFixture(), status: 500)
    let bridge = MinvoiceBridge(backend: FixtureBackend(identity: identity, events: events), http: http)
    #expect(try object(await bridge.dispatch(command(), origin: miOrigin))["code"] as? Int != 1)
    #expect(await http.requests.filter { $0.url!.path.hasSuffix("/upload-xml") }.count == 1)
}

@Test func minvoiceZIPRejectsMultipleMismatchedCorruptAndOversized() throws {
    let good = try zipFixture()
    #expect(try MinvoiceZIP.extract(good).xml == unsignedCash)
    #expect(throws: MinvoiceError.self) { try MinvoiceZIP.extract(zipFixture(multiple: true)) }
    #expect(throws: MinvoiceError.self) { try MinvoiceZIP.extract(zipFixture(name: "unexpected.xml")) }
    var corrupt = good; corrupt[45] ^= 0xff
    #expect(throws: MinvoiceError.self) { try MinvoiceZIP.extract(corrupt) }
    #expect(throws: MinvoiceError.self) { try MinvoiceZIP.extract(Data(repeating: 0, count: (2 << 20)+1)) }
}

@Test func minvoiceCashProfileAndTampering() async throws {
    let identity = try TestIdentity()
    let signed = try await MinvoiceCashXML.sign(xml: unsignedCash, id: invoiceID, signingTime: "2026-10-23T00:24:49", certificate: identity.cert, signer: identity.sign)
    try MinvoiceCashXML.verify(xml: signed, id: invoiceID, certificate: identity.cert)
    let doc = try XMLDocument(data: signed)
    #expect(try doc.nodes(forXPath: "/TDiep/CKSNNT/*[local-name()='Signature']").count == 1)
    #expect(try doc.nodes(forXPath: "//*[local-name()='RSAKeyValue']").isEmpty)
    let timeNodes = try doc.nodes(forXPath: "//*[local-name()='SignatureProperties' or local-name()='SignatureProperty' or local-name()='SigningTime']")
    #expect(timeNodes.count == 3 && timeNodes.allSatisfy { ($0.uri ?? "").isEmpty })
    for pair in [("Hóa đơn thử", "Đã sửa"), ("2026-10-23T00:24:49", "2026-10-23T00:24:50")] {
        let tampered = Data(String(decoding: signed, as: UTF8.self).replacingOccurrences(of: pair.0, with: pair.1).utf8)
        #expect(throws: MinvoiceError.self) { try MinvoiceCashXML.verify(xml: tampered, id: invoiceID, certificate: identity.cert) }
    }
    #expect(throws: MinvoiceError.self) { try MinvoiceCashXML.verify(xml: signed, id: invoiceID, certificate: TestIdentity().cert) }
}

@Test(.enabled(if: FileManager.default.isExecutableFile(atPath: "/opt/homebrew/bin/xmlsec1")))
func minvoiceCashIndependentXMLSecVerification() async throws {
    let identity = try TestIdentity()
    let signed = try await MinvoiceCashXML.sign(xml: unsignedCash, id: invoiceID, signingTime: "2026-10-23T00:24:49", certificate: identity.cert, signer: identity.sign)
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent("minvoice-xmlsec-\(UUID())")
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: false)
    defer { try? FileManager.default.removeItem(at: dir) }
    let file = dir.appendingPathComponent("signed.xml"), cert = dir.appendingPathComponent("cert.der")
    try Data(base64Encoded: identity.cert.derB64)!.write(to: cert)
    func verify(_ xml: Data) throws -> Int32 {
        try xml.write(to: file)
        let process = Process(); process.executableURL = URL(fileURLWithPath: "/opt/homebrew/bin/xmlsec1")
        process.arguments = ["--verify", "--lax-key-search", "--pubkey-cert-der", cert.path,
            "--enabled-reference-uris", "same-doc", "--id-attr:Id", "DLieu", "--id-attr:Id", "Object", file.path]
        process.standardOutput = FileHandle.nullDevice; process.standardError = FileHandle.nullDevice
        try process.run(); process.waitUntilExit(); return process.terminationStatus
    }
    #expect(try verify(signed) == 0)
    #expect(try verify(Data(String(decoding: signed, as: UTF8.self).replacingOccurrences(of: "Hóa đơn thử", with: "Tampered").utf8)) != 0)
}

private actor WaitingBackend: MinvoiceSigningBackend {
    let cert: CertInfo
    var started = false
    var cancelled = false
    init(cert: CertInfo) { self.cert = cert }
    func certificates() async -> [CertInfo] { [cert] }
    func withApproval(origin: String, serial: String, operation: @escaping MinvoiceOperation) async throws {
        started = true
        do { try await Task.sleep(for: .seconds(30)) }
        catch { cancelled = true; throw error }
        throw MinvoiceError.cancelled
    }
}

@Test func minvoiceBusyAndSignalRAbortCancelPendingApproval() async throws {
    let identity = try TestIdentity(), events = Events()
    let backend = WaitingBackend(cert: identity.cert)
    let http = FixtureHTTP(events: events, archive: Data())
    let bridge = MinvoiceBridge(backend: backend, http: http)
    let hub = SignalRHub(handler: bridge.handler)
    let negotiated = try object(await hub.negotiate(origin: miOrigin))
    let token = try #require(negotiated["ConnectionToken"] as? String)
    let invocation = SignalRHub.json(["H": "handlerHub", "M": "processMessage", "A": [try command()], "I": "one"])
    let ack = try object(try #require(await hub.receive(token: token, data: invocation)))
    #expect(ack["I"] as? String == "one")
    for _ in 0..<100 {
        if await backend.started { break }
        try await Task.sleep(for: .milliseconds(10))
    }
    try #require(await backend.started)
    #expect(try object(await bridge.dispatch(command(), origin: miOrigin))["code"] as? Int != 1)
    await hub.abort(token)
    for _ in 0..<100 {
        if await backend.cancelled { break }
        try await Task.sleep(for: .milliseconds(10))
    }
    #expect(await backend.cancelled)
    #expect(await http.requests.isEmpty)
    #expect(await hub.isKnown(token) == false)
}

@Test func minvoiceRejectsUnsafeXMLBeforeRequestingPIN() async throws {
    let identity = try TestIdentity(), events = Events()
    let duplicate = Data(String(decoding: unsignedCash, as: UTF8.self).replacingOccurrences(of: "<CKSNNT/>", with: "<CKSNNT/><Other Id=\"\(invoiceID.uuidString.lowercased())\"/>").utf8)
    let doctype = Data("<!DOCTYPE TDiep SYSTEM 'file:///etc/passwd'><TDiep/>".utf8)
    for bytes in [duplicate, doctype, Data("<HDon/>".utf8)] {
        await #expect(throws: MinvoiceError.self) {
            try await MinvoiceCashXML.sign(xml: bytes, id: invoiceID, signingTime: "2026-10-23T00:24:49", certificate: identity.cert) { message in
                await events.note("unexpected-sign")
                return try identity.sign(message)
            }
        }
    }
    #expect(await events.values.isEmpty)
}

@Test func minvoiceSignsServerEntryGUIDRatherThanAssumingRequestedInvoiceID() async throws {
    let generated = UUID()
    let xml = Data(String(decoding: unsignedCash, as: UTF8.self).replacingOccurrences(of: invoiceID.uuidString.lowercased(), with: generated.uuidString.lowercased()).utf8)
    let events = Events(), identity = try TestIdentity()
    let http = FixtureHTTP(events: events, archive: try zipFixture(xml, name: generated.uuidString.lowercased() + ".xml"))
    let bridge = MinvoiceBridge(backend: FixtureBackend(identity: identity, events: events), http: http)
    #expect(try object(await bridge.dispatch(command(), origin: miOrigin))["code"] as? Int == 1)
    let last = try #require(await http.requests.last)
    #expect(String(decoding: last.httpBody!, as: UTF8.self).contains("filename=\"\(generated.uuidString.lowercased()).xml\""))
}

@Test func minvoiceAuthFailureAndUncertainUploadAreNotRetried() async throws {
    let identity = try TestIdentity()
    for fault in ["login", "no-xsrf", "upload-timeout", "upload-cancel"] {
        let events = Events()
        let http = FixtureHTTP(events: events, archive: try zipFixture(), fault: fault)
        let bridge = MinvoiceBridge(backend: FixtureBackend(identity: identity, events: events), http: http)
        let result = try object(await bridge.dispatch(command(), origin: miOrigin))
        #expect(result["code"] as? Int != 1)
        let uploads = await http.requests.filter { $0.url!.path.hasSuffix("/upload-xml") }
        #expect(uploads.count == (fault.hasPrefix("upload-") ? 1 : 0))
        if fault.hasPrefix("upload-") { #expect((result["message"] as? String)?.contains("trạng thái upload") == true) }
        else { #expect(await events.values.contains("pin/sign") == false) }
    }
}

private func bulkZIP(_ entries: [(UUID, Data)]) throws -> Data {
    let dir = FileManager.default.temporaryDirectory.appendingPathComponent("minvoice-bulk-fixture-\(UUID())")
    try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: false)
    defer { try? FileManager.default.removeItem(at: dir) }
    for (id, data) in entries { try data.write(to: dir.appendingPathComponent(id.uuidString.lowercased() + ".xml")) }
    let process = Process(); process.executableURL = URL(fileURLWithPath: "/usr/bin/zip")
    process.arguments = ["-q", "-j", dir.appendingPathComponent("fixture.zip").path] + entries.map { dir.appendingPathComponent($0.0.uuidString.lowercased() + ".xml").path }
    process.standardOutput = FileHandle.nullDevice; process.standardError = FileHandle.nullDevice
    try process.run(); process.waitUntilExit()
    try #require(process.terminationStatus == 0)
    return try Data(contentsOf: dir.appendingPathComponent("fixture.zip"))
}

private actor BulkBackend: MinvoiceSigningBackend {
    let identity: TestIdentity
    var approvals = 0, invoiceCount = 0, signatures = 0
    var progress: [MinvoiceBatchProgress] = []
    let badSignature: Int?
    let cancelSignature: Int?
    init(identity: TestIdentity, badSignature: Int? = nil, cancelSignature: Int? = nil) { self.identity = identity; self.badSignature = badSignature; self.cancelSignature = cancelSignature }
    func certificates() async -> [CertInfo] { [identity.cert] }
    func withApproval(origin: String, serial: String, operation: @escaping MinvoiceOperation) async throws {
        try await withApproval(origin: origin, serial: serial, invoiceCount: 1, operation: operation)
    }
    func withApproval(origin: String, serial: String, invoiceCount: Int, operation: @escaping MinvoiceOperation) async throws {
        approvals += 1; self.invoiceCount = invoiceCount
        try await operation(identity.cert) { message in try await self.sign(message) }
    }
    func sign(_ message: Data) throws -> Data {
        signatures += 1
        if signatures == cancelSignature { throw CancellationError() }
        return signatures == badSignature ? Data(repeating: 0, count: 256) : try identity.sign(message)
    }
    func batchProgress(_ value: MinvoiceBatchProgress) { progress.append(value) }
}

private actor BulkHTTP: MinvoiceHTTPTransport {
    var requests: [URLRequest] = [], downloads: [[String]] = []
    var events: [String] = []
    var uploads = 0
    let documentsPerGroup: Int
    let payloadRepeats: Int
    let fault: String?
    init(documentsPerGroup: Int = 1, fault: String? = nil, payloadRepeats: Int = 30) { self.documentsPerGroup = documentsPerGroup; self.fault = fault; self.payloadRepeats = payloadRepeats }
    func send(_ request: URLRequest) async throws -> MinvoiceHTTPResponse {
        try Task.checkCancellation()
        requests.append(request)
        let path = request.url!.path
        switch path {
        case "/api/account/login": return .init(status: 200, headers: ["Set-Cookie": ".AspNetCore.Identity.Application=fixture-auth; Path=/; Secure; HttpOnly"])
        case "/api/abp/application-configuration": return .init(status: 200, headers: ["Set-Cookie": "XSRF-TOKEN=fixture-xsrf; Path=/; Secure"])
        case "/api/app/tenant-company/current-tenant": return .init(status: 200, body: Data(#"{"currentDateTime":"2026-10-23T00:24:49"}"#.utf8))
        case "/api/app/token/by-serial-number": return .init(status: 200, body: Data(#"{"serialNumber":"AABBCC"}"#.utf8))
        case _ where path.hasSuffix("/detail"):
            let mixed = fault == "mixed" && requests.filter { $0.url!.path.hasSuffix("/detail") }.count == 2
            return .init(status: 200, body: Data((mixed ? #"{"invoiceSerial":"1C26MYY"}"# : #"{"invoiceSerial":"1C26MXX"}"#).utf8))
        case _ where path.hasSuffix("/download-xml-invoice-cash"):
            let ids = try JSONDecoder().decode([String].self, from: #require(request.httpBody))
            downloads.append(ids); events.append("download\(downloads.count)")
            if fault == "download2" && downloads.count == 2 { throw MinvoiceError.transport }
            var entries: [(UUID, Data)] = []
            for document in 0..<documentsPerGroup {
                let id = UUID() // Entry ID is deliberately unrelated to invoice IDs.
                let rows = ids.enumerated().filter { $0.offset % documentsPerGroup == document }
                    .map { "<HDon><DLHDon><TTChung><SHDon>\($0.offset)</SHDon></TTChung><NDHDon><Text>\(String(repeating: "Hàng hóa thử ", count: payloadRepeats))</Text></NDHDon></DLHDon></HDon>" }.joined()
                let xml = "<TDiep><DLieu Id='\(id.uuidString.lowercased())'>\(rows)</DLieu><CKSNNT/></TDiep>"
                entries.append((id, Data(xml.utf8)))
            }
            return .init(status: 200, body: try bulkZIP(entries))
        case _ where path.hasSuffix("/upload-xml"):
            uploads += 1; events.append("upload\(uploads)")
            if fault == "timeout2" && uploads == 2 { throw MinvoiceError.transport }
            if fault == "cancel-upload2" && uploads == 2 { throw CancellationError() }
            if fault == "cancel-after1" && uploads == 1 { withUnsafeCurrentTask { $0?.cancel() } }
            return .init(status: 204)
        default: throw MinvoiceError.invalidInput
        }
    }
}

private func batchObject(_ response: [String: Any]) throws -> [String: Any] {
    let data = try #require(response["data"] as? [String: Any])
    return try #require(data["batch"] as? [String: Any])
}

@Test(arguments: [1, 3, 99, 100, 101, 200, 201, 300, 301])
func minvoiceCashVariableBatchKeepsOrderAndAuthenticatesOnce(count: Int) async throws {
    let identity = try TestIdentity(), ids = (0..<count).map { _ in UUID() }
    let backend = BulkBackend(identity: identity), http = BulkHTTP()
    let bridge = MinvoiceBridge(backend: backend, http: http, groupDelay: .zero)
    let start = ContinuousClock.now
    let response = try object(await bridge.dispatch(command(ids: ids), origin: miOrigin))
    #expect(response["code"] as? Int == 1)
    let result = try batchObject(response), chunks = await http.downloads
    #expect(chunks.flatMap { $0 } == ids.map { $0.uuidString.lowercased() })
    #expect(chunks.map(\.count) == stride(from: 0, to: count, by: 100).map { min(100, count - $0) })
    #expect(await http.events == chunks.indices.flatMap { ["download\($0+1)", "upload\($0+1)"] })
    let approvals = await backend.approvals, invoiceCount = await backend.invoiceCount
    #expect(approvals == 1 && invoiceCount == count)
    #expect(await backend.signatures == chunks.count)
    #expect(result["uploadAcknowledgedInvoices"] as? Int == count)
    #expect(result["signedDocuments"] as? Int == chunks.count)
    #expect(await http.requests.filter { $0.url!.path == "/api/account/login" }.count == 1)
    let progress = try #require(await backend.progress.last)
    #expect(progress.outcome == .completed && progress.acknowledged == count && progress.uncertain == 0)
    if count == 300 { print("Mock 300 aggregate invoices: \(start.duration(to: .now)); 3 downloads/uploads and 3 XML signatures") }
}

@Test func minvoiceBulkMultipleDocumentsAllVerifyBeforeUpload() async throws {
    let identity = try TestIdentity()
    for bad in [false, true] {
        let backend = BulkBackend(identity: identity, badSignature: bad ? 2 : nil), http = BulkHTTP(documentsPerGroup: 2)
        let bridge = MinvoiceBridge(backend: backend, http: http, groupDelay: .zero)
        let response = try object(await bridge.dispatch(command(ids: [UUID(), UUID(), UUID()]), origin: miOrigin))
        #expect(response["code"] as? Int == (bad ? 2 : 1))
        #expect(await backend.signatures == 2)
        #expect(await http.uploads == (bad ? 0 : 1))
        if !bad {
            let upload = try #require(await http.requests.last?.httpBody)
            #expect(String(decoding: upload, as: UTF8.self).components(separatedBy: "name=\"files\"").count - 1 == 2)
        }
    }
}

@Test(arguments: ["download2", "signature2", "cancel-sign2", "timeout2", "cancel-upload2", "cancel-after1"])
func minvoiceBulkFailureKeepsAcknowledgedGroupsAndNeverRetries(fault: String) async throws {
    let identity = try TestIdentity(), ids = (0..<300).map { _ in UUID() }
    let backend = BulkBackend(identity: identity, badSignature: fault == "signature2" ? 2 : nil, cancelSignature: fault == "cancel-sign2" ? 2 : nil)
    let http = BulkHTTP(fault: fault), bridge = MinvoiceBridge(backend: backend, http: http, groupDelay: .zero)
    let request = try command(ids: ids)
    let task = Task { await bridge.dispatch(request, origin: miOrigin) }
    let response = try object(await task.value), result = try batchObject(response)
    #expect(response["code"] as? Int != 1)
    #expect(result["uploadAcknowledgedInvoices"] as? Int == 100)
    let uncertain = fault == "timeout2" || fault == "cancel-upload2"
    #expect(result["uploadUncertainInvoices"] as? Int == (uncertain ? 100 : 0))
    #expect(result["notStartedInvoices"] as? Int == (fault == "cancel-after1" ? 200 : 100))
    #expect(await http.uploads == (uncertain ? 2 : 1))
    #expect(await http.downloads.count == (fault == "cancel-after1" ? 1 : 2))
    let text = SignalRHub.json(response)
    #expect(!text.contains(ids[0].uuidString) && !text.contains("fixture-password") && !text.contains("fixture-auth"))
    if fault == "cancel-after1" { #expect(result["outcome"] as? String == "cancelled") }
}

@Test func minvoiceBulkMixedSerialIsRejectedBeforeAnyDownloadOrUpload() async throws {
    let backend = BulkBackend(identity: try TestIdentity()), http = BulkHTTP(fault: "mixed")
    let bridge = MinvoiceBridge(backend: backend, http: http, groupDelay: .zero)
    #expect(try object(await bridge.dispatch(command(ids: [UUID(), UUID()]), origin: miOrigin))["code"] as? Int != 1)
    let downloads = await http.downloads, uploads = await http.uploads
    #expect(downloads.isEmpty && uploads == 0)
}

@Test func minvoiceZIPMultipleEntriesRemainBoundedAndRejectDuplicateNames() throws {
    let a = UUID(), b = UUID()
    let zip = try bulkZIP([(a, unsignedCash), (b, unsignedCash)])
    #expect(try MinvoiceZIP.extractAll(zip).map(\.id) == [a, b])
    var duplicate = zip
    let source = Data((b.uuidString.lowercased() + ".xml").utf8), replacement = Data((a.uuidString.lowercased() + ".xml").utf8)
    while let range = duplicate.range(of: source) { duplicate.replaceSubrange(range, with: replacement) }
    #expect(throws: MinvoiceError.self) { try MinvoiceZIP.extractAll(duplicate) }
    var traversal = zip
    let name = Data((a.uuidString.lowercased() + ".xml").utf8)
    while let range = traversal.range(of: name) {
        traversal.replaceSubrange(range, with: Data(("../" + String(repeating: "a", count: 33) + ".xml").utf8))
    }
    #expect(throws: MinvoiceError.self) { try MinvoiceZIP.extractAll(traversal) }
}

@Test func minvoiceZIPChecksCRCAndDeclaredExpansionBeforeAcceptingGroup() throws {
    var zip = try bulkZIP([(UUID(), unsignedCash)])
    let end = zip.count - 22
    let central = Int(zip[end+16]) | Int(zip[end+17]) << 8 | Int(zip[end+18]) << 16 | Int(zip[end+19]) << 24
    // Keep header CRCs in agreement; decompression still yields a different CRC.
    zip[central+16] ^= 1; zip[14] ^= 1
    #expect(throws: MinvoiceError.self) { try MinvoiceZIP.extractAll(zip) }
    var oversized = try bulkZIP([(UUID(), unsignedCash)])
    let e = oversized.count - 22
    let c = Int(oversized[e+16]) | Int(oversized[e+17]) << 8 | Int(oversized[e+18]) << 16 | Int(oversized[e+19]) << 24
    let size = MinvoiceBatchLimits.documentBytes + 1
    for i in 0..<4 { oversized[c+24+i] = UInt8(truncatingIfNeeded: size >> (8*i)) }
    #expect(throws: MinvoiceError.self) { try MinvoiceZIP.extractAll(oversized) }
    #expect(throws: MinvoiceError.self) { try MinvoiceZIP.extractAll(Data(count: MinvoiceBatchLimits.archiveBytes + 1)) }
}

@Test func minvoiceMock300LargerInvoicesPerformanceEvidence() async throws {
    let backend = BulkBackend(identity: try TestIdentity()), http = BulkHTTP(payloadRepeats: 600)
    let bridge = MinvoiceBridge(backend: backend, http: http, groupDelay: .zero)
    let request = try command(ids: (0..<300).map { _ in UUID() })
    let start = ContinuousClock.now
    let response = try object(await bridge.dispatch(request, origin: miOrigin))
    let duration = start.duration(to: .now).components
    #expect(response["code"] as? Int == 1)
    #expect(try batchObject(response)["uploadAcknowledgedInvoices"] as? Int == 300)
    #expect(await http.downloads.map(\.count) == [100,100,100])
    var usage = rusage(); _ = getrusage(RUSAGE_SELF, &usage)
    let uploads = await http.requests.filter { $0.url!.path.hasSuffix("/upload-xml") }
    print("MINVOICE_MOCK_BENCH=" + SignalRHub.json([
        "invoices": 300, "groups": 3, "xmlSignatures": 3,
        "elapsedSeconds": Double(duration.seconds) + Double(duration.attoseconds) / 1e18,
        "multipartBytes": uploads.reduce(0) { $0 + ($1.httpBody?.count ?? 0) },
        "testProcessPeakResidentBytesDarwin": usage.ru_maxrss,
        "realNetworkOrToken": false,
    ]))
}

@Test(arguments: [("diag-login", "login"), ("diag-configuration", "configuration"), ("diag-tenant", "tenant"), ("diag-token", "registeredToken"), ("diag-detail", "invoiceDetail")])
func minvoicePreflightFailurePreservesSafeStageBeforePINAndDownload(testCase: (String, String)) async throws {
    let events = Events(), identity = try TestIdentity()
    let http = FixtureHTTP(events: events, archive: Data(), fault: testCase.0)
    let bridge = MinvoiceBridge(backend: FixtureBackend(identity: identity, events: events), http: http)
    let text = await bridge.dispatch(try command(ids: [invoiceID, UUID()]), origin: miOrigin)
    let response = try object(text), batch = try batchObject(response)
    #expect(response["code"] as? Int == 2)
    #expect((response["message"] as? String)?.contains("[MI_HTTP \(testCase.1)/fetch URL:-1009]") == true)
    #expect(batch["diagnostic"] as? String == "[MI_HTTP \(testCase.1)/fetch URL:-1009]")
    #expect(batch["uploadAcknowledgedInvoices"] as? Int == 0 && batch["notStartedInvoices"] as? Int == 2)
    #expect(await http.requests.contains { $0.url!.path.contains("download-xml") || $0.url!.path.hasSuffix("/upload-xml") } == false)
    #expect(await events.values.contains("pin/sign") == false)
    for privateValue in ["PRIVATE_NEVER_EMIT", "fixture-password", "fixture-auth", invoiceID.uuidString.lowercased()] { #expect(!text.contains(privateValue)) }
}
