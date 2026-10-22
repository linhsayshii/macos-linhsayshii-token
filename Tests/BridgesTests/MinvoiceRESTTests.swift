import Foundation
import Testing
@testable import Bridges

private let miID = UUID(uuidString: "12345678-90ab-cdef-1234-567890abcdef")!
private let miBoundary = "0123456789abcdef0123456789abcdef"
private func miSession(api: String = "https://api-hddt.minvoice.com.vn/api/app/", cookie: String = "__tenant=test; auth=fixture") throws -> MinvoiceRESTRequests.Session {
    try .init(api: URL(string: api)!, userAgent: "Fixture", cookie: cookie, verificationToken: "fixture-xsrf")
}

@Test func minvoiceDownloadUsesJSONArrayAndSessionHeaders() throws {
    let r = try MinvoiceRESTRequests.downloadXML(session: miSession(), ids: [miID], requestID: miID)
    #expect(r.url?.absoluteString == "https://api-hddt.minvoice.com.vn/api/app/release-invoice/download-xml")
    #expect(r.httpMethod == "POST")
    #expect(try JSONDecoder().decode([String].self, from: #require(r.httpBody)) == [miID.uuidString.lowercased()])
    #expect(r.value(forHTTPHeaderField: "x_req_id") == miID.uuidString.lowercased())
    #expect(r.value(forHTTPHeaderField: "Cookie") == "__tenant=test; auth=fixture")
    #expect(r.value(forHTTPHeaderField: "RequestVerificationToken") == "fixture-xsrf")
    #expect(r.value(forHTTPHeaderField: "User-Agent") == "Fixture")
    #expect(r.value(forHTTPHeaderField: "Authorization") == nil)
    #expect(r.value(forHTTPHeaderField: "Content-Type") == "application/json; charset=utf-8")
}

@Test func minvoiceUploadUsesEmptyGuidRouteAndUTF8XMLParts() throws {
    let second = UUID(uuidString: "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee")!
    let xml = "<HDon>Hóa đơn</HDon>"
    let r = try MinvoiceRESTRequests.uploadXML(session: miSession(), invoices: [.init(id: miID, xml: xml), .init(id: second, xml: "<BKe/>")], boundary: miBoundary)
    #expect(r.httpMethod == "POST")
    #expect(r.url?.path == "/api/app/release-invoice/00000000-0000-0000-0000-000000000000/upload-xml")
    #expect(r.value(forHTTPHeaderField: "Content-Type") == "multipart/form-data; boundary=\(miBoundary)")
    let body = String(decoding: try #require(r.httpBody), as: UTF8.self)
    #expect(body.contains("name=\"files\"; filename=\"12345678-90ab-cdef-1234-567890abcdef.xml\"\r\nContent-Type: text/xml\r\n\r\n\(xml)\r\n"))
    #expect(body.contains("filename=\"aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee.xml\""))
    #expect(body.hasSuffix("--\(miBoundary)--\r\n"))
    #expect(r.value(forHTTPHeaderField: "x_req_id") == nil)
}

@Test func minvoiceInfoRequestUsesInvoiceDetail() throws {
    let r = MinvoiceRESTRequests.invoiceInfo(session: try miSession(), id: miID)
    #expect(r.httpMethod == "GET")
    #expect(r.url?.path == "/api/app/invoice/12345678-90ab-cdef-1234-567890abcdef/detail")
    #expect(r.httpBody == nil)
}

@Test func minvoiceRejectsCredentialEgressAndHeaderInjection() throws {
    for api in ["http://api-hddt.minvoice.com.vn/api/app/", "https://attacker.invalid/api/app/", "https://api-hddt.minvoice.com.vn.attacker.invalid/api/app/", "https://user@api-hddt.minvoice.com.vn/api/app/", "https://api-hddt.minvoice.com.vn:8443/api/app/", "https://api-hddt.minvoice.com.vn/api/app/?x=1", "https://api-hddt.minvoice.com.vn/api/app/#fragment", "https://api-hddt.minvoice.com.vn/api/app/../"] {
        #expect(throws: MinvoiceRESTRequests.ConstructionError.self) { try miSession(api: api) }
    }
    #expect(throws: MinvoiceRESTRequests.ConstructionError.self) { try miSession(cookie: "auth=fixture\r\nX-Injected: true") }
}

@Test func minvoiceRejectsAmbiguousBatchAndMultipartDelimiters() throws {
    let s = try miSession()
    #expect(throws: MinvoiceRESTRequests.ConstructionError.self) { try MinvoiceRESTRequests.downloadXML(session: s, ids: []) }
    #expect(throws: MinvoiceRESTRequests.ConstructionError.self) { try MinvoiceRESTRequests.downloadXML(session: s, ids: [miID, miID]) }
    #expect(throws: MinvoiceRESTRequests.ConstructionError.self) { try MinvoiceRESTRequests.uploadXML(session: s, invoices: [.init(id: miID, xml: "x\r\n--\(miBoundary)")], boundary: miBoundary) }
    #expect(throws: MinvoiceRESTRequests.ConstructionError.self) { try MinvoiceRESTRequests.uploadXML(session: s, invoices: [.init(id: miID, xml: "<HDon/>")], boundary: "bad\r\nHeader") }
}
