import Foundation
import Testing
import Core
@testable import Bridges

@Test func minvoiceHTTPDiagnosticRedactsURLsCredentialsAndUntrustedDomains() throws {
    let sentinel = "PRIVATE_NEVER_EMIT"
    let underlying = NSError(domain: sentinel, code: 54, userInfo: [NSLocalizedDescriptionKey: sentinel])
    let error = NSError(domain: NSURLErrorDomain, code: -1005, userInfo: [
        NSLocalizedDescriptionKey: sentinel, NSURLErrorFailingURLErrorKey: URL(string: "https://secret.invalid/\(sentinel)")!,
        NSUnderlyingErrorKey: underlying, "cookie": sentinel, "password": sentinel,
    ])
    let request = URLRequest(url: URL(string: "https://api-hddt.minvoice.com.vn/api/app/invoice/12345678-90ab-cdef-1234-567890abcdef/detail?token=\(sentinel)")!)
    let diagnostic = MinvoiceHTTPFailure(request: request, reason: .read, error: error)
    #expect(diagnostic.route == .invoiceDetail)
    #expect(diagnostic.description == "[MI_HTTP invoiceDetail/read URL:-1005<-other:54]")
    for text in [diagnostic.description, String(reflecting: diagnostic)] {
        #expect(!text.contains(sentinel) && !text.contains("https://") && !text.contains("12345678"))
    }
    let unknown = MinvoiceHTTPFailure(request: URLRequest(url: URL(string: "https://secret.invalid/\(sentinel)")!), reason: .fetch, error: error)
    #expect(unknown.route == .other && !unknown.description.contains(sentinel))
}

@Test func minvoiceHTTPDiagnosticKeepsOnlyBoundedNumericSystemCauses() {
    var error = NSError(domain: NSOSStatusErrorDomain, code: -9806)
    for _ in 0..<8 { error = NSError(domain: "kCFErrorDomainCFNetwork", code: -1200, userInfo: [NSUnderlyingErrorKey: error]) }
    let request = URLRequest(url: URL(string: "https://api-hddt.minvoice.com.vn/api/account/login")!)
    let diagnostic = MinvoiceHTTPFailure(request: request, reason: .fetch, error: error)
    #expect(diagnostic.systemCodes.count == 3)
    #expect(diagnostic.systemCodes.allSatisfy { $0.domain == .cfNetwork && $0.code == -1200 })
    #expect(diagnostic.description.hasPrefix("[MI_HTTP login/fetch"))
}

@Test func minvoiceHTTPDiagnosticsDistinguishGuardsWithoutResponseData() throws {
    let url = URL(string: "https://api-hddt.minvoice.com.vn/api/account/login")!, request = URLRequest(url: url)
    let response = HTTPURLResponse(url: url, statusCode: 200, httpVersion: nil, headerFields: [:])!
    #expect(try MinvoiceHTTPFailure.checkResponse(response, request: request).statusCode == 200)
    let cases: [(URLResponse, MinvoiceHTTPFailure.Reason)] = [
        (URLResponse(url: url, mimeType: "text/xml", expectedContentLength: 0, textEncodingName: nil), .nonHTTP),
        (HTTPURLResponse(url: URL(string: "https://secret.invalid/PRIVATE_BODY")!, statusCode: 200, httpVersion: nil, headerFields: [:])!, .urlMismatch),
        (HTTPURLResponse(url: url, statusCode: 200, httpVersion: nil, headerFields: ["Content-Length": String(MinvoiceBatchLimits.archiveBytes + 1)])!, .declaredSize),
    ]
    for (response, reason) in cases {
        do { _ = try MinvoiceHTTPFailure.checkResponse(response, request: request); Issue.record("Unsafe response accepted") }
        catch let failure as MinvoiceHTTPFailure { #expect(failure.reason == reason && !failure.description.contains("PRIVATE_BODY")) }
    }
}

@Test func minvoiceHTTPDiagnosticsClassifyAllKnownRoutesWithoutParameters() {
    let routes: [(String, MinvoiceHTTPFailure.Route)] = [
        ("/api/account/login", .login), ("/api/abp/application-configuration", .configuration),
        ("/api/app/tenant-company/current-tenant", .tenant), ("/api/app/token/by-serial-number?serialNumber=PRIVATE", .registeredToken),
        ("/api/app/release-invoice/download-xml-invoice-cash", .downloadCash), ("/api/app/release-invoice/download-xml", .downloadStandard),
        ("/api/app/release-invoice/00000000-0000-0000-0000-000000000000/upload-xml", .upload),
    ]
    for (path, route) in routes {
        let diagnostic = MinvoiceHTTPFailure(request: URLRequest(url: URL(string: "https://api-hddt.minvoice.com.vn" + path)!), reason: .status, status: 403)
        #expect(diagnostic.route == route && diagnostic.status == 403 && !diagnostic.description.contains("PRIVATE"))
    }
}
