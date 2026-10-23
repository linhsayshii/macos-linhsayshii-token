import Foundation
import Core

/// Safe diagnostics: only enum labels, HTTP status and allowlisted system domains
/// with numeric codes survive. Never retains an NSError, URL, headers or body.
struct MinvoiceHTTPFailure: Error, Sendable, Equatable, CustomStringConvertible {
    enum Route: String, Sendable {
        case login, configuration, tenant, registeredToken, invoiceDetail, downloadCash, downloadStandard, upload, other
        init(_ request: URLRequest) {
            let path = request.url?.path ?? ""
            switch path {
            case "/api/account/login": self = .login
            case "/api/abp/application-configuration": self = .configuration
            case "/api/app/tenant-company/current-tenant": self = .tenant
            case "/api/app/token/by-serial-number": self = .registeredToken
            case "/api/app/release-invoice/download-xml-invoice-cash": self = .downloadCash
            case "/api/app/release-invoice/download-xml": self = .downloadStandard
            case "/api/app/release-invoice/00000000-0000-0000-0000-000000000000/upload-xml": self = .upload
            default:
                let parts = path.split(separator: "/")
                self = parts.count == 5 && parts[0] == "api" && parts[1] == "app" && parts[2] == "invoice"
                    && UUID(uuidString: String(parts[3])) != nil && parts[4] == "detail" ? .invoiceDetail : .other
            }
        }
    }
    enum Reason: String, Sendable { case fetch, read, nonHTTP, urlMismatch, declaredSize, streamSize, status, json, cookies, shape, ack }
    struct SystemCode: Sendable, Equatable {
        enum Domain: String, Sendable { case url = "URL", cfNetwork = "CFNetwork", posix = "POSIX", cocoa = "Cocoa", osStatus = "OSStatus", other }
        let domain: Domain
        let code: Int
    }
    let route: Route
    let reason: Reason
    let status: Int?
    let systemCodes: [SystemCode]

    init(request: URLRequest, reason: Reason, status: Int? = nil, error: Error? = nil) {
        route = Route(request); self.reason = reason
        self.status = status.flatMap { (100...599).contains($0) ? $0 : nil }
        var codes: [SystemCode] = [], seen = Set<ObjectIdentifier>()
        var current = error.map { $0 as NSError }
        while let value = current, codes.count < 3, seen.insert(ObjectIdentifier(value)).inserted {
            let domain: SystemCode.Domain
            switch value.domain {
            case NSURLErrorDomain: domain = .url
            case "kCFErrorDomainCFNetwork": domain = .cfNetwork
            case NSPOSIXErrorDomain: domain = .posix
            case NSCocoaErrorDomain: domain = .cocoa
            case NSOSStatusErrorDomain: domain = .osStatus
            default: domain = .other
            }
            codes.append(.init(domain: domain, code: value.code))
            current = value.userInfo[NSUnderlyingErrorKey] as? NSError
        }
        systemCodes = codes
    }
    var description: String {
        let http = status.map { " HTTP:\($0)" } ?? ""
        let codes = systemCodes.isEmpty ? "" : " " + systemCodes.map { "\($0.domain.rawValue):\($0.code)" }.joined(separator: "<-")
        return "[MI_HTTP \(route.rawValue)/\(reason.rawValue)\(http)\(codes)]"
    }

    static func checkResponse(_ response: URLResponse, request: URLRequest) throws -> HTTPURLResponse {
        guard let http = response as? HTTPURLResponse else { throw Self(request: request, reason: .nonHTTP) }
        guard http.url == request.url else { throw Self(request: request, reason: .urlMismatch) }
        guard response.expectedContentLength <= MinvoiceBatchLimits.archiveBytes else { throw Self(request: request, reason: .declaredSize) }
        return http
    }
}

extension MinvoiceHTTPTransport {
    /// Covers injected transports as well as URLSession without losing the step.
    func sendDiagnosed(_ request: URLRequest) async throws -> MinvoiceHTTPResponse {
        do { return try await send(request) }
        catch let error as MinvoiceHTTPFailure { throw error }
        catch is CancellationError { throw CancellationError() }
        catch MinvoiceError.cancelled { throw MinvoiceError.cancelled }
        catch MinvoiceError.transport { throw MinvoiceHTTPFailure(request: request, reason: .fetch) }
        catch let error as MinvoiceError { throw error }
        catch { throw MinvoiceHTTPFailure(request: request, reason: .fetch, error: error) }
    }
}
