import Foundation
import Core

public struct MinvoiceHTTPResponse: Sendable {
    public let status: Int
    public let headers: [String: String]
    public let body: Data
    public init(status: Int, headers: [String: String] = [:], body: Data = Data()) {
        self.status = status; self.headers = headers; self.body = body
    }
}

public protocol MinvoiceHTTPTransport: Sendable {
    func send(_ request: URLRequest) async throws -> MinvoiceHTTPResponse
}

/// Credentials and invoice bytes never enter a shared cookie jar, cache or log.
public final class MinvoiceURLSession: NSObject, MinvoiceHTTPTransport, URLSessionTaskDelegate, @unchecked Sendable {
    public override init() { super.init() }
    public func send(_ request: URLRequest) async throws -> MinvoiceHTTPResponse {
        let config = URLSessionConfiguration.ephemeral
        config.httpCookieStorage = nil; config.urlCache = nil; config.urlCredentialStorage = nil
        config.httpShouldSetCookies = false
        config.requestCachePolicy = .reloadIgnoringLocalCacheData
        config.timeoutIntervalForResource = 90
        let session = URLSession(configuration: config, delegate: self, delegateQueue: nil)
        defer { session.invalidateAndCancel() }
        do {
            let (stream, response) = try await session.bytes(for: request)
            guard let http = response as? HTTPURLResponse,
                  http.url == request.url, response.expectedContentLength <= 2 << 20 else { throw MinvoiceError.transport }
            var bytes = Data()
            for try await byte in stream {
                guard bytes.count < 2 << 20 else { throw MinvoiceError.transport }
                bytes.append(byte)
            }
            var headers: [String: String] = [:]
            for (key, value) in http.allHeaderFields { headers[String(describing: key)] = String(describing: value) }
            return .init(status: http.statusCode, headers: headers, body: bytes)
        } catch is CancellationError { throw MinvoiceError.cancelled }
        catch let error as MinvoiceError { throw error }
        catch { throw MinvoiceError.transport } // never surface URLs, response bodies or credentials
    }

    public func urlSession(_ session: URLSession, task: URLSessionTask, willPerformHTTPRedirection response: HTTPURLResponse,
                           newRequest request: URLRequest, completionHandler: @escaping @Sendable (URLRequest?) -> Void) {
        completionHandler(nil)
    }
}

struct MinvoiceBrowserInfo: Decodable, Sendable {
    let Cookie, UserAgent, UserName, Pass, LinkApi: String

    func validate() throws {
        _ = try MinvoiceRESTRequests.Session(api: URL(string: LinkApi) ?? URL(fileURLWithPath: "/"),
            userAgent: UserAgent, cookie: "validation", verificationToken: "validation")
        guard !UserName.isEmpty, !Pass.isEmpty, UserName.utf8.count <= 1024, Pass.utf8.count <= 4096,
              Cookie.utf8.count <= 16384, UserAgent.utf8.count <= 4096,
              !Cookie.unicodeScalars.contains(where: { $0.value < 0x20 || $0.value == 0x7f }) else { throw MinvoiceError.invalidInput }
    }
}

struct MinvoiceLogin {
    private struct Credentials: Encodable { let UserNameOrEmailAddress, Password: String; let RememberMe = false }

    static func session(info: MinvoiceBrowserInfo, http: any MinvoiceHTTPTransport) async throws -> MinvoiceRESTRequests.Session {
        try info.validate()
        let api = URL(string: info.LinkApi)!
        let base = api.deletingLastPathComponent()
        var cookies: [String: String] = [:]
        for part in info.Cookie.split(separator: ";") {
            let pair = part.trimmingCharacters(in: .whitespaces).split(separator: "=", maxSplits: 1)
            if pair.count == 2, pair[0] == "__tenant" {
                guard cookies["__tenant"] == nil else { throw MinvoiceError.invalidInput }
                cookies["__tenant"] = String(pair[1])
            }
        }
        func cookieHeader() -> String { cookies.keys.sorted().map { "\($0)=\(cookies[$0]!)" }.joined(separator: "; ") }
        for path in ["account/login", "abp/application-configuration"] {
            var request = URLRequest(url: base.appendingPathComponent(path))
            request.httpShouldHandleCookies = false; request.timeoutInterval = 60
            request.setValue(info.UserAgent, forHTTPHeaderField: "User-Agent")
            if !cookies.isEmpty { request.setValue(cookieHeader(), forHTTPHeaderField: "Cookie") }
            if path == "account/login" {
                request.httpMethod = "POST"
                request.setValue("application/json; charset=utf-8", forHTTPHeaderField: "Content-Type")
                request.httpBody = try JSONEncoder().encode(Credentials(UserNameOrEmailAddress: info.UserName, Password: info.Pass))
            }
            let response = try await http.send(request)
            guard response.status == 200 else { throw MinvoiceError.server(response.status) }
            for cookie in HTTPCookie.cookies(withResponseHeaderFields: response.headers, for: request.url!) where cookie.name != "__tenant" {
                cookies[cookie.name] = cookie.value
            }
        }
        guard let xsrf = cookies["XSRF-TOKEN"], cookies.keys.contains(where: { $0 != "__tenant" && $0 != "XSRF-TOKEN" }) else {
            throw MinvoiceError.invalidInput
        }
        return try .init(api: api, userAgent: info.UserAgent, cookie: cookieHeader(), verificationToken: xsrf)
    }
}
