import Foundation
import Core

/// Classic handlerHub bridge, with a deliberately bounded single-cash path.
public struct MinvoiceBridge: Sendable {
    private let backend: any MinvoiceSigningBackend
    private let invoices: MinvoiceInvoices
    public static let version = "2.0.0"
    public init(backend: any MinvoiceSigningBackend, http: any MinvoiceHTTPTransport = MinvoiceURLSession()) {
        self.backend = backend; self.invoices = MinvoiceInvoices(backend: backend, http: http)
    }

    public var handler: SignalRHub.Handler {
        { method, args, call in
            switch method.lowercased() {
            case "getversion": return Self.version
            case "getcommandinfo", "runupdate": return nil
            case "processmessage":
                let text = args.first ?? ""
                await call.start {
                    let result = await dispatch(text, origin: call.origin)
                    await call.push("reponseResult", [result])
                }
                return nil
            case "swichtask", "voucherhub": return await dispatch(args.first ?? "", origin: call.origin)
            default: throw SignalRInvokeError.message("Method not supported")
            }
        }
    }

    func dispatch(_ text: String, origin: String) async -> String {
        guard text.utf8.count <= 65536, let data = text.data(using: .utf8),
              let root = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else { return Self.result(code: 400, message: "Yêu cầu không hợp lệ") }
        let command = (root["PlugCommand"] as? [String: Any]) ?? root
        switch command["CommandName"] as? String {
        case "TokenInfo", "GetCertificate", "GetInfoToken":
            do {
                let cert = try await backend.selectCertificate(origin: origin, serial: command["SerialNumber"] as? String)
                return Self.result(code: 1, data: ["token": ["Issuer": cert.issuer, "SerialNumber": cert.serialHex,
                    "Subject": cert.subject, "NotBefore": Self.iso(cert.notBefore), "NotAfter": Self.iso(cert.notAfter), "Base64Certificate": cert.derB64]])
            } catch {
                let (code, message) = Self.failure(error)
                return Self.result(code: code, message: message)
            }
        case "SignInvoices":
            do {
                try await invoices.sign(text, origin: origin)
                return Self.result(code: 1, message: "Successful", data: ["status": true, "command": "SignInvoices"])
            } catch {
                let (code, message) = Self.failure(error)
                return Self.result(code: code, message: message, data: ["status": false, "command": "SignInvoices"])
            }
        default: return Self.result(code: 501, message: "Lệnh Minvoice chưa được hỗ trợ")
        }
    }

    static func failure(_ error: Error) -> (Int, String) {
        switch error {
        case SigningTargetError.unknownCertificate, SigningTargetError.ambiguousCertificate:
            return (404, "Hãy chọn đúng một chứng thư số")
        case MinvoiceError.unsupported: return (501, "Hiện chỉ hỗ trợ một hóa đơn cash TDiep mỗi lần; HDon/BKe và batch chưa được hỗ trợ")
        case MinvoiceError.expiredCertificate: return (2, "Chứng thư chưa có hiệu lực hoặc đã hết hạn; không gửi hóa đơn")
        case MinvoiceError.busy: return (2, "Đang xử lý yêu cầu ký khác")
        case MinvoiceError.invalidXML, MinvoiceError.invalidSignature: return (2, "XML hoặc chữ ký không hợp lệ; chưa upload hóa đơn")
        case MinvoiceError.server: return (2, "Minvoice chưa xác nhận thành công. Hãy kiểm tra trạng thái hóa đơn trước khi thử lại")
        case MinvoiceError.uploadUncertain: return (2, "Chưa xác định trạng thái upload. Hãy kiểm tra hóa đơn trên Minvoice trước khi gửi lại")
        case MinvoiceError.transport: return (2, "Lỗi kết nối Minvoice. Nếu đã gửi upload, hãy kiểm tra trạng thái trước khi thử lại")
        case is CancellationError, MinvoiceError.cancelled: return (2, "Đã huỷ yêu cầu ký")
        case TokenBroker.SignError.card(let message): return (2, message)
        case TokenBroker.SignError.loginFailed: return (2, "Đăng nhập token thất bại; không tự thử lại PIN")
        default: return (2, "Không thể xử lý yêu cầu Minvoice; chưa xác nhận ký thành công")
        }
    }

    static func iso(_ value: String) -> String { value.replacingOccurrences(of: " ", with: "T") }
    static func result(code: Int, message: String = "", data: [String: Any] = [:]) -> String {
        SignalRHub.json(["code": code, "message": message, "errorName": NSNull(), "data": data])
    }
}
